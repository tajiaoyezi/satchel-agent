package netprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// DomainLatency 对最多 200 个域名以最多 16 并发做 TCP/TLS 延迟探测，按去重后的输入顺序返回结果并附最快列表。
func DomainLatency(ctx context.Context, p xrpc.NetworkDomainLatencyParams) (*xrpc.NetworkDomainLatencyResult, error) {
	if len(p.Domains) == 0 {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "domains 不能为空"}
	}
	seen := make(map[string]struct{}, len(p.Domains))
	domains := make([]string, 0, len(p.Domains))
	for _, raw := range p.Domains {
		d, err := ValidateHost(raw)
		if err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "domains 含非法项：" + err.Error()}
		}
		key := strings.ToLower(d)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		domains = append(domains, d)
		if len(domains) > xrpc.DomainLatencyMaxDomains {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("去重后域名数超过上限 %d", xrpc.DomainLatencyMaxDomains)}
		}
	}

	port := p.Port
	if port == 0 {
		port = xrpc.DomainLatencyDefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("port %d 必须在 1..65535 之间", port)}
	}
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "tls"
	}
	if mode != "tls" && mode != "tcp" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("不支持的探测模式 %q（仅允许 tls 或 tcp）", p.Mode)}
	}
	timeoutMS := p.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = xrpc.DomainLatencyDefaultTimeoutMS
	}
	if timeoutMS < xrpc.DomainLatencyMinTimeoutMS || timeoutMS > xrpc.DomainLatencyMaxTimeoutMS {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("timeout_ms %d 必须在 %d..%d 之间", timeoutMS, xrpc.DomainLatencyMinTimeoutMS, xrpc.DomainLatencyMaxTimeoutMS)}
	}
	conc := p.Concurrency
	if conc == 0 {
		conc = xrpc.DomainLatencyMaxConcurrency
	}
	if conc < 1 || conc > xrpc.DomainLatencyMaxConcurrency {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("concurrency %d 必须在 1..%d 之间", conc, xrpc.DomainLatencyMaxConcurrency)}
	}
	if conc > len(domains) {
		conc = len(domains)
	}

	startAll := time.Now()
	timeout := time.Duration(timeoutMS) * time.Millisecond
	results := make([]xrpc.DomainLatencyItem, len(domains))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, dom := range domains {
		wg.Add(1)
		go func(idx int, dom string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = xrpc.DomainLatencyItem{Domain: dom, OK: false, Error: ctx.Err().Error()}
				return
			}
			results[idx] = probeSingleDomainLatency(ctx, dom, port, mode, timeout)
		}(i, dom)
	}
	wg.Wait()

	fastest := make([]xrpc.DomainLatencyItem, 0, len(results))
	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
			fastest = append(fastest, r)
		}
	}
	sort.Slice(fastest, func(i, j int) bool {
		if fastest[i].LatencyMS != fastest[j].LatencyMS {
			return fastest[i].LatencyMS < fastest[j].LatencyMS
		}
		return fastest[i].Domain < fastest[j].Domain
	})
	if len(fastest) > 10 {
		fastest = fastest[:10]
	}

	return &xrpc.NetworkDomainLatencyResult{
		Mode:        mode,
		Port:        port,
		Total:       len(results),
		OKCount:     okCount,
		FailedCount: len(results) - okCount,
		Results:     results,
		Fastest:     fastest,
		DurationMS:  time.Since(startAll).Milliseconds(),
	}, nil
}

func probeSingleDomainLatency(ctx context.Context, domain string, port int, mode string, timeout time.Duration) xrpc.DomainLatencyItem {
	t0 := time.Now()
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(pctx, "tcp", net.JoinHostPort(domain, strconv.Itoa(port)))
	if err != nil {
		return xrpc.DomainLatencyItem{Domain: domain, OK: false, Error: err.Error()}
	}
	if mode == "tcp" {
		lat := time.Since(t0).Milliseconds()
		_ = conn.Close()
		return xrpc.DomainLatencyItem{Domain: domain, OK: true, LatencyMS: lat}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, // 延迟测速仅评估握手耗时与 TLS 版本/ALPN，证书有效性由 website validate 负责。
	})
	if deadline, ok := pctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if herr := tlsConn.HandshakeContext(pctx); herr != nil {
		_ = tlsConn.Close()
		return xrpc.DomainLatencyItem{Domain: domain, OK: false, Error: herr.Error()}
	}
	lat := time.Since(t0).Milliseconds()
	st := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	return xrpc.DomainLatencyItem{
		Domain:     domain,
		OK:         true,
		LatencyMS:  lat,
		TLSVersion: tlsVersionName(st.Version),
		ALPN:       st.NegotiatedProtocol,
	}
}

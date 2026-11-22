// Package netprobe 实现节点侧纯 Go 网络探测（端口扫描、站点校验、域名批量延迟与返程路由追踪分类）。
package netprobe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// ValidateHost 检查扫描或探测目标主机名/IP 不含空白、控制字符或路径分隔符。
func ValidateHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", fmt.Errorf("目标主机不能为空")
	}
	if len(h) > 253 {
		return "", fmt.Errorf("目标主机 %q 过长", h)
	}
	for _, r := range h {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' || r == '?' || r == '#' {
			return "", fmt.Errorf("目标主机 %q 含非法字符", h)
		}
	}
	if strings.Contains(h, "..") {
		return "", fmt.Errorf("目标主机 %q 不能包含 ..", h)
	}
	return h, nil
}

// PortScan 执行受限 TCP 端口扫描（上限 256 端口，并发 1..64，单端口超时 100ms..5s）。
func PortScan(ctx context.Context, p xrpc.NetworkPortScanParams) (*xrpc.NetworkPortScanResult, error) {
	host := strings.TrimSpace(p.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	var err error
	host, err = ValidateHost(host)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}

	ports := p.Ports
	if len(ports) == 0 {
		ports = append([]int(nil), xrpc.DefaultPortScanPorts...)
	}
	if len(ports) > xrpc.PortScanMaxPorts {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("扫描端口数 %d 超出上限 %d", len(ports), xrpc.PortScanMaxPorts)}
	}
	seen := make(map[int]struct{}, len(ports))
	uniq := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("非法端口 %d（必须在 1..65535 之间）", port)}
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		uniq = append(uniq, port)
	}
	sort.Ints(uniq)

	timeoutMS := p.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = xrpc.PortScanDefaultTimeoutMS
	}
	if timeoutMS < xrpc.PortScanMinTimeoutMS || timeoutMS > xrpc.PortScanMaxTimeoutMS {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("timeout_ms %d 必须在 %d..%d 之间", timeoutMS, xrpc.PortScanMinTimeoutMS, xrpc.PortScanMaxTimeoutMS)}
	}
	conc := p.Concurrency
	if conc == 0 {
		conc = xrpc.PortScanDefaultConcurrency
	}
	if conc < 1 || conc > xrpc.PortScanMaxConcurrency {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("concurrency %d 必须在 1..%d 之间", conc, xrpc.PortScanMaxConcurrency)}
	}
	if conc > len(uniq) {
		conc = len(uniq)
	}

	startAll := time.Now()
	timeout := time.Duration(timeoutMS) * time.Millisecond
	results := make([]xrpc.PortScanItem, len(uniq))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, port := range uniq {
		wg.Add(1)
		go func(idx, port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = xrpc.PortScanItem{Port: port, Open: false, Error: ctx.Err().Error()}
				return
			}
			t0 := time.Now()
			dialer := &net.Dialer{Timeout: timeout}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, derr := dialer.DialContext(ctx, "tcp", addr)
			lat := time.Since(t0).Milliseconds()
			if derr != nil {
				results[idx] = xrpc.PortScanItem{Port: port, Open: false, Error: derr.Error()}
				return
			}
			banner := readBriefBanner(conn)
			_ = conn.Close()
			results[idx] = xrpc.PortScanItem{
				Port:      port,
				Open:      true,
				LatencyMS: lat,
				Banner:    banner,
			}
		}(i, port)
	}
	wg.Wait()

	openPorts := make([]int, 0)
	closed := 0
	for _, r := range results {
		if r.Open {
			openPorts = append(openPorts, r.Port)
		} else {
			closed++
		}
	}
	return &xrpc.NetworkPortScanResult{
		Host:         host,
		ScannedCount: len(results),
		OpenPorts:    openPorts,
		ClosedCount:  closed,
		Results:      results,
		DurationMS:   time.Since(startAll).Milliseconds(),
	}, nil
}

func readBriefBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
	r := bufio.NewReaderSize(conn, 256)
	buf := make([]byte, 128)
	n, _ := r.Read(buf)
	if n <= 0 {
		return ""
	}
	line := strings.TrimSpace(string(buf[:n]))
	if idx := strings.IndexAny(line, "\r\n"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

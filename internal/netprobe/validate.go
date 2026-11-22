package netprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// ValidateSiteOptions 允许测试注入根证书池（生产环境为 nil，使用系统根证书）。
type ValidateSiteOptions struct {
	RootCAs *x509.CertPool
}

// ValidateSite 从本机向目标站点发起 TCP + TLS + 可选 HTTP HEAD 校验，输出 TLS 版本、ALPN、证书与 Reality 适用性判定。
// 目标不可达或证书校验失败返回结构化 OK=false 结果，不返回 RPC 错误。
func ValidateSite(ctx context.Context, p xrpc.NetworkValidateSiteParams, opts ...ValidateSiteOptions) (*xrpc.NetworkValidateSiteResult, error) {
	domain, err := ValidateHost(p.Domain)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "domain 非法：" + err.Error()}
	}
	port := p.Port
	if port == 0 {
		port = xrpc.ValidateSiteDefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("port %d 必须在 1..65535 之间", port)}
	}
	sni := strings.TrimSpace(p.SNI)
	if sni == "" {
		sni = domain
	} else {
		sni, err = ValidateHost(sni)
		if err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "sni 非法：" + err.Error()}
		}
	}
	timeoutMS := p.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = xrpc.ValidateSiteDefaultTimeoutMS
	}
	if timeoutMS < xrpc.ValidateSiteMinTimeoutMS || timeoutMS > xrpc.ValidateSiteMaxTimeoutMS {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("timeout_ms %d 必须在 %d..%d 之间", timeoutMS, xrpc.ValidateSiteMinTimeoutMS, xrpc.ValidateSiteMaxTimeoutMS)}
	}

	var rootCAs *x509.CertPool
	if len(opts) > 0 {
		rootCAs = opts[0].RootCAs
	}

	now := time.Now().UTC()
	res := &xrpc.NetworkValidateSiteResult{
		Domain:    domain,
		Port:      port,
		SNI:       sni,
		CheckedAt: now,
	}

	timeout := time.Duration(timeoutMS) * time.Millisecond
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, derr := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(domain, strconv.Itoa(port)))
	if derr != nil {
		res.LatencyMS = time.Since(t0).Milliseconds()
		res.Error = fmt.Sprintf("TCP 连接失败：%v", derr)
		return res, nil
	}
	res.Reachable = true

	var verifyErr error
	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, // 在 VerifyConnection 手动校验，以便证书无效时仍能采集对端证书主题与到期时间。
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				verifyErr = fmt.Errorf("对端未提供证书")
				return nil
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			vopts := x509.VerifyOptions{
				DNSName:       sni,
				Intermediates: intermediates,
				Roots:         rootCAs,
				CurrentTime:   now,
			}
			if _, err := cs.PeerCertificates[0].Verify(vopts); err != nil {
				verifyErr = err
			}
			return nil
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if herr := tlsConn.HandshakeContext(probeCtx); herr != nil {
		_ = tlsConn.Close()
		res.LatencyMS = time.Since(t0).Milliseconds()
		res.Error = fmt.Sprintf("TLS 握手失败：%v", herr)
		return res, nil
	}
	res.LatencyMS = time.Since(t0).Milliseconds()

	state := tlsConn.ConnectionState()
	res.TLSVersion = tlsVersionName(state.Version)
	res.ALPN = state.NegotiatedProtocol
	res.HTTP2 = state.NegotiatedProtocol == "h2"
	res.CertValid = verifyErr == nil
	if verifyErr != nil {
		res.Error = fmt.Sprintf("证书校验未通过：%v", verifyErr)
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		res.CertSubject = leaf.Subject.CommonName
		if res.CertSubject == "" {
			res.CertSubject = leaf.Subject.String()
		}
		res.CertIssuer = leaf.Issuer.CommonName
		if res.CertIssuer == "" {
			res.CertIssuer = leaf.Issuer.String()
		}
		if len(leaf.DNSNames) > 0 {
			res.CertDNSNames = append([]string(nil), leaf.DNSNames...)
		}
		exp := leaf.NotAfter.UTC()
		res.CertExpiresAt = &exp
		res.CertDaysLeft = int(time.Until(exp).Hours() / 24)
	}

	// 若协商到 http/1.1，在同一连接上做一次轻量 HEAD 探查；h2 场景仅关闭并按需由单独轻量检查或跳过以避免额外延迟。
	if state.NegotiatedProtocol != "h2" {
		status, srvHdr := probeHTTP1Head(tlsConn, sni)
		res.HTTPStatus = status
		res.ServerHeader = srvHdr
	}
	_ = tlsConn.Close()

	res.OK = res.Reachable && res.TLSVersion != "" && res.CertValid
	res.RealitySuitable = res.TLSVersion == "TLS 1.3" && res.HTTP2 && res.CertValid
	return res, nil
}

func probeHTTP1Head(conn net.Conn, host string) (int, string) {
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	reqStr := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: satchel-probe/1.0\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return 0, ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodHead})
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	return resp.StatusCode, strings.TrimSpace(resp.Header.Get("Server"))
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", v)
	}
}

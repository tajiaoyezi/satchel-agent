package netprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

func TestPortScanOpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-TestBanner\r\n"))
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// 找一个确定关闭的本地端口。
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := tmpLn.Addr().(*net.TCPAddr).Port
	_ = tmpLn.Close()

	res, err := PortScan(context.Background(), xrpc.NetworkPortScanParams{
		Host:        "127.0.0.1",
		Ports:       []int{closedPort, openPort, openPort},
		TimeoutMS:   500,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("PortScan 失败：%v", err)
	}
	if res.ScannedCount != 2 || len(res.OpenPorts) != 1 || res.OpenPorts[0] != openPort || res.ClosedCount != 1 {
		t.Fatalf("扫描结果异常：%+v", res)
	}
	var gotBanner string
	for _, it := range res.Results {
		if it.Port == openPort {
			gotBanner = it.Banner
		}
	}
	if gotBanner != "SSH-2.0-TestBanner" {
		t.Fatalf("banner 不符：%q", gotBanner)
	}

	// 超限端口数报 bad_params。
	tooMany := make([]int, xrpc.PortScanMaxPorts+1)
	for i := range tooMany {
		tooMany[i] = i + 1
	}
	if _, err := PortScan(context.Background(), xrpc.NetworkPortScanParams{Ports: tooMany}); err == nil {
		t.Fatal("超 256 端口应报 bad_params")
	}
}

func startLocalTLS13Server(t *testing.T, dnsName string, alpn []string) (int, *x509.CertPool, func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: alpn,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				buf := make([]byte, 256)
				_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: satchel-test\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pool, func() { _ = ln.Close() }
}

func TestValidateSiteTLS13AndUnreachable(t *testing.T) {
	port, pool, stop := startLocalTLS13Server(t, "decoy.local", []string{"h2", "http/1.1"})
	defer stop()

	res, err := ValidateSite(context.Background(), xrpc.NetworkValidateSiteParams{
		Domain:    "127.0.0.1",
		Port:      port,
		SNI:       "decoy.local",
		TimeoutMS: 3000,
	}, ValidateSiteOptions{RootCAs: pool})
	if err != nil {
		t.Fatalf("ValidateSite 失败：%v", err)
	}
	if !res.OK || !res.Reachable || res.TLSVersion != "TLS 1.3" || res.ALPN != "h2" || !res.HTTP2 || !res.CertValid || !res.RealitySuitable {
		t.Fatalf("TLS 1.3 h2 校验结果异常：%+v", res)
	}

	// 不信任证书仍返回证书主题与 CertValid=false，而非 RPC error。
	untrusted, err := ValidateSite(context.Background(), xrpc.NetworkValidateSiteParams{
		Domain:    "127.0.0.1",
		Port:      port,
		SNI:       "decoy.local",
		TimeoutMS: 3000,
	})
	if err != nil {
		t.Fatalf("自签证书不应返回 RPC error：%v", err)
	}
	if untrusted.CertValid || untrusted.RealitySuitable || untrusted.CertSubject != "decoy.local" {
		t.Fatalf("自签证书校验结果不对：%+v", untrusted)
	}

	// 不可达端口返回 OK=false 而非 RPC error。
	tmpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := tmpLn.Addr().(*net.TCPAddr).Port
	_ = tmpLn.Close()
	unreach, err := ValidateSite(context.Background(), xrpc.NetworkValidateSiteParams{
		Domain:    "127.0.0.1",
		Port:      closedPort,
		TimeoutMS: 1000,
	})
	if err != nil || unreach.OK || unreach.Reachable || unreach.Error == "" {
		t.Fatalf("不可达端口应返回结构化 OK=false：res=%+v err=%v", unreach, err)
	}
}

func TestDomainLatencyLimitsAndOrder(t *testing.T) {
	port, _, stop := startLocalTLS13Server(t, "localhost", []string{"h2"})
	defer stop()

	// 超过 200 域名或超过 16 并发报错。
	over200 := make([]string, xrpc.DomainLatencyMaxDomains+1)
	for i := range over200 {
		over200[i] = fmt.Sprintf("d%d.example.com", i)
	}
	if _, err := DomainLatency(context.Background(), xrpc.NetworkDomainLatencyParams{Domains: over200}); err == nil {
		t.Fatal("超 200 域名应报 bad_params")
	}
	if _, err := DomainLatency(context.Background(), xrpc.NetworkDomainLatencyParams{Domains: []string{"127.0.0.1"}, Concurrency: 17}); err == nil {
		t.Fatal("超 16 并发应报 bad_params")
	}

	res, err := DomainLatency(context.Background(), xrpc.NetworkDomainLatencyParams{
		Domains:     []string{"127.0.0.1", "localhost", "127.0.0.1"},
		Port:        port,
		Mode:        "tls",
		TimeoutMS:   2000,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("DomainLatency 失败：%v", err)
	}
	if res.Total != 2 || res.OKCount != 2 || len(res.Results) != 2 || res.Results[0].Domain != "127.0.0.1" || res.Results[1].Domain != "localhost" || len(res.Fastest) != 2 {
		t.Fatalf("域名延迟结果不对：%+v", res)
	}
	if res.Results[0].TLSVersion != "TLS 1.3" {
		t.Fatalf("TLS 模式应返回版本：%+v", res.Results[0])
	}
}

type fakeTracer struct {
	hops []xrpc.ReturnRouteHop
	err  error
}

func (f fakeTracer) Trace(_ context.Context, _ string, _, _ int, _ time.Duration) ([]xrpc.ReturnRouteHop, string, error) {
	return f.hops, "fake", f.err
}

func TestReturnRouteClassificationAndFallback(t *testing.T) {
	cases := []struct {
		name      string
		carrier   string
		hops      []xrpc.ReturnRouteHop
		wantType  string
		wantASN   string
		wantEntry string
	}{
		{"CN2 GIA", "ct", []xrpc.ReturnRouteHop{{Hop: 1, IP: "10.0.0.1"}, {Hop: 2, IP: "59.43.130.1"}}, "CN2 GIA", "AS4809", "59.43.130.1"},
		{"CN2 GT", "CT", []xrpc.ReturnRouteHop{{Hop: 1, IP: "202.97.1.1"}, {Hop: 2, IP: "59.43.2.2"}}, "CN2 GT", "AS4809", "59.43.2.2"},
		{"163", "CT", []xrpc.ReturnRouteHop{{Hop: 1, IP: "202.97.50.1"}}, "163", "AS4134", "202.97.50.1"},
		{"AS9929", "cu", []xrpc.ReturnRouteHop{{Hop: 1, IP: "218.105.1.1"}}, "AS9929", "AS9929", "218.105.1.1"},
		{"AS4837", "CU", []xrpc.ReturnRouteHop{{Hop: 1, IP: "219.158.10.1"}}, "AS4837", "AS4837", "219.158.10.1"},
		{"CMIN2", "cm", []xrpc.ReturnRouteHop{{Hop: 1, IP: "223.120.2.1"}}, "CMIN2", "AS58807", "223.120.2.1"},
		{"CMI", "CM", []xrpc.ReturnRouteHop{{Hop: 1, IP: "221.183.1.1"}}, "CMI", "AS58453", "221.183.1.1"},
		{"CERNET", "edu", []xrpc.ReturnRouteHop{{Hop: 1, IP: "202.112.14.1"}}, "CERNET", "AS4538", "202.112.14.1"},
		{"Unknown", "CT", []xrpc.ReturnRouteHop{{Hop: 1, IP: "1.1.1.1"}}, "Unknown", "", "1.1.1.1"},
	}
	for _, tc := range cases {
		res, err := TestReturnRoute(context.Background(), xrpc.NetworkReturnRouteTestParams{
			Carrier: tc.carrier,
		}, fakeTracer{hops: tc.hops})
		if err != nil {
			t.Fatalf("%s 失败：%v", tc.name, err)
		}
		if res.RouteType != tc.wantType || res.EntryASN != tc.wantASN || res.EntryIP != tc.wantEntry {
			t.Fatalf("%s 分类不对：got=(%s,%s,%s) want=(%s,%s,%s)", tc.name, res.RouteType, res.EntryASN, res.EntryIP, tc.wantType, tc.wantASN, tc.wantEntry)
		}
	}

	// traceroute 输出解析测试。
	rawOut := "traceroute to 202.97.1.1, 30 hops max\n 1  192.168.1.1  1.23 ms\n 2  * * *\n 3  59.43.80.1  14.8 ms\n"
	parsed := parseTracerouteOutput(rawOut)
	if len(parsed) != 2 || parsed[1].IP != "59.43.80.1" || parsed[1].LatencyMS != 15 {
		t.Fatalf("traceroute 解析异常：%+v", parsed)
	}

	// 无系统命令时回落纯 Go TCP 探测。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	sysT := &SystemTracer{LookPath: func(string) (string, error) { return "", fmt.Errorf("not found") }}
	res, err := TestReturnRoute(context.Background(), xrpc.NetworkReturnRouteTestParams{
		Carrier:  "CT",
		TargetIP: "127.0.0.1",
		Port:     port,
	}, sysT)
	if err != nil || len(res.Hops) != 1 || res.Hops[0].IP != "127.0.0.1" {
		t.Fatalf("回落探测异常：res=%+v err=%v", res, err)
	}
}

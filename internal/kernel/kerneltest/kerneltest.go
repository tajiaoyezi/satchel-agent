// Package kerneltest 是内核与连接管控的测试工具，只在测试里 import（agent-kernel 的证伪测试用，m2-04 的正式验收复用）：
// 进程里的 sing-box 服务端（VLESS 入站 in1、Hysteria2 入站 in2，用户 A、B 共四份凭据，出站 out1、out2 按目标端口分流）、
// 每个（用户，入站）一个客户端内核（本地 direct 入站作入口），以及收发流量的服务与吞吐计量。
package kerneltest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/tracker"
)

const (
	InVLESS = "in1"
	InHY2   = "in2"
	Out1    = "out1"
	Out2    = "out2"
	UserA   = "A"
	UserB   = "B"

	// hy2Mbps 是 Hysteria2 两端申报的带宽，远大于测试量，免得它自己的拥塞控制成了瓶颈。
	hy2Mbps = 2000
)

var uuids = map[string]string{UserA: "6a4f1c2e-3b5d-4e7f-8a9b-0c1d2e3f4a5b", UserB: "7b5e2d3f-4c6e-4f80-9bac-1d2e3f4a5b6c"}

func password(user string) string { return "pw-" + user }

// Server 是服务端内核与两个收发流量的服务：发往 Sink1 的走 out1，发往 Sink2 的走 out2。
type Server struct {
	Kernel    *kernel.Kernel
	VLESSPort int
	HY2Port   int
	Sink1     *Sink
	Sink2     *Sink
	config    []byte
}

// StartServer 起服务端。t 结束时停掉。
func StartServer(t testing.TB) *Server {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := writeCert(t, dir)
	s := &Server{VLESSPort: FreePort(t), HY2Port: FreePort(t), Sink1: StartSink(t), Sink2: StartSink(t)}
	users := func(field func(string) map[string]string) []map[string]string {
		return []map[string]string{field(UserA), field(UserB)}
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{"type": "vless", "tag": InVLESS, "listen": "127.0.0.1", "listen_port": s.VLESSPort,
				"users": users(func(u string) map[string]string { return map[string]string{"name": u, "uuid": uuids[u]} })},
			map[string]any{"type": "hysteria2", "tag": InHY2, "listen": "127.0.0.1", "listen_port": s.HY2Port,
				"up_mbps": hy2Mbps, "down_mbps": hy2Mbps,
				"users": users(func(u string) map[string]string { return map[string]string{"name": u, "password": password(u)} }),
				"tls":   map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": Out1}, map[string]any{"type": "direct", "tag": Out2}},
		"route": map[string]any{
			"rules": []any{map[string]any{"port": []int{s.Sink2.Port}, "action": "route", "outbound": Out2}},
			"final": Out1,
		},
	}
	s.config = mustJSON(t, cfg)
	s.Kernel = kernel.New(tracker.New())
	s.start(t)
	t.Cleanup(func() { s.Kernel.Stop() })
	return s
}

func (s *Server) start(t testing.TB) {
	t.Helper()
	if err := s.Kernel.Start(context.Background(), s.config); err != nil {
		t.Fatal(err)
	}
}

// Config 返回服务端内核用的 sing-box 配置（JSON），可以写成 kernel.json 交给别的内核起同样的入站。
func (s *Server) Config() []byte { return s.config }

// Tracker 返回服务端的 tracker。
func (s *Server) Tracker() *tracker.Tracker { return s.Kernel.Tracker() }

// RestartKernel 在同一个进程里停掉再启动服务端内核，tracker 不变。
func (s *Server) RestartKernel(t testing.TB) {
	t.Helper()
	if err := s.Kernel.Stop(); err != nil {
		t.Fatal(err)
	}
	s.start(t)
}

// RestartProcess 模拟 satchel-agent 进程重启：停掉内核，换一个新的 tracker（新的启动标识、计数从零开始）再启动。
func (s *Server) RestartProcess(t testing.TB) {
	t.Helper()
	if err := s.Kernel.Stop(); err != nil {
		t.Fatal(err)
	}
	s.Kernel = kernel.New(tracker.New())
	s.start(t)
}

// SinkPort 返回第 n 个（1 或 2）收发流量服务的端口。
func (s *Server) SinkPort(n int) int {
	if n == 2 {
		return s.Sink2.Port
	}
	return s.Sink1.Port
}

// Client 是一个（用户，入站）的客户端内核：本地两个 direct 入站分别通到服务端那边的 Sink1 与 Sink2。
type Client struct {
	User    string
	Inbound string
	ports   [3]int // 下标 1、2：通到 Sink1、Sink2 的本地端口
	kernel  *kernel.Kernel
}

// StartClient 为 user 经服务端的 inbound（InVLESS 或 InHY2）起一个客户端内核。t 结束时停掉。
func StartClient(t testing.TB, s *Server, user, inbound string) *Client {
	t.Helper()
	port := s.VLESSPort
	if inbound == InHY2 {
		port = s.HY2Port
	}
	return StartClientVia(t, s, user, inbound, port)
}

// StartClientVia 同 StartClient，但连本机的 port 去找服务端的入站（例如挡在入站前面的 Relay）。
func StartClientVia(t testing.TB, s *Server, user, inbound string, port int) *Client {
	t.Helper()
	c := &Client{User: user, Inbound: inbound}
	var inbounds []any
	for n := 1; n <= 2; n++ {
		c.ports[n] = FreePort(t)
		inbounds = append(inbounds, map[string]any{"type": "direct", "tag": fmt.Sprintf("local%d", n),
			"listen": "127.0.0.1", "listen_port": c.ports[n], "override_address": "127.0.0.1", "override_port": s.SinkPort(n)})
	}
	var proxy map[string]any
	switch inbound {
	case InVLESS:
		proxy = map[string]any{"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "uuid": uuids[user]}
	case InHY2:
		proxy = map[string]any{"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
			"password": password(user), "up_mbps": hy2Mbps, "down_mbps": hy2Mbps,
			"tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true}}
	default:
		t.Fatalf("不认识的入站 %q", inbound)
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  inbounds,
		"outbounds": []any{proxy},
		"route":     map[string]any{"final": "proxy"},
	}
	c.kernel = kernel.New(tracker.New())
	if err := c.kernel.Start(context.Background(), mustJSON(t, cfg)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.kernel.Stop() })
	return c
}

// DialTCP 经这个客户端连到服务端那边的第 n 个收发流量服务。
func (c *Client) DialTCP(n int) (net.Conn, error) {
	return net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", c.ports[n]), 5*time.Second)
}

// DialUDP 经这个客户端向服务端那边的第 n 个收发流量服务开一个 UDP 流。
func (c *Client) DialUDP(n int) (net.Conn, error) {
	return net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", c.ports[n]))
}

// Flow 是一个后台跑着的流：Meter 是接收方的计数，Stop 关掉它，Done 在流结束（对方关闭或出错）时关闭。
type Flow struct {
	Meter *Meter
	conn  net.Conn
	done  chan struct{}
	err   error
}

// Stop 关掉流并等它结束。
func (f *Flow) Stop() {
	f.conn.Close()
	<-f.done
}

// Done 在流结束时关闭。
func (f *Flow) Done() <-chan struct{} { return f.done }

// Err 返回流结束的原因（Done 关闭之后才有意义）。
func (f *Flow) Err() error { return f.err }

// Download 经客户端开一条 TCP 下载：服务端按 bps 下发 total 个字节（0 表示不限）。计数在客户端这一侧。
func Download(t testing.TB, c *Client, n int, bps, total int64) *Flow {
	t.Helper()
	conn, err := c.DialTCP(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "D %d %d\n", bps, total); err != nil {
		t.Fatal(err)
	}
	f := &Flow{Meter: &Meter{}, conn: conn, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		buf := make([]byte, 32<<10)
		for {
			m, err := conn.Read(buf)
			f.Meter.Add(m)
			if err != nil {
				if err != io.EOF {
					f.err = err
				}
				return
			}
		}
	}()
	return f
}

// Upload 经客户端开一条 TCP 上传，按 bps 发（0 表示不控速），total 为 0 表示一直发。计数在服务端那边的收发流量服务上（id 区分）。
func Upload(t testing.TB, s *Server, c *Client, n int, id string, bps, total int64) *Flow {
	t.Helper()
	conn, err := c.DialTCP(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "U %s\n", id); err != nil {
		t.Fatal(err)
	}
	sink := s.Sink1
	if n == 2 {
		sink = s.Sink2
	}
	f := &Flow{Meter: sink.Upload(id), conn: conn, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		done := make(chan struct{})
		pacedWrite(conn, bps, total, done)
		if tc, ok := conn.(*net.TCPConn); ok && total > 0 {
			tc.CloseWrite()
			io.Copy(io.Discard, conn) // 等服务端收完、关掉
		}
	}()
	return f
}

// UDPDownload 经客户端开一个 UDP 流：服务端按 bps 下发 d 这么长时间。计数在客户端这一侧（负载字节）。
func UDPDownload(t testing.TB, c *Client, n int, bps int64, d time.Duration) *Flow {
	t.Helper()
	conn, err := c.DialUDP(n)
	if err != nil {
		t.Fatal(err)
	}
	f := &Flow{Meter: &Meter{}, conn: conn, done: make(chan struct{})}
	if _, err := fmt.Fprintf(conn, "D %d %d", bps, d.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(f.done)
		buf := make([]byte, 64<<10)
		for {
			m, err := conn.Read(buf)
			if err != nil {
				f.err = err
				return
			}
			f.Meter.Add(m)
		}
	}()
	return f
}

// Echo 经客户端开一个回显的 TCP 连接，确认通了再返回。用来撑起活动连接（识别连接、踢线）。
func Echo(t testing.TB, c *Client, n int) net.Conn {
	t.Helper()
	conn, err := c.DialTCP(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "E\nping\n"); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ping" {
		t.Fatalf("回显没通：%q %v", line, err)
	}
	conn.SetReadDeadline(time.Time{})
	t.Cleanup(func() { conn.Close() })
	return conn
}

// EchoUDP 经客户端开一个 UDP 流，回显一次确认通了再返回。
func EchoUDP(t testing.TB, c *Client, n int) net.Conn {
	t.Helper()
	conn, err := c.DialUDP(n)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	for i := 0; i < 10; i++ { // UDP 可能丢，重试几次
		if _, err := io.WriteString(conn, "E ping"); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if m, err := conn.Read(buf); err == nil && string(buf[:m]) == "E ping" {
			conn.SetReadDeadline(time.Time{})
			t.Cleanup(func() { conn.Close() })
			return conn
		}
	}
	t.Fatal("UDP 回显没通")
	return nil
}

// WaitConns 等到服务端某个（入站，凭据）的活动连接数等于 want，最多等 d。
func WaitConns(t testing.TB, tr *tracker.Tracker, inbound, user string, want int, d time.Duration) []tracker.Conn {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		got := tr.Connections(inbound, user)
		if len(got) == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeCert 生成一张 localhost / 127.0.0.1 的自签证书，写进 dir。
func writeCert(t testing.TB, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

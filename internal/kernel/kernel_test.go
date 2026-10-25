package kernel_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel-agent/internal/kernel"
	kt "github.com/satchel/satchel-agent/internal/kernel/kerneltest"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// agent-kernel「零 fork 内嵌 sing-box」「带标签能起 Hysteria2」：四个客户端（A、B 各经 VLESS 与 Hysteria2）的 TCP 与 UDP 都通。
func TestSmoke(t *testing.T) {
	s := kt.StartServer(t)
	for _, user := range []string{kt.UserA, kt.UserB} {
		for _, in := range []string{kt.InVLESS, kt.InHY2} {
			c := kt.StartClient(t, s, user, in)
			kt.Echo(t, c, 1)
			kt.EchoUDP(t, c, 2)
		}
	}
}

// agent-kernel「内核起停」：同一进程里停掉再启动，客户端能重新连上，tracker 是同一个实例，内核代数为 2。
func TestKernelRestart(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	c := kt.StartClient(t, s, kt.UserA, kt.InVLESS)
	kt.Echo(t, c, 1)
	s.RestartKernel(t)
	if s.Tracker() != tr || tr.Generation() != 2 {
		t.Fatalf("重启后 tracker 应当是同一个、内核代数为 2：%d", tr.Generation())
	}
	kt.Echo(t, c, 1)
	if err := s.Kernel.Start(context.Background(), []byte(`{}`)); err != kernel.ErrRunning {
		t.Fatalf("在跑时再 Start 应当是 ErrRunning：%v", err)
	}
}

// 半关闭照常：目标发完 hello 就半关闭，客户端读到 EOF 后还能接着上传，目标收得到。包装层不转发 CloseWrite 的话，
// sing-box 会把半关闭变成整条关闭，客户端后发的数据就丢了。只测 VLESS：sing-box v1.14.4 的 Hysteria2 在不挂 tracker 时
// 也收不到半关闭之后的上传（本站核对过），与包装层无关。
func TestHalfClose(t *testing.T) {
	s := kt.StartServer(t)
	for _, in := range []string{kt.InVLESS} {
		c := kt.StartClient(t, s, kt.UserA, in)
		conn, err := c.DialTCP(1)
		if err != nil {
			t.Fatal(err)
		}
		id := "half-" + in
		fmt.Fprintf(conn, "H %s\n", id)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != "hello" {
			t.Fatalf("%s：应当读到 hello 再读到 EOF：%q %v", in, got, err)
		}
		if _, err := conn.Write([]byte("ack")); err != nil {
			t.Fatalf("%s：目标半关闭之后客户端应当还能发：%v", in, err)
		}
		conn.(*net.TCPConn).CloseWrite()
		m := s.Sink1.Upload(id)
		deadline := time.Now().Add(3 * time.Second)
		for m.Bytes() != 3 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if m.Bytes() != 3 {
			t.Errorf("%s：目标应当收到客户端半关闭之后发的 3 个字节：%d", in, m.Bytes())
		}
		conn.Close()
	}
}

// agent-kernel「重启基线」：内核代数是成功启动的次数。入站端口被占导致启动失败时代数不变，否则接收方会多记一次重启。
func TestFailedStartNotCounted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"direct","tag":"in","listen":"127.0.0.1",`+
		`"listen_port":%d,"network":"tcp","override_address":"127.0.0.1","override_port":9}]}`, ln.Addr().(*net.TCPAddr).Port))
	k := kernel.New(tracker.New())
	if err := k.Start(context.Background(), config); err == nil {
		t.Fatal("端口被占时启动应当失败")
	}
	if g := k.Tracker().Generation(); g != 0 || k.Running() || !k.StartedAt().IsZero() {
		t.Fatalf("启动失败后内核代数应当还是 0、内核不在跑、没有启动时间：%d %v %v", g, k.Running(), k.StartedAt())
	}
	ln.Close()
	if err := k.Start(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	if g := k.Tracker().Generation(); g != 1 {
		t.Fatalf("端口放开后启动成功，内核代数应当是 1：%d", g)
	}
	first := k.StartedAt()
	if first.IsZero() {
		t.Fatal("启动成功后应当有启动时间")
	}
	k.Stop()
	if !k.StartedAt().Equal(first) {
		t.Fatal("停掉以后启动时间仍是那一次")
	}
	time.Sleep(10 * time.Millisecond)
	if err := k.Start(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if !k.StartedAt().After(first) {
		t.Fatalf("再启动一次，启动时间应当变新：%v → %v", first, k.StartedAt())
	}
}

// kernel.Version 与 go.mod 里引用的 sing-box 版本一致。
func TestVersionMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := "github.com/sagernet/sing-box v" + kernel.Version
	for _, line := range strings.Split(string(mod), "\n") {
		if strings.TrimSpace(line) == want {
			return
		}
	}
	t.Fatalf("go.mod 里应当有一行 %q：升级 sing-box 时要同时改 kernel.Version", want)
}

// agent-kernel「所有入站共用一个挂接点」：A 经两个入站各开 TCP 与 UDP，tracker 看到四类连接，入站、凭据、出站都对。
func TestHooksSeeAllPaths(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	for _, in := range []string{kt.InVLESS, kt.InHY2} {
		c := kt.StartClient(t, s, kt.UserA, in)
		kt.Echo(t, c, 1)    // TCP → Sink1 → out1
		kt.EchoUDP(t, c, 2) // UDP → Sink2 → out2
		got := kt.WaitConns(t, tr, in, kt.UserA, 2, 3*time.Second)
		if len(got) != 2 {
			t.Fatalf("%s 上 A 应当有两条连接：%+v", in, got)
		}
		seen := map[string]string{}
		for _, conn := range got {
			seen[conn.Network] = conn.Outbound
		}
		if seen["tcp"] != kt.Out1 || seen["udp"] != kt.Out2 {
			t.Fatalf("%s：TCP 应当走 out1、UDP 走 out2：%+v", in, got)
		}
	}
	if got := tr.Connections(kt.InVLESS, kt.UserB); len(got) != 0 {
		t.Fatalf("B 没有连接：%+v", got)
	}
	_ = tracker.SourceStatic
}

// hangingRuleSet 起一个收到请求就挂着不回的 HTTP 服务，返回一份要从它下载远程规则集的 sing-box 配置与「收到请求」的通知。
func hangingRuleSet(t *testing.T) ([]byte, <-chan struct{}) {
	t.Helper()
	hit, release := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	config := fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}],`+
		`"route":{"rule_set":[{"type":"remote","tag":"rs","format":"binary","url":"%s/rs.srs"}],"rules":[{"rule_set":["rs"],"action":"route","outbound":"direct"}]}}`, srv.URL)
	return []byte(config), hit
}

// 启动期间取消：卡在下载远程规则集时 ctx 结束，Start 很快返回 ctx 的错误，内核不在跑、内核代数还是 0。
func TestStartCancelledDuringStartup(t *testing.T) {
	config, hit := hangingRuleSet(t)
	k := kernel.New(tracker.New())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Start(ctx, config) }()
	select {
	case <-hit:
	case <-time.After(5 * time.Second):
		t.Fatal("内核启动时应当去下载远程规则集")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("应当返回 ctx 被取消的错误：%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("启动期间取消，Start 应当很快返回")
	}
	if k.Running() || k.Tracker().Generation() != 0 {
		t.Fatalf("取消之后内核不应当在跑、代数还是 0：%v %d", k.Running(), k.Tracker().Generation())
	}
}

// 启动成功以后再取消 ctx，内核照常工作：ctx 只管启动这一段。用真流量查：入站经 direct 出站连到本地的回显服务，取消之后
// 发一行要原样收回来（只看端口还在听不够：实例跟着 ctx 被取消时端口还在，出站拨号却会报 operation was canceled）。
func TestStartContextOnlyCoversStartup(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := kt.FreePort(t)
	config := []byte(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"direct","tag":"in","listen":"127.0.0.1",`+
		`"listen_port":%d,"network":"tcp","override_address":"127.0.0.1","override_port":%d}],"outbounds":[{"type":"direct","tag":"out"}]}`,
		port, echo.Addr().(*net.TCPAddr).Port))
	k := kernel.New(tracker.New())
	ctx, cancel := context.WithCancel(context.Background())
	if err := k.Start(ctx, config); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	cancel()
	time.Sleep(200 * time.Millisecond)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("取消 ctx 之后入站应当还在听：%v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "ping\n" || !k.Running() {
		t.Fatalf("取消 ctx 之后内核应当照常转发：%q %v %v", line, err, k.Running())
	}
}

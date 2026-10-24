package kernel_test

import (
	"context"
	"fmt"
	"io"
	"net"
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
	if g := k.Tracker().Generation(); g != 0 || k.Running() {
		t.Fatalf("启动失败后内核代数应当还是 0、内核不在跑：%d %v", g, k.Running())
	}
	ln.Close()
	if err := k.Start(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	defer k.Stop()
	if g := k.Tracker().Generation(); g != 1 {
		t.Fatalf("端口放开后启动成功，内核代数应当是 1：%d", g)
	}
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

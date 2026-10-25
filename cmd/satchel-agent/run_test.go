package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/channel"
	kt "github.com/satchel/satchel-agent/internal/kernel/kerneltest"
)

// testMaster 是只接一条连接的假主控：握手、认可认证、回心跳确认，把「向节点发请求」交给测试；连接断开时关闭 gone。
type testMaster struct {
	priv  ed25519.PrivateKey
	url   string
	calls chan func(method string, params any) (json.RawMessage, error)
	gone  chan struct{}
}

func startTestMaster(t *testing.T) *testMaster {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := &testMaster{priv: priv, calls: make(chan func(string, any) (json.RawMessage, error), 1), gone: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		defer close(m.gone)
		ctx := context.Background()
		conn := xrpc.NewConn(ws)
		if err := xrpc.ServerHandshake(ctx, conn, priv); err != nil {
			return
		}
		if msg, err := conn.Read(ctx); err != nil || msg.Type != xrpc.TypeAuth {
			return
		}
		if err := conn.Write(ctx, xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 30}); err != nil {
			return
		}
		caller := xrpc.NewCaller()
		m.calls <- func(method string, params any) (json.RawMessage, error) {
			return caller.Call(context.Background(), conn, method, params, 5*time.Second)
		}
		for {
			msg, err := conn.Read(ctx)
			if err != nil {
				caller.CloseAll(nil)
				return
			}
			switch msg.Type {
			case xrpc.TypeHeartbeat:
				_ = conn.Write(ctx, xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now()})
			case xrpc.TypeReply:
				var r xrpc.Reply
				_ = xrpc.Decode(msg, &r)
				caller.Deliver(r)
			}
		}
	}))
	t.Cleanup(srv.Close)
	m.url = srv.URL
	return m
}

// startAgent 在后台跑 runAgent，返回取消函数与退出码的通道；logger 为空时不记日志。
func startAgent(t *testing.T, m *testMaster, dir string, logger *slog.Logger) (context.CancelFunc, <-chan int) {
	t.Helper()
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	cfg := channel.Config{MasterURL: m.url, Token: "tok", MasterKey: m.priv.Public().(ed25519.PublicKey), AgentVersion: "1.0.0"}
	go func() { code <- runAgent(ctx, dir, cfg, logger) }()
	t.Cleanup(cancel)
	return cancel, code
}

// onLog 是一个日志 handler：记到指定的那条日志时（在记日志的 goroutine 里）调一次 fn。
type onLog struct {
	msg  string
	fn   func()
	once *sync.Once
}

func (h onLog) Enabled(context.Context, slog.Level) bool { return true }
func (h onLog) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h onLog) WithGroup(string) slog.Handler            { return h }
func (h onLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.once.Do(h.fn)
	}
	return nil
}

func waitCall(t *testing.T, m *testMaster) func(string, any) (json.RawMessage, error) {
	t.Helper()
	select {
	case call := <-m.calls:
		return call
	case <-time.After(10 * time.Second):
		t.Fatal("节点没有连上假主控")
		return nil
	}
}

func waitExit(t *testing.T, code <-chan int) int {
	t.Helper()
	select {
	case c := <-code:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("ctx 结束后 runAgent 应当返回")
		return -1
	}
}

// agent-kernel「内核配置坏了」与 node-limiter：kernel.json 坏了时照常连上主控；五个方法都装在通道上（快照报内核没在跑、
// limiter.set 回「节点没有内核配置」）；ctx 结束时断开主控、退出码 0。
func TestRunAgentWithBrokenKernelConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, kernelConfig), []byte("{"), 0o600)
	m := startTestMaster(t)
	cancel, code := startAgent(t, m, dir, nil)
	call := waitCall(t, m)
	raw, err := call(xrpc.MethodTrafficSnapshot, nil)
	var snap xrpc.TrafficSnapshot
	if err != nil || json.Unmarshal(raw, &snap) != nil || snap.KernelRunning || snap.BootID == "" {
		t.Fatalf("快照应当报内核没在跑：%s %v", raw, err)
	}
	var xe *xrpc.Error
	_, err = call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Credential: "a", Source: xrpc.SourceMaster, BPS: 1})
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeBadParams || !strings.Contains(xe.Message, "没有内核配置") {
		t.Fatalf("limiter.set 应当回「节点没有内核配置」：%v", err)
	}
	cancel()
	if c := waitExit(t, code); c != 0 {
		t.Fatalf("退出码应当是 0：%d", c)
	}
	select {
	case <-m.gone:
	case <-time.After(5 * time.Second):
		t.Fatal("退出时应当断开主控")
	}
}

// 有效的 kernel.json：内核起来、快照报在跑；ctx 结束后先断通道、再停内核，退出码 0，内核停了（入站端口放出来）。
// 顺序这样查：runAgent 断开主控之后、停内核之前记「已断开主控，停内核」，日志 handler 在这条日志里等主控看到断开、再等 0.3 秒，
// 这时内核必须还能转发（runAgent 卡在记日志，还没停内核）：经 VLESS 走一次回显要成功。先停内核、或者内核跟着退出用的 ctx
// 被取消（端口还在听、出站却拨不出去），这时回显都会失败。
func TestRunAgentStopsKernelOnExit(t *testing.T) {
	s := kt.StartServer(t)
	config := s.Config()
	if err := s.Kernel.Stop(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, kernelConfig), config, 0o600)
	m := startTestMaster(t)
	addr := fmt.Sprintf("127.0.0.1:%d", s.VLESSPort)
	var disconnectedFirst, kernelStillUp bool
	var client *kt.Client
	logger := slog.New(onLog{msg: "已断开主控，停内核", once: &sync.Once{}, fn: func() {
		select {
		case <-m.gone:
			disconnectedFirst = true
		case <-time.After(3 * time.Second):
		}
		time.Sleep(300 * time.Millisecond)
		kernelStillUp = echoThrough(client) == nil
	}})
	cancel, code := startAgent(t, m, dir, logger)
	call := waitCall(t, m)
	raw, err := call(xrpc.MethodTrafficSnapshot, nil)
	var snap xrpc.TrafficSnapshot
	if err != nil || json.Unmarshal(raw, &snap) != nil || !snap.KernelRunning || snap.Generation != 1 {
		t.Fatalf("快照应当报内核在跑：%s %v", raw, err)
	}
	client = kt.StartClient(t, s, kt.UserA, kt.InVLESS)
	if err := echoThrough(client); err != nil {
		t.Fatalf("内核在跑时经 VLESS 应当能回显：%v", err)
	}
	if ln, err := net.Listen("tcp", addr); err == nil {
		ln.Close()
		t.Fatal("内核在跑时入站端口应当被占着")
	}
	cancel()
	if c := waitExit(t, code); c != 0 {
		t.Fatalf("退出码应当是 0：%d", c)
	}
	if !disconnectedFirst || !kernelStillUp {
		t.Fatalf("应当先断通道、再停内核：断开主控时内核应当还能转发（主控已看到断开=%v，内核还能转发=%v）", disconnectedFirst, kernelStillUp)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("退出之后内核应当停了、入站端口放出来：%v", err)
	}
	ln.Close()
}

// echoThrough 经客户端走一次回显（收发流量服务的 E 命令）；在日志 handler 里也能调，不碰 testing.T。
func echoThrough(c *kt.Client) error {
	conn, err := c.DialTCP(1)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "E\nping\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "ping" {
		return fmt.Errorf("回显不对：%q", line)
	}
	return nil
}

// 内核启动期间收到退出：卡在下载远程规则集时取消 ctx，runAgent 很快返回、退出码 0，不等下载结束。
func TestRunAgentCancelledDuringKernelStart(t *testing.T) {
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
	dir := t.TempDir()
	config := fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}],`+
		`"route":{"rule_set":[{"type":"remote","tag":"rs","format":"binary","url":"%s/rs.srs"}],"rules":[{"rule_set":["rs"],"action":"route","outbound":"direct"}]}}`, srv.URL)
	os.WriteFile(filepath.Join(dir, kernelConfig), []byte(config), 0o600)
	cancel, code := startAgent(t, startTestMaster(t), dir, nil)
	select {
	case <-hit:
	case <-time.After(5 * time.Second):
		t.Fatal("内核启动时应当去下载远程规则集")
	}
	cancel()
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("退出码应当是 0：%d", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("内核启动期间收到退出，runAgent 应当很快返回")
	}
}

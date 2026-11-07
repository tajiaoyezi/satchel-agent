package main

import (
	"bufio"
	"bytes"
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/channel"
	kt "github.com/satchel/satchel-agent/pkg/kerneltest"
)

// testMaster 是假主控：握手、认可认证、回心跳确认，把「向节点发请求」交给测试；第一条连接断开时关闭 gone，drop 可主动断开当前连接。
type testMaster struct {
	priv  ed25519.PrivateKey
	url   string
	calls chan func(method string, params any) (json.RawMessage, error)
	gone  chan struct{}

	mu   sync.Mutex
	ws   *websocket.Conn
	once sync.Once
}

func (m *testMaster) drop() {
	m.mu.Lock()
	ws := m.ws
	m.mu.Unlock()
	if ws != nil {
		_ = ws.CloseNow()
	}
}

func startTestMaster(t *testing.T) *testMaster {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := &testMaster{priv: priv, calls: make(chan func(string, any) (json.RawMessage, error), 4), gone: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		m.mu.Lock()
		m.ws = ws
		m.mu.Unlock()
		defer ws.CloseNow()
		defer m.once.Do(func() { close(m.gone) })
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
	client = kt.StartClient(t, s.Target(), kt.UserA, kt.InVLESS)
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

func withRemoteRuleSet(t *testing.T, base []byte, url string) []byte {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(base, &cfg); err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	route["rule_set"] = []any{map[string]any{
		"type":   "remote",
		"tag":    "rs",
		"format": "source",
		"url":    url,
	}}
	rules := route["rules"].([]any)
	route["rules"] = append(rules, map[string]any{
		"rule_set": []string{"rs"},
		"action":   "route",
		"outbound": kt.Out1,
	})
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// agent-kernel「重启内核」（m2-04 tasks 2.4 前五项）：
// 1. 传流量、重启、再传：计数相加，内核代数加一，启动标识不变；
// 2. 主控临时 5 Mbps 重启后仍生效（快速窗口）；
// 3. 改了入站名后重启：limiter.set 对新名成功、对旧名回参数不合法；
// 4. kernel.json 改成坏的后重启：回参数不合法，已有连接还能回显；
// 5. 占住入站端口后重启：回失败，假主控连接还在，快照报没在跑，放开后再重启能起来。
func TestKernelRestartOverChannel(t *testing.T) {
	s := kt.StartServer(t)
	config := s.Config()
	if err := s.Kernel.Stop(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, kernelConfig)
	os.WriteFile(cfgPath, config, 0o600)
	m := startTestMaster(t)
	_, _ = startAgent(t, m, dir, nil)
	call := waitCall(t, m)

	snapshot := func() xrpc.TrafficSnapshot {
		t.Helper()
		raw, err := call(xrpc.MethodTrafficSnapshot, nil)
		var snap xrpc.TrafficSnapshot
		if err != nil || json.Unmarshal(raw, &snap) != nil {
			t.Fatalf("取快照失败：%s %v", raw, err)
		}
		return snap
	}
	restart := func() xrpc.KernelRestarted {
		t.Helper()
		raw, err := call(xrpc.MethodKernelRestart, nil)
		var res xrpc.KernelRestarted
		if err != nil || json.Unmarshal(raw, &res) != nil {
			t.Fatalf("重启内核失败：%s %v", raw, err)
		}
		return res
	}
	downBytes := func(snap xrpc.TrafficSnapshot) int64 {
		for _, c := range snap.Counts {
			if c.Inbound == kt.InVLESS && c.Outbound == kt.Out1 && c.Credential == kt.UserA {
				return c.Down
			}
		}
		return 0
	}

	// 1. 传流量、重启、再传：计数相加，内核代数加一，启动标识不变。
	client := kt.StartClient(t, s.Target(), kt.UserA, kt.InVLESS)
	const chunk = 512 << 10
	<-kt.Download(t, client, 1, 0, chunk).Done()
	snap1 := snapshot()
	down1 := downBytes(snap1)
	if !snap1.KernelRunning || snap1.Generation != 1 || down1 < chunk {
		t.Fatalf("重启前快照不对：%+v (down=%d)", snap1, down1)
	}
	res := restart()
	if !res.Running || res.Version == "" || res.StartedAt == nil || !slices.Equal(res.Inbounds, []string{kt.InVLESS, kt.InHY2}) {
		t.Fatalf("重启返回不对：%+v", res)
	}
	<-kt.Download(t, client, 1, 0, chunk).Done()
	snap2 := snapshot()
	down2 := downBytes(snap2)
	if snap2.BootID != snap1.BootID || snap2.Generation != snap1.Generation+1 || down2 < down1+chunk {
		t.Fatalf("重启后计数应当相加、代数加一、BootID 不变：before=%+v (down=%d) after=%+v (down=%d)", snap1, down1, snap2, down2)
	}

	// 2. 主控临时 5 Mbps 重启后仍生效（快速窗口 6 秒）。
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: kt.InVLESS, Credential: kt.UserA, Source: xrpc.SourceMaster, BPS: 5_000_000}); err != nil {
		t.Fatalf("设 5 Mbps 失败：%v", err)
	}
	restart()
	var flows []*kt.Flow
	for range 4 {
		flows = append(flows, kt.Download(t, client, 1, 0, 0))
	}
	start := time.Now()
	time.Sleep(6 * time.Second)
	var total int64
	for _, f := range flows {
		total += f.Meter.Bytes()
		f.Stop()
	}
	gotMbps := float64(total) * 8 / time.Since(start).Seconds() / 1e6
	if gotMbps < 4 || gotMbps > 6 {
		t.Fatalf("重启后主控临时 5 Mbps 应当仍生效（±20%%）：%.2f Mbps", gotMbps)
	}
	if _, err := call(xrpc.MethodLimiterUnset, xrpc.LimiterUnsetParams{Inbound: kt.InVLESS, Credential: kt.UserA, Source: xrpc.SourceMaster}); err != nil {
		t.Fatalf("撤掉限速失败：%v", err)
	}

	// 3. 改了入站名后重启：limiter.set 对新名成功、对旧名回参数不合法。
	renamed := bytes.Replace(config, []byte(`"tag":"`+kt.InVLESS+`"`), []byte(`"tag":"vless-2"`), 1)
	os.WriteFile(cfgPath, renamed, 0o600)
	res = restart()
	if !slices.Equal(res.Inbounds, []string{"vless-2", kt.InHY2}) {
		t.Fatalf("新入站名应当是 [vless-2 %s]：%+v", kt.InHY2, res)
	}
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-2", Credential: kt.UserA, Source: xrpc.SourceMaster, BPS: 10_000_000}); err != nil {
		t.Fatalf("对新入站名 vless-2 应当成功：%v", err)
	}
	var xe *xrpc.Error
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: kt.InVLESS, Credential: kt.UserA, Source: xrpc.SourceMaster, BPS: 10_000_000}); !errors.As(err, &xe) || xe.Code != xrpc.CodeBadParams {
		t.Fatalf("对旧入站名 %s 应当回 bad_params：%v", kt.InVLESS, err)
	}
	os.WriteFile(cfgPath, config, 0o600)
	restart()

	// 4. kernel.json 改成坏的后重启：回参数不合法，已有连接还能回显。
	conn, err := client.DialTCP(1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "E\nbefore\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := rd.ReadString('\n'); err != nil || strings.TrimSpace(line) != "before" {
		t.Fatalf("回显不对：%q %v", line, err)
	}
	os.WriteFile(cfgPath, []byte("{"), 0o600)
	xe = nil
	if _, err := call(xrpc.MethodKernelRestart, nil); !errors.As(err, &xe) || xe.Code != xrpc.CodeBadParams || !strings.Contains(xe.Message, "解析不了") {
		t.Fatalf("坏配置重启应当回 bad_params（解析不了）：%v", err)
	}
	if _, err := io.WriteString(conn, "after\n"); err != nil {
		t.Fatalf("坏配置重启不应当断已有连接：%v", err)
	}
	if line, err := rd.ReadString('\n'); err != nil || strings.TrimSpace(line) != "after" {
		t.Fatalf("已有连接应当还能回显：%q %v", line, err)
	}
	conn.Close()

	// 5. 占住入站端口后重启：回失败，假主控连接还在，快照报没在跑，放开后再重启能起来。
	busyPort := kt.FreePort(t)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", busyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conflictCfg := bytes.Replace(config, fmt.Appendf(nil, `"listen_port":%d`, s.VLESSPort), fmt.Appendf(nil, `"listen_port":%d`, busyPort), 1)
	os.WriteFile(cfgPath, conflictCfg, 0o600)
	xe = nil
	if _, err := call(xrpc.MethodKernelRestart, nil); !errors.As(err, &xe) || xe.Code != xrpc.CodeFailed {
		t.Fatalf("端口被占重启应当回 failed：%v", err)
	}
	if snap := snapshot(); snap.KernelRunning {
		t.Fatalf("启动失败后快照应当报内核没在跑：%+v", snap)
	}
	os.WriteFile(cfgPath, config, 0o600)
	res = restart()
	if !res.Running || !snapshot().KernelRunning {
		t.Fatal("恢复配置后再重启应当起来")
	}
	if err := echoThrough(client); err != nil {
		t.Fatalf("恢复后经 VLESS 应当能回显：%v", err)
	}
}

// agent-kernel「重启内核」（m2-04 tasks 2.4 后两项）：
// 6. 重启卡在下载远程规则集时断开假主控的连接：放行下载之后内核起来；
// 7. 同样卡住时取消 ctx：runAgent 很快返回、退出码 0。
func TestKernelRestartDisconnectAndCancel(t *testing.T) {
	t.Run("断开连接不打断重启", func(t *testing.T) {
		s := kt.StartServer(t)
		config := s.Config()
		if err := s.Kernel.Stop(); err != nil {
			t.Fatal(err)
		}
		hit, release := make(chan struct{}, 1), make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case hit <- struct{}{}:
			default:
			}
			select {
			case <-release:
				w.Write([]byte(`{"version":1,"rules":[{"domain":["example.com"]}]}`))
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(func() {
			select {
			case <-release:
			default:
				close(release)
			}
			srv.Close()
		})

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, kernelConfig)
		os.WriteFile(cfgPath, config, 0o600)
		m := startTestMaster(t)
		_, _ = startAgent(t, m, dir, nil)
		call := waitCall(t, m)
		client := kt.StartClient(t, s.Target(), kt.UserA, kt.InVLESS)

		os.WriteFile(cfgPath, withRemoteRuleSet(t, config, srv.URL+"/rs.json"), 0o600)
		go func() { _, _ = call(xrpc.MethodKernelRestart, nil) }()
		select {
		case <-hit:
		case <-time.After(5 * time.Second):
			t.Fatal("重启时应当去下载远程规则集")
		}
		m.drop()
		select {
		case <-m.gone:
		case <-time.After(3 * time.Second):
			t.Fatal("假主控应当看到连接断开")
		}
		time.Sleep(150 * time.Millisecond) // 给通道 goroutine 一点时间把连接的 ctx 取消掉
		close(release)

		deadline := time.Now().Add(5 * time.Second)
		var lastErr error
		for time.Now().Before(deadline) {
			if lastErr = echoThrough(client); lastErr == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("放行远程规则集下载之后内核应当起来并能回显：%v", lastErr)
	})

	t.Run("卡住时取消ctx很快退出", func(t *testing.T) {
		s := kt.StartServer(t)
		config := s.Config()
		if err := s.Kernel.Stop(); err != nil {
			t.Fatal(err)
		}
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
		cfgPath := filepath.Join(dir, kernelConfig)
		os.WriteFile(cfgPath, config, 0o600)
		m := startTestMaster(t)
		cancel, code := startAgent(t, m, dir, nil)
		call := waitCall(t, m)

		os.WriteFile(cfgPath, withRemoteRuleSet(t, config, srv.URL+"/rs.json"), 0o600)
		go func() { _, _ = call(xrpc.MethodKernelRestart, nil) }()
		select {
		case <-hit:
		case <-time.After(5 * time.Second):
			t.Fatal("重启时应当去下载远程规则集")
		}
		cancel()
		select {
		case c := <-code:
			if c != 0 {
				t.Fatalf("退出码应当是 0：%d", c)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("重启期间收到退出，runAgent 应当很快返回")
		}
	})
}

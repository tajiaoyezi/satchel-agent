package channel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// fakeMaster 是测试里的主控：用 pkg/xrpc 握手、认证、收心跳，能按需拒绝认证、向节点发请求（m2-02 design 第 10 条）。
type fakeMaster struct {
	t        *testing.T
	priv     ed25519.PrivateKey
	reject   string // 非空时以这个原因拒绝认证
	interval int
	rawOnly  bool // 为真时握手之后不认证，只把节点发来的每一帧原样记进 raw（明文的也算）

	mu      sync.Mutex
	ln      net.Listener
	srv     *http.Server
	conns   []*websocket.Conn
	headers []http.Header
	uris    []string

	auths      chan xrpc.Auth
	heartbeats chan time.Time
	callers    chan func(method string, params any) (json.RawMessage, error)
	raw        chan []byte
	rawEnd     chan error // rawOnly 时连接读到错误（节点断开）就送一次
}

func newFakeMaster(t *testing.T) *fakeMaster {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := &fakeMaster{t: t, priv: priv, interval: 30, auths: make(chan xrpc.Auth, 64), heartbeats: make(chan time.Time, 64),
		callers: make(chan func(string, any) (json.RawMessage, error), 8), raw: make(chan []byte, 64), rawEnd: make(chan error, 8)}
	m.listen("127.0.0.1:0")
	t.Cleanup(m.stop)
	return m
}

func (m *fakeMaster) pub() ed25519.PublicKey { return m.priv.Public().(ed25519.PublicKey) }

func (m *fakeMaster) url() string { return "http://" + m.ln.Addr().String() }

func (m *fakeMaster) listen(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		m.t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(m.handle)}
	m.mu.Lock()
	m.ln, m.srv = ln, srv
	m.mu.Unlock()
	go srv.Serve(ln)
}

// stop 关掉监听与所有连接（模拟主控停掉）。
func (m *fakeMaster) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srv != nil {
		m.srv.Close()
		m.srv = nil
	}
	for _, c := range m.conns {
		c.CloseNow()
	}
	m.conns = nil
}

func (m *fakeMaster) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.headers = append(m.headers, r.Header.Clone())
	m.uris = append(m.uris, r.URL.RequestURI())
	m.mu.Unlock()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.conns = append(m.conns, ws)
	m.mu.Unlock()
	defer ws.CloseNow()
	conn := xrpc.NewConn(ws)
	ctx := context.Background()
	if err := xrpc.ServerHandshake(ctx, conn, m.priv); err != nil {
		return
	}
	if m.rawOnly {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				m.rawEnd <- err
				return
			}
			m.raw <- data
		}
	}
	msg, err := conn.Read(ctx)
	if err != nil || msg.Type != xrpc.TypeAuth {
		return
	}
	var auth xrpc.Auth
	_ = xrpc.Decode(msg, &auth)
	m.auths <- auth
	if m.reject != "" {
		_ = conn.Write(ctx, xrpc.TypeAuthResult, xrpc.AuthResult{OK: false, Reason: m.reject, Message: "拒绝"})
		return
	}
	_ = conn.Write(ctx, xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: m.interval})
	caller := xrpc.NewCaller()
	m.callers <- func(method string, params any) (json.RawMessage, error) {
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
			m.heartbeats <- time.Now()
			_ = conn.Write(ctx, xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now()})
		case xrpc.TypeReply:
			var r xrpc.Reply
			_ = xrpc.Decode(msg, &r)
			caller.Deliver(r)
		}
	}
}

func fastBackoff() Backoff {
	return Backoff{Base: 20 * time.Millisecond, Max: 100 * time.Millisecond, AuthStep: 20 * time.Millisecond, AuthMax: 100 * time.Millisecond,
		Penalty: time.Second, PenaltyAfter: 10}
}

func runClient(t *testing.T, cfg Config) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = New(cfg).Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run 没有在 ctx 结束后返回")
		}
	})
	return cancel
}

func waitAuth(t *testing.T, m *fakeMaster) xrpc.Auth {
	t.Helper()
	select {
	case a := <-m.auths:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("等不到认证")
	}
	return xrpc.Auth{}
}

// node-channel「主控公钥不对」：节点验签失败并断开，token 没有发出去：握手回复之后一帧都没有发（加密的、明文的都没有），
// 断开时的关闭原因（不加密）与升级请求的地址、请求头里也没有 token。
func TestWrongMasterKey(t *testing.T) {
	const token = "tok-wrong-master-key-7f3a"
	m := newFakeMaster(t)
	m.rawOnly = true
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	c := New(Config{MasterURL: m.url(), Token: token, MasterKey: other, AgentVersion: "1.0.0"})
	authenticated, err := c.session(context.Background())
	var ae *AuthError
	if authenticated || !errors.As(err, &ae) || ae.Reason != badMasterKey {
		t.Fatalf("主控公钥不对应当验签失败：%v %v", authenticated, err)
	}
	select {
	case end := <-m.rawEnd:
		if strings.Contains(end.Error(), token) {
			t.Fatalf("关闭原因里不应当有 token：%v", end)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("节点应当断开连接")
	}
	// 帧在断开之前就已经送进 raw，这里不用再等。
	select {
	case f := <-m.raw:
		t.Fatalf("握手回复之后节点不应当再发任何帧：%q", f)
	default:
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, h := range m.headers {
		if strings.Contains(m.uris[i], token) || strings.Contains(fmt.Sprint(h), token) {
			t.Fatalf("升级请求里不应当有 token：%s %v", m.uris[i], h)
		}
	}
}

// 认证与心跳：认证消息带 token、版本号与控制协议号；升级请求只带 User-Agent、不带 Authorization；
// 心跳间隔跟着认证结果走（认证成功后立即发第一次）；agent.info 回版本号与协议号。
func TestAuthHeartbeatAndInfo(t *testing.T) {
	m := newFakeMaster(t)
	m.interval = 1
	runClient(t, Config{MasterURL: m.url(), Token: "tok-1", MasterKey: m.pub(), AgentVersion: "9.9.9", Backoff: fastBackoff()})
	a := waitAuth(t, m)
	if a.Token != "tok-1" || a.AgentVersion != "9.9.9" || a.ControlProtocol != xrpc.ControlProtocol {
		t.Fatalf("认证消息不对：%+v", a)
	}
	m.mu.Lock()
	h := m.headers[0]
	m.mu.Unlock()
	if h.Get("Authorization") != "" || h.Get("User-Agent") != "satchel-agent/9.9.9" {
		t.Fatalf("升级请求只带 User-Agent：%v", h)
	}
	var beats []time.Time
	deadline := time.After(3 * time.Second)
	for len(beats) < 3 {
		select {
		case b := <-m.heartbeats:
			beats = append(beats, b)
		case <-deadline:
			t.Fatalf("3 秒内应当收到 3 次心跳（立即一次，之后每秒一次）：%d", len(beats))
		}
	}
	if gap := beats[2].Sub(beats[1]); gap < 800*time.Millisecond || gap > 1500*time.Millisecond {
		t.Fatalf("心跳间隔应当约 1 秒：%v", gap)
	}
	call := <-m.callers
	raw, err := call(xrpc.MethodAgentInfo, nil)
	var info xrpc.AgentInfo
	if err != nil || json.Unmarshal(raw, &info) != nil || info.AgentVersion != "9.9.9" || info.ControlProtocol != xrpc.ControlProtocol {
		t.Fatalf("agent.info：%s %v", raw, err)
	}
	var rerr *xrpc.Error
	if _, err := call("no.such", nil); !errors.As(err, &rerr) || rerr.Code != xrpc.CodeUnknownMethod {
		t.Fatalf("不认识的方法应当回 unknown_method：%v", err)
	}
}

// node-channel「主控重启后自动连回」：主控停掉再在同一地址起来，节点在退避间隔内重新连上并认证。
func TestReconnectAfterMasterRestart(t *testing.T) {
	m := newFakeMaster(t)
	addr := m.ln.Addr().String()
	runClient(t, Config{MasterURL: m.url(), Token: "tok", MasterKey: m.pub(), AgentVersion: "1.0.0", Backoff: fastBackoff()})
	waitAuth(t, m)
	m.stop()
	time.Sleep(300 * time.Millisecond) // 这段时间里节点按退避反复连不上
	m.listen(addr)
	waitAuth(t, m)
}

// node-channel「认证失败时退避变长」：token 无效时依次等 30、60、90 秒……封顶 10 分钟；连续 10 次后睡 30 分钟再重新计数。
// 用记录等待时长、立即返回的 Sleep，不真等。
func TestAuthFailureBackoff(t *testing.T) {
	m := newFakeMaster(t)
	m.reject = xrpc.AuthInvalidToken
	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := New(Config{MasterURL: m.url(), Token: "bad", MasterKey: m.pub(), AgentVersion: "1.0.0",
		Sleep: func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			if len(waits) == 12 {
				cancel()
			}
			return ctx.Err()
		}})
	_ = c.Run(ctx)
	want := []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second, 120 * time.Second, 150 * time.Second, 180 * time.Second,
		210 * time.Second, 240 * time.Second, 270 * time.Second, 30 * time.Minute, 30 * time.Second, 60 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("等待次数不对：%v", waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("第 %d 次等待应当是 %v，得到 %v（全部：%v）", i+1, want[i], waits[i], waits)
		}
	}

	// 普通失败：从 5 秒起翻倍，封顶 5 分钟。
	m.stop()
	waits = nil
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	c2 := New(Config{MasterURL: m.url(), Token: "t", MasterKey: m.pub(), AgentVersion: "1.0.0",
		Sleep: func(ctx context.Context, d time.Duration) error {
			waits = append(waits, d)
			if len(waits) == 8 {
				cancel2()
			}
			return ctx.Err()
		}})
	_ = c2.Run(ctx2)
	wantPlain := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second,
		5 * time.Minute, 5 * time.Minute}
	for i := range wantPlain {
		if i >= len(waits) || waits[i] != wantPlain[i] {
			t.Fatalf("普通失败的等待应当是 %v，得到 %v", wantPlain, waits)
		}
	}
}

// node-limiter「通道上的连接管控方法」：主控经通道调五个方法，tracker 是真的、不起内核。
func TestControlMethodsOverChannel(t *testing.T) {
	newClient := func(inbounds []string) func(string, any) (json.RawMessage, error) {
		t.Helper()
		m := newFakeMaster(t)
		tr := tracker.New()
		store, err := limits.Open(filepath.Join(t.TempDir(), limits.FileName), tr, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		methods := control.Methods(control.Deps{Limits: store, Tracker: tr, Kernel: kernel.New(tr), Inbounds: inbounds})
		runClient(t, Config{MasterURL: m.url(), Token: "tok", MasterKey: m.pub(), AgentVersion: "1.0.0", Methods: methods})
		waitAuth(t, m)
		return <-m.callers
	}
	badParams := func(err error) bool {
		var e *xrpc.Error
		return errors.As(err, &e) && e.Code == xrpc.CodeBadParams
	}
	state := func(raw json.RawMessage, err error) xrpc.LimiterState {
		t.Helper()
		var st xrpc.LimiterState
		if err != nil || json.Unmarshal(raw, &st) != nil {
			t.Fatalf("回复不对：%s %v", raw, err)
		}
		return st
	}
	call := newClient([]string{"vless-in", "hy2-in"})
	set := func(source string, mbps int64) (json.RawMessage, error) {
		return call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Credential: "a", Source: source, BPS: mbps * 1_000_000})
	}
	// 来源不认识：拒绝、状态不变。
	if _, err := set("boss", 5); !badParams(err) {
		t.Fatalf("来源 boss 应当回参数不合法：%v", err)
	}
	// 三份来源取最小，撤掉主控临时以后由剩下的重新算。
	state(set(xrpc.SourceStatic, 10))
	if st := state(set(xrpc.SourceMaster, 5)); len(st.Sources) != 2 || st.EffectiveBPS != 5_000_000 {
		t.Fatalf("来源 boss 不应当改动状态，静态 10、主控临时 5 → 5：%+v", st)
	}
	state(set(xrpc.SourceNodeRule, 8))
	st := state(call(xrpc.MethodLimiterUnset, xrpc.LimiterUnsetParams{Inbound: "vless-in", Credential: "a", Source: xrpc.SourceMaster}))
	if st.EffectiveBPS != 8_000_000 || len(st.Sources) != 2 {
		t.Fatalf("撤掉主控临时以后应当是 8 Mbps：%+v", st)
	}
	// 入站不存在、凭据名为空、值为负：都拒绝。
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "nope", Credential: "a", Source: xrpc.SourceMaster, BPS: 1}); !badParams(err) ||
		!strings.Contains(err.Error(), "nope") {
		t.Fatalf("入站不存在应当回参数不合法：%v", err)
	}
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Source: xrpc.SourceMaster, BPS: 1}); !badParams(err) {
		t.Fatalf("凭据名为空应当回参数不合法：%v", err)
	}
	if _, err := set(xrpc.SourceMaster, -1); !badParams(err) {
		t.Fatalf("负数应当回参数不合法：%v", err)
	}
	// 没给 bps 不能当成 0（那会静默解除已有的限速）；截止时间是零值或已经过了也拒绝。三种都不改状态。
	state(set(xrpc.SourceMaster, 5))
	if _, err := call(xrpc.MethodLimiterSet, map[string]string{"inbound": "vless-in", "credential": "a", "source": "master"}); !badParams(err) ||
		!strings.Contains(err.Error(), "bps") {
		t.Fatalf("没给 bps 应当回参数不合法：%v", err)
	}
	for _, d := range []time.Time{{}, time.Now().Add(-time.Minute)} {
		if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Credential: "a", Source: xrpc.SourceMaster, BPS: 1, Deadline: &d}); !badParams(err) ||
			!strings.Contains(err.Error(), "已经过了") {
			t.Fatalf("截止时间 %v 应当回参数不合法：%v", d, err)
		}
	}
	if st := state(set(xrpc.SourceStatic, 10)); st.EffectiveBPS != 5_000_000 || st.Sources[1].BPS != 5_000_000 || st.Sources[1].Deadline != nil {
		t.Fatalf("被拒的请求不应当改动主控临时的 5 Mbps：%+v", st)
	}
	// 合法的边界：值为 0（这一份显式不限速）与将来的截止时间都能设上，回复里带着它们。
	if st := state(set(xrpc.SourceMaster, 0)); len(st.Sources) != 3 || st.Sources[1].BPS != 0 || st.EffectiveBPS != 8_000_000 {
		t.Fatalf("主控临时设成 0 应当成功、退出取最小（剩静态 10 与节点规则 8）：%+v", st)
	}
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	st = state(call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Credential: "a", Source: xrpc.SourceMaster, BPS: 4_000_000, Deadline: &future}))
	if st.Sources[1].Deadline == nil || !st.Sources[1].Deadline.Equal(future) || st.EffectiveBPS != 4_000_000 {
		t.Fatalf("将来的截止时间应当能设上：%+v", st)
	}
	// 没有连接时列连接是空列表、踢线 0 条。
	raw, err := call(xrpc.MethodConnectionsList, xrpc.ConnectionsListParams{Inbound: "vless-in", Credential: "a"})
	if err != nil || !strings.Contains(string(raw), `"connections":[]`) {
		t.Fatalf("没有连接时应当是空列表：%s %v", raw, err)
	}
	if raw, err := call(xrpc.MethodConnectionsKick, xrpc.ConnectionsKickParams{Credential: "a"}); err != nil || !strings.Contains(string(raw), `"kicked":0`) {
		t.Fatalf("没有连接时踢 0 条：%s %v", raw, err)
	}
	// 快照：内核没在跑。
	raw, err = call(xrpc.MethodTrafficSnapshot, nil)
	var snap xrpc.TrafficSnapshot
	if err != nil || json.Unmarshal(raw, &snap) != nil || snap.KernelRunning || snap.BootID == "" || snap.KernelStartedAt != nil {
		t.Fatalf("没起内核时快照应当报内核没在跑：%s %v", raw, err)
	}

	// 没有内核配置：limiter.set 回「节点没有内核配置」，快照照常回。
	call = newClient(nil)
	if _, err := call(xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in", Credential: "a", Source: xrpc.SourceMaster, BPS: 1}); !badParams(err) ||
		!strings.Contains(err.Error(), "没有内核配置") {
		t.Fatalf("没有内核配置时应当拒绝：%v", err)
	}
	if _, err := call(xrpc.MethodTrafficSnapshot, nil); err != nil {
		t.Fatalf("没有内核配置时快照照常回：%v", err)
	}
}

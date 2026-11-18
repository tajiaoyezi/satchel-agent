package channel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func signedNodeReq(t *testing.T, priv ed25519.PrivateKey, baseURL, path, token, sid string, body []byte) (*http.Response, error) {
	t.Helper()
	method := http.MethodGet
	if path != xrpc.HTTPNodePathHealth {
		method = http.MethodPost
	}
	nonce, err := securechan.RandomNonce()
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", securechan.UserAgentPrefix+"master/test")
	req.Header.Set(securechan.HeaderNonce, nonce)
	req.Header.Set(securechan.HeaderAuth, securechan.SignSilentAuth(token, method, path, nonce))
	if sid != "" {
		req.Header.Set(securechan.HeaderSession, sid)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	return client.Do(req)
}

func handshakeNode(t *testing.T, priv ed25519.PrivateKey, baseURL, token string) (string, *securechan.Session, error) {
	t.Helper()
	resp, err := signedNodeReq(t, priv, baseURL, xrpc.HTTPNodePathHandshakeInit, token, "", []byte("{}"))
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, errors.New(resp.Status)
	}
	var initResp xrpc.NodeHandshakeInitResp
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return "", nil, err
	}
	agentEph, err := ecdh.X25519().NewPublicKey(initResp.AgentEphemeral)
	if err != nil {
		return "", nil, err
	}
	masterPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	masterBytes := masterPriv.PublicKey().Bytes()
	shared, _ := masterPriv.ECDH(agentEph)
	sess, err := securechan.DeriveSession(shared, initResp.AgentEphemeral, masterBytes, true)
	if err != nil {
		return "", nil, err
	}
	finReq, _ := json.Marshal(xrpc.NodeHandshakeFinishReq{
		HandshakeID:     initResp.HandshakeID,
		MasterEphemeral: masterBytes,
		Signature:       securechan.SignHandshake(priv, initResp.AgentEphemeral, masterBytes),
	})
	resp2, err := signedNodeReq(t, priv, baseURL, xrpc.HTTPNodePathHandshakeFinish, token, "", finReq)
	if err != nil {
		return "", nil, err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return "", nil, errors.New(resp2.Status)
	}
	var finResp xrpc.NodeHandshakeFinishResp
	if err := json.NewDecoder(resp2.Body).Decode(&finResp); err != nil {
		return "", nil, err
	}
	return finResp.SessionID, sess, nil
}

func callNodeRPC(t *testing.T, priv ed25519.PrivateKey, baseURL, token, sid string, sess *securechan.Session, method string, params any) (int, xrpc.Reply, error) {
	t.Helper()
	var rawParams json.RawMessage
	if params != nil {
		rawParams, _ = json.Marshal(params)
	}
	cb, _ := json.Marshal(xrpc.Call{ID: "1", Method: method, Params: rawParams})
	env, _ := sess.Encrypt(cb)
	resp, err := signedNodeReq(t, priv, baseURL, xrpc.HTTPNodePathRPC, token, sid, env)
	if err != nil {
		return 0, xrpc.Reply{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, xrpc.Reply{}, nil
	}
	dec, err := sess.Decrypt(data)
	if err != nil {
		return resp.StatusCode, xrpc.Reply{}, err
	}
	var rep xrpc.Reply
	_ = json.Unmarshal(dec, &rep)
	return resp.StatusCode, rep, nil
}

// 缺主控公钥时 Run 直接报错，且不启动任何监听或连接。
func TestRunRefusesMissingMasterKey(t *testing.T) {
	lp, pp := freeTCPPort(t), freeTCPPort(t)
	c := New(Config{
		MasterURL:  "https://127.0.0.1:1",
		Token:      "tok",
		AgentToken: "agt",
		PullToken:  "pul",
		Mode:       config.ModeAuto,
		ListenHost: "127.0.0.1",
		ListenPort: lp,
		PullPort:   pp,
	})
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("缺少 MasterKey 时必须拒绝启动")
	}
	if mAddr, pAddr := c.InboundAddrs(); mAddr != "" || pAddr != "" {
		t.Fatalf("拒绝启动后不应打开任何监听口：manage=%q pull=%q", mAddr, pAddr)
	}
}

// websocket 固定模式不开放端口；auto 模式 WS 认证稳定满宽限后进入隐身关端口，断线即刻重开端口。
func TestWebsocketZeroListenAndAutoPortStealth(t *testing.T) {
	m := newFakeMaster(t)
	// 1. 固定 websocket 断连期间也绝不开端口。
	cWS := New(Config{
		MasterURL: m.url(), Token: "tok", MasterKey: m.pub(),
		Mode: config.ModeWebsocket, ListenHost: "127.0.0.1", ListenPort: freeTCPPort(t), PullPort: freeTCPPort(t),
		Backoff: fastBackoff(),
	})
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- cWS.Run(ctx1) }()
	waitAuth(t, m)
	m.stop()
	time.Sleep(80 * time.Millisecond)
	if mAddr, pAddr := cWS.InboundAddrs(); mAddr != "" || pAddr != "" {
		t.Fatalf("websocket 模式在连接和重连期间均不应监听端口：%q %q", mAddr, pAddr)
	}
	cancel1()
	<-done1

	// 2. auto 模式：WS 不可用先开双口 -> 连上 WS 后满 StealthDelay(80ms) 关闭双口 -> WS 断线立即重开双口。
	m2 := newFakeMaster(t)
	addr2 := m2.ln.Addr().String()
	m2.stop() // 初始让 WS 不通，测试端口保持打开

	lp, pp := freeTCPPort(t), freeTCPPort(t)
	cAuto := New(Config{
		MasterURL: "http://" + addr2, Token: "tok", AgentToken: "agt", PullToken: "pul",
		MasterKey: m2.pub(), Mode: config.ModeAuto,
		ListenHost: "127.0.0.1", ListenPort: lp, PullPort: pp,
		StealthDelay: 80 * time.Millisecond, WSProbeInterval: 50 * time.Millisecond,
		HTTPFailLimit: 50, PullWindowBase: 50 * time.Millisecond,
		HTTPHeartbeatInterval: 30 * time.Millisecond,
		Backoff:               fastBackoff(),
	})
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- cAuto.Run(ctx2) }()
	defer func() { cancel2(); <-done2 }()

	// 等双口就绪后恢复主控 WS。
	waitForAddr := func(wantOpen bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			ma, pa := cAuto.InboundAddrs()
			isOpen := ma != "" && pa != ""
			isClosed := ma == "" && pa == ""
			if (wantOpen && isOpen) || (!wantOpen && isClosed) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("等待端口状态 open=%v 超时：manage=%q pull=%q", wantOpen, ma, pa)
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	waitForAddr(true)
	m2.listen(addr2)
	waitAuth(t, m2)

	// 满 StealthDelay 后端口应当关闭隐身。
	waitForAddr(false)
	// TCP 拨号必须被拒。
	if conn, err := net.DialTimeout("tcp", fmtAddr(lp), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("auto 隐身之后管理端口不应再接受 TCP 连接")
	}

	// 掐断主控 WS：节点必须立即取消隐身重新打开双口。
	m2.stop()
	waitForAddr(true)
}

func fmtAddr(p int) string { return net.JoinHostPort("127.0.0.1", itoa(p)) }
func itoa(n int) string    { return (&net.TCPAddr{Port: n}).AddrPort().String()[1:] }

// 静默认证直接丢弃未授权连接（零响应字节），强制 securechan 不回退明文，且 pull 轮询口拒绝管理 RPC；
// online token.rotate 先写回 0600 config.yaml 再清旧会话。
func TestInboundSecurityIsolationAndTokenRotate(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	initCfg := config.Config{
		MasterURL: "https://panel.example.com", Token: "tok-1", AgentToken: "agt-1", PullToken: "pul-1",
		MasterPublicKey: securechan.EncodePublicKey(pub), ConnectionMode: config.ModePull,
		ListenPort: freeTCPPort(t), PullPort: freeTCPPort(t),
	}
	if err := config.Save(cfgPath, initCfg); err != nil {
		t.Fatal(err)
	}

	var manageCalls atomic.Int32
	methods := xrpc.Methods{
		xrpc.MethodLimiterSet: func(context.Context, json.RawMessage) (any, error) {
			manageCalls.Add(1)
			return xrpc.LimiterState{Inbound: "vless-in", Credential: "a", Limited: true, EffectiveBPS: 1_000_000}, nil
		},
		xrpc.MethodTrafficSnapshot: func(context.Context, json.RawMessage) (any, error) {
			return xrpc.TrafficSnapshot{BootID: "b-pull", Generation: 1, KernelRunning: true}, nil
		},
	}
	c := New(Config{
		MasterURL: initCfg.MasterURL, Token: initCfg.Token, AgentToken: initCfg.AgentToken, PullToken: initCfg.PullToken,
		MasterKey: pub, Mode: config.ModePull, ListenHost: "127.0.0.1",
		ListenPort: initCfg.ListenPort, PullPort: initCfg.PullPort,
		ConfigPath: cfgPath, Methods: methods, AgentVersion: "0.2.0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()

	var mAddr, pAddr string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		mAddr, pAddr = c.InboundAddrs()
		if mAddr != "" && pAddr != "" {
			break
		}
	}
	if mAddr == "" || pAddr == "" {
		t.Fatal("pull 模式应开启双端口")
	}
	mURL, pURL := "http://"+mAddr, "http://"+pAddr

	// 1. 未通过 SilentAuth 的 GET /health 与 POST /handshake/init 必须零字节断连（EOF）。
	for _, targetAddr := range []string{mAddr, pAddr} {
		for _, reqLine := range []string{"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", "POST /handshake/init HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"} {
			conn, err := net.DialTimeout("tcp", targetAddr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = conn.Write([]byte(reqLine))
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 128)
			n, rerr := conn.Read(buf)
			_ = conn.Close()
			if n != 0 || !errors.Is(rerr, io.EOF) {
				t.Fatalf("未授权探测应当零字节直接 EOF：n=%d err=%v raw=%q", n, rerr, buf[:n])
			}
		}
	}

	// 2. 通过 SilentAuth 后：缺会话 412、明文直通 400；轮询口只放行 traffic.snapshot 与 agent.health，拒绝 limiter.set 且不触发业务处理。
	if resp, err := signedNodeReq(t, priv, mURL, xrpc.HTTPNodePathRPC, "agt-1", "", []byte(`{}`)); err != nil || resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("缺会话应返 412：%v %v", resp, err)
	}
	pSID, pSess, err := handshakeNode(t, priv, pURL, "pul-1")
	if err != nil {
		t.Fatal(err)
	}
	// 带合法会话发送未经加密 JSON -> 400
	if resp, err := signedNodeReq(t, priv, pURL, xrpc.HTTPNodePathRPC, "pul-1", pSID, []byte(`{"method":"agent.health"}`)); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("明文载荷应被拒绝 400：%v %v", resp, err)
	}
	// 轮询口调用 traffic.snapshot 成功；调用 limiter.set 被加密拒绝，且 manageCalls 为 0。
	code, rep, err := callNodeRPC(t, priv, pURL, "pul-1", pSID, pSess, xrpc.MethodTrafficSnapshot, nil)
	if err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("轮询口允许 traffic.snapshot：code=%d rep=%+v err=%v", code, rep, err)
	}
	code, rep, err = callNodeRPC(t, priv, pURL, "pul-1", pSID, pSess, xrpc.MethodLimiterSet, xrpc.LimiterSetParams{Inbound: "vless-in"})
	if err != nil || code != 200 || rep.Error == nil || manageCalls.Load() != 0 {
		t.Fatalf("轮询口必须拒绝 limiter.set 且绝不进业务回调：code=%d rep=%+v calls=%d", code, rep, manageCalls.Load())
	}

	// 3. 管理口调用 limiter.set 成功。
	mSID, mSess, err := handshakeNode(t, priv, mURL, "agt-1")
	if err != nil {
		t.Fatal(err)
	}
	code, rep, err = callNodeRPC(t, priv, mURL, "agt-1", mSID, mSess, xrpc.MethodLimiterSet, xrpc.LimiterSetParams{})
	if err != nil || code != 200 || rep.Error != nil || manageCalls.Load() != 1 {
		t.Fatalf("管理口应当允许 limiter.set：code=%d rep=%+v calls=%d err=%v", code, rep, manageCalls.Load(), err)
	}

	// 4. 在线 token.rotate：写 0600 文件、回传当次加密 ACK、旧凭据/旧会话立即失效、新凭据可用。
	code, rep, err = callNodeRPC(t, priv, mURL, "agt-1", mSID, mSess, xrpc.MethodTokenRotate, xrpc.TokenRotateParams{
		Token: "tok-2", AgentToken: "agt-2", PullToken: "pul-2",
	})
	if err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("token.rotate 应当返回加密 ACK：code=%d rep=%+v err=%v", code, rep, err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil || loaded.Token != "tok-2" || loaded.AgentToken != "agt-2" || loaded.PullToken != "pul-2" {
		t.Fatalf("config.yaml 应当原子持久化新凭据：%+v err=%v", loaded, err)
	}
	// 旧 agent_token 被 SilentAuth 直接 EOF 切断；新 agent_token+旧 sessionID 返回 412；新握手成功。
	if _, err := signedNodeReq(t, priv, mURL, xrpc.HTTPNodePathHealth, "agt-1", "", nil); err == nil {
		t.Fatal("轮换后旧 agent_token 应当被 SilentAuth 静默断开")
	}
	if resp, err := signedNodeReq(t, priv, mURL, xrpc.HTTPNodePathRPC, "agt-2", mSID, []byte("x")); err != nil || resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("轮换后管理口旧 session 应当被清空（回 412）：%v %v", resp, err)
	}
	newSID, newSess, err := handshakeNode(t, priv, mURL, "agt-2")
	if err != nil {
		t.Fatalf("新 agent_token 握手应当成功：%v", err)
	}
	if code, rep, err := callNodeRPC(t, priv, mURL, "agt-2", newSID, newSess, xrpc.MethodAgentHealth, nil); err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("新会话应正常工作：code=%d rep=%+v err=%v", code, rep, err)
	}
}

// 验证 auto 逐级降级（WS→HTTP→pull 窗口→WS 恢复）、固定 HTTP 永不探测 WS，以及公网 IP 漂移立即唤醒重连。
func TestAutoStateMachineFixedHTTPAndIPDrift(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	var (
		mu          sync.Mutex
		wsOpen      atomic.Bool
		httpOpen    atomic.Bool
		wsHits      atomic.Int32
		httpHits    atomic.Int32
		force412    atomic.Bool
		sessions    = securechan.NewSessionCache(securechan.SessionCacheConfig{TTL: time.Hour})
		wsAccepted  = make(chan string, 16)
		httpBeat    = make(chan string, 32)
		ipDriftStep atomic.Int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/remote/ws":
			wsHits.Add(1)
			if !wsOpen.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			ws, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			conn := xrpc.NewConn(ws)
			if err := xrpc.ServerHandshake(r.Context(), conn, priv); err != nil {
				return
			}
			msg, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			var a xrpc.Auth
			_ = xrpc.Decode(msg, &a)
			_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 1})
			wsAccepted <- a.Token
			<-r.Context().Done()
		case xrpc.HTTPMasterPathHandshake:
			if !httpOpen.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			var req xrpc.HTTPHandshakeReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			eph, _ := ecdh.X25519().NewPublicKey(req.AgentEphemeral)
			mPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
			shared, _ := mPriv.ECDH(eph)
			mPub := mPriv.PublicKey().Bytes()
			sess, _ := securechan.DeriveSession(shared, req.AgentEphemeral, mPub, true)
			sid, _ := securechan.GenerateSessionID()
			_ = sessions.Put(sid, sess, 1, "u")
			_ = json.NewEncoder(w).Encode(xrpc.HTTPHandshakeResp{
				SessionID: sid, MasterEphemeral: mPub, Signature: securechan.SignHandshake(priv, req.AgentEphemeral, mPub),
			})
		case xrpc.HTTPMasterPathRPC:
			httpHits.Add(1)
			if !httpOpen.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if force412.Swap(false) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			sid := r.Header.Get(securechan.HeaderSession)
			sess, _, _, ok := sessions.Get(sid)
			if !ok {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			body, _ := io.ReadAll(r.Body)
			plain, err := sess.Decrypt(body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var rpc xrpc.AgentHTTPRPC
			_ = json.Unmarshal(plain, &rpc)
			select {
			case httpBeat <- rpc.Method:
			default:
			}
			repBytes, _ := json.Marshal(xrpc.AgentHTTPRPCReply{OK: true, HeartbeatInterval: 1})
			enc, _ := sess.Encrypt(repBytes)
			_, _ = w.Write(enc)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	// 1. auto 逐级降级并在 WS 开放时自动升回。
	httpOpen.Store(true)
	force412.Store(true) // 首次 RPC 故意回 412，检验透明重握手
	cAuto := New(Config{
		MasterURL: srv.URL, Token: "tok-auto", AgentToken: "agt", PullToken: "pul",
		MasterKey: pub, Mode: config.ModeAuto,
		ListenHost: "127.0.0.1", ListenPort: freeTCPPort(t), PullPort: freeTCPPort(t),
		WSProbeInterval: 40 * time.Millisecond, HTTPFailLimit: 3,
		PullWindowBase: 40 * time.Millisecond, PullWindowMax: 80 * time.Millisecond,
		HTTPHeartbeatInterval: 20 * time.Millisecond, Backoff: fastBackoff(),
	})
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- cAuto.Run(ctx1) }()

	// 等 HTTP 降级上报成功（经历过 412 重协商）。
	select {
	case <-httpBeat:
	case <-time.After(3 * time.Second):
		t.Fatal("auto 应当先降级为加密 HTTP 上报")
	}

	// 关闭 HTTP 让节点连续失败进入 pull 窗口，再开放 WS，验证节点升回 WS。
	httpOpen.Store(false)
	time.Sleep(150 * time.Millisecond)
	wsOpen.Store(true)
	select {
	case tok := <-wsAccepted:
		if tok != "tok-auto" {
			t.Fatalf("升回 WS 的 token 不对：%q", tok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WS 恢复后 auto 应当升回 WebSocket")
	}
	cancel1()
	<-done1

	// 2. 固定 HTTP 模式绝不拨 /api/remote/ws，多次失败后恢复依然只走 HTTP。
	wsHits.Store(0)
	httpHits.Store(0)
	httpOpen.Store(false)
	cHTTP := New(Config{
		MasterURL: srv.URL, Token: "tok-http", AgentToken: "agt",
		MasterKey: pub, Mode: config.ModeHTTP,
		ListenHost: "127.0.0.1", ListenPort: freeTCPPort(t),
		HTTPHeartbeatInterval: 20 * time.Millisecond, Backoff: fastBackoff(),
	})
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- cHTTP.Run(ctx2) }()
	time.Sleep(100 * time.Millisecond)
	httpOpen.Store(true)
	select {
	case <-httpBeat:
	case <-time.After(3 * time.Second):
		t.Fatal("http 模式在主控恢复后应重连 HTTP 成功")
	}
	if wsHits.Load() != 0 {
		t.Fatalf("固定 http 模式绝不能向 /api/remote/ws 发请求，实际收到 %d 次", wsHits.Load())
	}
	cancel2()
	<-done2

	// 3. 公网 IP 漂移唤醒长退避睡眠中的 websocket 重连。
	wsOpen.Store(false)
	wsHits.Store(0)
	driftClient := New(Config{
		MasterURL: "http://127.0.0.1:1", Token: "tok-drift", MasterKey: pub,
		Mode: config.ModeWebsocket,
		Backoff: Backoff{
			Base: 10 * time.Second, Max: 10 * time.Second, AuthStep: 10 * time.Second, AuthMax: 10 * time.Second, Penalty: time.Hour, PenaltyAfter: 10,
		},
		IPProbeInterval: 20 * time.Millisecond,
		IPProber: func(context.Context) (string, string, error) {
			if ipDriftStep.Add(1) <= 2 {
				return "198.51.100.1", "", nil
			}
			return "203.0.113.5", "", nil
		},
	})
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	// 用可追踪的 Sleep 捕获唤醒：实际等待应远远短于 10 秒。
	var sleeps []time.Duration
	var wokeCount atomic.Int32
	origSleep := driftClient.cfg.Sleep
	driftClient.cfg.Sleep = func(sctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		began := time.Now()
		err := origSleep(sctx, d)
		if time.Since(began) < 2*time.Second && err != nil && ctx3.Err() == nil {
			wokeCount.Add(1)
			cancel3()
		}
		return err
	}
	if err := driftClient.Run(ctx3); err != nil {
		t.Fatalf("Run 退出出错：%v", err)
	}
	if wokeCount.Load() == 0 {
		t.Fatal("检测到公网 IP 漂移后应当立刻打断 10 秒退避睡眠发起重连")
	}
	_ = slices.Contains(sleeps, 10*time.Second)
}

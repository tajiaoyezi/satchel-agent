package channel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/logging"
	"github.com/satchel/satchel-agent/internal/telemetry"
)

func callNodeRPCPath(t *testing.T, priv ed25519.PrivateKey, baseURL, rpcPath, token, sid string, sess *securechan.Session, method string, params any) (int, xrpc.Reply, error) {
	t.Helper()
	var rawParams json.RawMessage
	if params != nil {
		rawParams, _ = json.Marshal(params)
	}
	cb, _ := json.Marshal(xrpc.Call{ID: "1", Method: method, Params: rawParams})
	env, _ := sess.Encrypt(cb)
	resp, err := signedNodeReq(t, priv, baseURL, rpcPath, token, sid, env)
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

// pull_port 仅增量开放 /api/child/speed（speed.get），严格拒绝 system.info、system.nics、agent.logs、agent.logs.files 与 agent.config_update；
// 同一批方法在管理口 listen_port 全部可用。
func TestPullPortAllowsSpeedGetAndRejectsTelemetryLogsAndConfigUpdate(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "logs", "satchel-agent.log")
	logSet, err := logging.Setup(logPath, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer logSet.Close()
	logSet.Logger.Warn("pull isolation marker")

	fakeRead := func(p string) ([]byte, error) {
		switch p {
		case "/proc/net/dev":
			return []byte("Inter-| Receive | Transmit\neth0: 5000 1 0 0 0 0 0 0 7000 1 0 0 0 0 0 0\n"), nil
		case "/proc/stat":
			return []byte("cpu  100 0 50 850 0 0 0 0 0 0\nbtime 1700000001\n"), nil
		case "/proc/meminfo":
			return []byte("MemTotal: 1024 kB\nMemAvailable: 512 kB\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}
	sysCol := telemetry.NewSysCollector(telemetry.SysReader{
		ReadFile:      fakeRead,
		Hostname:      func() (string, error) { return "pull-node", nil },
		StatFS:        func(string) (int64, int64, error) { return 1000, 500, nil },
		NumCPU:        func() int { return 2 },
		CPUProbeDelay: 0,
	})
	speedCol := telemetry.NewSpeedCollector(fakeRead, time.Now)
	logInsp := telemetry.NewLogInspector(logSet.LogDir, filepath.Base(logSet.AgentLogPath), filepath.Base(logSet.CoreLogPath))

	var nicCalls atomic.Int32
	methods := control.Methods(control.Deps{
		Sys:   sysCol,
		Speed: speedCol,
		Logs:  logInsp,
		ListNICs: func() ([]xrpc.NICInfo, error) {
			nicCalls.Add(1)
			return []xrpc.NICInfo{{Name: "eth0"}}, nil
		},
	})

	var cfgApplied atomic.Int32
	c := New(Config{
		MasterURL:    "https://panel.example.com",
		Token:        "tok",
		AgentToken:   "agt-pull-test",
		PullToken:    "pul-pull-test",
		MasterKey:    pub,
		Mode:         config.ModePull,
		ListenHost:   "127.0.0.1",
		ListenPort:   freeTCPPort(t),
		PullPort:     freeTCPPort(t),
		Methods:      methods,
		AgentVersion: "0.2.0",
		OnAgentConfig: func(ac xrpc.AgentConfig) {
			cfgApplied.Add(1)
			logSet.SetDebugEnabled(ac.AgentLogEnabled)
		},
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
		t.Fatal("pull 模式未监听双端口")
	}
	mURL, pURL := "http://"+mAddr, "http://"+pAddr

	// 1. pull_port：/api/child/speed 放行 speed.get，且拒绝其余遥测/日志/配置方法。
	pSID, pSess, err := handshakeNode(t, priv, pURL, "pul-pull-test")
	if err != nil {
		t.Fatalf("pull_port handshake: %v", err)
	}
	code, rep, err := callNodeRPCPath(t, priv, pURL, xrpc.HTTPNodePathPullSpeed, "pul-pull-test", pSID, pSess, xrpc.MethodSpeedGet, nil)
	if err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("pull_port /api/child/speed 必须放行 speed.get：code=%d rep=%+v err=%v", code, rep, err)
	}
	var sr xrpc.SpeedReport
	if err := json.Unmarshal(rep.Result, &sr); err != nil || sr.SystemRxBytes != 5000 || sr.SystemTxBytes != 7000 {
		t.Fatalf("speed.get 返回不对：%s err=%v", rep.Result, err)
	}

	blocked := []struct {
		method string
		params any
	}{
		{xrpc.MethodSystemInfo, nil},
		{xrpc.MethodSystemNICs, nil},
		{xrpc.MethodAgentLogs, xrpc.AgentLogsParams{Service: "agent"}},
		{xrpc.MethodAgentLogFiles, nil},
		{xrpc.MethodAgentConfigUpdate, xrpc.AgentConfigUpdate{AgentLogEnabled: true}},
	}
	for _, tc := range blocked {
		code, rep, err := callNodeRPCPath(t, priv, pURL, xrpc.HTTPNodePathRPC, "pul-pull-test", pSID, pSess, tc.method, tc.params)
		if err != nil || code != 200 || rep.Error == nil || rep.Error.Code != xrpc.CodeUnknownMethod {
			t.Fatalf("pull_port 必须拒绝 %s：code=%d rep=%+v err=%v", tc.method, code, rep, err)
		}
	}
	if nicCalls.Load() != 0 || cfgApplied.Load() != 0 {
		t.Fatalf("pull_port 拒绝方法绝不能触发业务处理器：nicCalls=%d cfgApplied=%d", nicCalls.Load(), cfgApplied.Load())
	}

	// 2. manage_port：全部遥测、日志与配置热推方法均正常放行。
	mSID, mSess, err := handshakeNode(t, priv, mURL, "agt-pull-test")
	if err != nil {
		t.Fatalf("manage_port handshake: %v", err)
	}
	for _, tc := range []struct {
		method string
		params any
	}{
		{xrpc.MethodSystemInfo, nil},
		{xrpc.MethodSystemNICs, nil},
		{xrpc.MethodSpeedGet, nil},
		{xrpc.MethodAgentLogFiles, nil},
		{xrpc.MethodAgentLogs, xrpc.AgentLogsParams{Service: "agent", Level: "warn"}},
		{xrpc.MethodAgentConfigUpdate, xrpc.AgentConfigUpdate{AgentLogEnabled: true, HeartbeatInterval: 15, SpeedCollectInterval: 5}},
	} {
		code, rep, err := callNodeRPC(t, priv, mURL, "agt-pull-test", mSID, mSess, tc.method, tc.params)
		if err != nil || code != 200 || rep.Error != nil {
			t.Fatalf("manage_port %s 应当成功：code=%d rep=%+v err=%v", tc.method, code, rep, err)
		}
	}
	if nicCalls.Load() != 1 || cfgApplied.Load() != 1 || !logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatalf("manage_port 调用结果不对：nicCalls=%d cfgApplied=%d debugEnabled=%v",
			nicCalls.Load(), cfgApplied.Load(), logSet.Logger.Enabled(context.Background(), slog.LevelDebug))
	}
}

// 验证 WS 与 HTTP 模式均支持实时网速上报（TypeSpeed / HTTPRPCMethodSpeed），且 AuthResult.Config、
// AgentHTTPRPCReply.Config 与 agent.config_update 均能无重启热切换 LevelVar 与心跳/网速周期。
func TestWSAndHTTPRuntimeConfigHotReloadAndSpeedReporting(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	// 共用可递增的模拟 /proc/net/dev。
	var sampleTick atomic.Int64
	readProc := func(p string) ([]byte, error) {
		switch p {
		case "/proc/net/dev":
			n := sampleTick.Add(1)
			rx := 10000 + n*3000
			tx := 20000 + n*6000
			return []byte("Inter-| Receive | Transmit\neth0: " +
				json.Number(itoa64(rx)).String() + " 1 0 0 0 0 0 0 " +
				json.Number(itoa64(tx)).String() + " 1 0 0 0 0 0 0\n"), nil
		case "/proc/stat":
			return []byte("btime 1700000099\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}

	// --- Part A: WebSocket 模式 ---
	t.Run("websocket speed and agent.config_update hot reload", func(t *testing.T) {
		dir := t.TempDir()
		logSet, err := logging.Setup(filepath.Join(dir, "satchel-agent.log"), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer logSet.Close()

		wsSpeeds := make(chan xrpc.SpeedReport, 16)
		wsBeats := make(chan struct{}, 16)
		wsCallCh := make(chan func(method string, params any) (json.RawMessage, error), 2)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			conn := xrpc.NewConn(ws)
			if err := xrpc.ServerHandshake(r.Context(), conn, priv); err != nil {
				return
			}
			if _, err := conn.Read(r.Context()); err != nil {
				return
			}
			_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{
				OK:                true,
				HeartbeatInterval: 30,
				Config: &xrpc.AgentConfig{
					HeartbeatInterval:      30,
					SpeedCollectInterval:   1,
					TrafficCollectInterval: 60,
					AgentLogEnabled:        false,
				},
			})
			caller := xrpc.NewCaller()
			wsCallCh <- func(method string, params any) (json.RawMessage, error) {
				return caller.Call(context.Background(), conn, method, params, 3*time.Second)
			}
			for {
				m, err := conn.Read(r.Context())
				if err != nil {
					caller.CloseAll(nil)
					return
				}
				switch m.Type {
				case xrpc.TypeHeartbeat:
					select {
					case wsBeats <- struct{}{}:
					default:
					}
					_ = conn.Write(r.Context(), xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now()})
				case xrpc.TypeSpeed:
					var sr xrpc.SpeedReport
					if xrpc.Decode(m, &sr) == nil {
						select {
						case wsSpeeds <- sr:
						default:
						}
					}
				case xrpc.TypeReply:
					var rep xrpc.Reply
					_ = xrpc.Decode(m, &rep)
					caller.Deliver(rep)
				}
			}
		}))
		defer srv.Close()

		speedCol := telemetry.NewSpeedCollector(readProc, time.Now)
		speedCol.Sample() // prime baseline
		c := New(Config{
			MasterURL:            srv.URL,
			Token:                "tok-ws",
			MasterKey:            pub,
			Mode:                 config.ModeWebsocket,
			AgentVersion:         "0.2.0",
			Logger:               logSet.Logger,
			SpeedCollector:       speedCol,
			SpeedCollectInterval: 50 * time.Millisecond,
			OnAgentConfig: func(ac xrpc.AgentConfig) {
				logSet.SetDebugEnabled(ac.AgentLogEnabled)
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		defer func() { cancel(); <-done }()

		// 1. 连上后收到初始心跳与实时网速帧。
		var call func(string, any) (json.RawMessage, error)
		select {
		case call = <-wsCallCh:
		case <-time.After(3 * time.Second):
			t.Fatal("WS 节点未连上")
		}
		select {
		case <-wsBeats:
		case <-time.After(3 * time.Second):
			t.Fatal("未收到初始心跳")
		}
		select {
		case sr := <-wsSpeeds:
			if sr.SystemBootTimeUnix != 1700000099 {
				t.Fatalf("WS SpeedReport 缺少 btime：%+v", sr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("WS 未在周期内上报 TypeSpeed")
		}
		if logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			t.Fatal("初始 AgentLogEnabled=false 时不应开启 DEBUG")
		}

		// 2. 热推 agent.config_update：开启 DEBUG 且将心跳从 30s 缩到 1s，无需断线重连。
		if _, err := call(xrpc.MethodAgentConfigUpdate, xrpc.AgentConfigUpdate{
			HeartbeatInterval:      1,
			SpeedCollectInterval:   1,
			TrafficCollectInterval: 60,
			AgentLogEnabled:        true,
		}); err != nil {
			t.Fatalf("agent.config_update 失败：%v", err)
		}
		if !logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			t.Fatal("热推 agent_log_enabled=true 后应立刻切换 LevelVar 到 DEBUG")
		}
		// 心跳周期已从 30s 热改为 1s，应在 2.5s 内收到下一条心跳。
		select {
		case <-wsBeats:
		case <-time.After(2500 * time.Millisecond):
			t.Fatal("心跳间隔热更新为 1s 后未及时触发新心跳")
		}
	})

	// --- Part B: HTTP 模式 ---
	t.Run("http speed and reply config hot reload", func(t *testing.T) {
		dir := t.TempDir()
		logSet, err := logging.Setup(filepath.Join(dir, "satchel-agent.log"), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer logSet.Close()

		var (
			cfgMu     sync.Mutex
			curCfg    = xrpc.AgentConfig{HeartbeatInterval: 30, SpeedCollectInterval: 1, TrafficCollectInterval: 60, AgentLogEnabled: false}
			sessions  = securechan.NewSessionCache(securechan.SessionCacheConfig{TTL: time.Hour})
			httpSpeed = make(chan xrpc.SpeedReport, 16)
		)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case xrpc.HTTPMasterPathHandshake:
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
				var req xrpc.AgentHTTPRPC
				_ = json.Unmarshal(plain, &req)
				if req.Method == xrpc.HTTPRPCMethodSpeed && req.Speed != nil {
					select {
					case httpSpeed <- *req.Speed:
					default:
					}
				}
				cfgMu.Lock()
				cfgCopy := curCfg
				cfgMu.Unlock()
				repBytes, _ := json.Marshal(xrpc.AgentHTTPRPCReply{
					OK:                true,
					HeartbeatInterval: cfgCopy.HeartbeatInterval,
					Config:            &cfgCopy,
				})
				enc, _ := sess.Encrypt(repBytes)
				_, _ = w.Write(enc)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		speedCol := telemetry.NewSpeedCollector(readProc, time.Now)
		speedCol.Sample()
		c := New(Config{
			MasterURL:             srv.URL,
			Token:                 "tok-http",
			AgentToken:            "agt-http",
			MasterKey:             pub,
			Mode:                  config.ModeHTTP,
			ListenHost:            "127.0.0.1",
			ListenPort:            freeTCPPort(t),
			AgentVersion:          "0.2.0",
			Logger:                logSet.Logger,
			SpeedCollector:        speedCol,
			HTTPHeartbeatInterval: 30 * time.Second,
			SpeedCollectInterval:  1 * time.Second,
			OnAgentConfig: func(ac xrpc.AgentConfig) {
				logSet.SetDebugEnabled(ac.AgentLogEnabled)
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		defer func() { cancel(); <-done }()

		// 1. 收到首次 HTTP speed 上报且此时 DEBUG 未开启。
		select {
		case sr := <-httpSpeed:
			if sr.SystemBootTimeUnix != 1700000099 {
				t.Fatalf("HTTP SpeedReport 缺少 btime：%+v", sr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP 模式未上报 speed")
		}
		if logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			t.Fatal("初始 AgentLogEnabled=false 时不应开启 DEBUG")
		}

		// 2. 主控仅更新下次 HTTP 回复里的 Config.AgentLogEnabled=true（不发反向 management RPC）：
		// 即使心跳间隔是 30s，节点仍会在下一次 1s speed 上报回复里立即热切到 DEBUG！
		cfgMu.Lock()
		curCfg.AgentLogEnabled = true
		cfgMu.Unlock()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("HTTP 模式未在数秒内通过 AgentHTTPRPCReply.Config 热开启 DEBUG 日志")
	})

	// --- Part C: Auto 模式（降级 HTTP 期间热开 DEBUG → 升回 WS 期间热关 DEBUG） ---
	t.Run("auto mode config hot reload across HTTP and WS", func(t *testing.T) {
		dir := t.TempDir()
		logSet, err := logging.Setup(filepath.Join(dir, "satchel-agent.log"), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer logSet.Close()

		var (
			wsOpen   atomic.Bool
			sessions = securechan.NewSessionCache(securechan.SessionCacheConfig{TTL: time.Hour})
			wsAuthed = make(chan struct{}, 2)
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/remote/ws":
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
				if _, err := conn.Read(r.Context()); err != nil {
					return
				}
				// 升回 WS 时主控下发 AgentLogEnabled=false。
				_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{
					OK:                true,
					HeartbeatInterval: 10,
					Config: &xrpc.AgentConfig{
						HeartbeatInterval:      10,
						SpeedCollectInterval:   1,
						TrafficCollectInterval: 60,
						AgentLogEnabled:        false,
					},
				})
				select {
				case wsAuthed <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			case xrpc.HTTPMasterPathHandshake:
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
				sid := r.Header.Get(securechan.HeaderSession)
				sess, _, _, ok := sessions.Get(sid)
				if !ok {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if _, err := sess.Decrypt(body); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				// HTTP 降级期下发 AgentLogEnabled=true。
				cfg := xrpc.AgentConfig{HeartbeatInterval: 1, SpeedCollectInterval: 1, TrafficCollectInterval: 60, AgentLogEnabled: true}
				repBytes, _ := json.Marshal(xrpc.AgentHTTPRPCReply{OK: true, HeartbeatInterval: 1, Config: &cfg})
				enc, _ := sess.Encrypt(repBytes)
				_, _ = w.Write(enc)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		speedCol := telemetry.NewSpeedCollector(readProc, time.Now)
		speedCol.Sample()
		c := New(Config{
			MasterURL:             srv.URL,
			Token:                 "tok-auto",
			AgentToken:            "agt-auto",
			PullToken:             "pul-auto",
			MasterKey:             pub,
			Mode:                  config.ModeAuto,
			ListenHost:            "127.0.0.1",
			ListenPort:            freeTCPPort(t),
			PullPort:              freeTCPPort(t),
			WSProbeInterval:       60 * time.Millisecond,
			HTTPHeartbeatInterval: 100 * time.Millisecond,
			SpeedCollector:        speedCol,
			SpeedCollectInterval:  1 * time.Second,
			Backoff:               fastBackoff(),
			Logger:                logSet.Logger,
			OnAgentConfig: func(ac xrpc.AgentConfig) {
				logSet.SetDebugEnabled(ac.AgentLogEnabled)
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		defer func() { cancel(); <-done }()

		// 1. auto 初始 WS 不通降级 HTTP，应收到 HTTP 回复中的 AgentLogEnabled=true。
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && !logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			time.Sleep(30 * time.Millisecond)
		}
		if !logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			t.Fatal("auto 降级 HTTP 后应热开启 DEBUG 日志")
		}

		// 2. 放开 WS 后自动升回 WS，AuthResult.Config 将 AgentLogEnabled 切回 false。
		wsOpen.Store(true)
		select {
		case <-wsAuthed:
		case <-time.After(3 * time.Second):
			t.Fatal("auto 应当升回 WS")
		}
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			time.Sleep(20 * time.Millisecond)
		}
		if logSet.Logger.Enabled(context.Background(), slog.LevelDebug) {
			t.Fatal("auto 升回 WS 后应按 AuthResult.Config 切回 INFO 级别")
		}
	})
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

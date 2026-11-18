package channel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/updater"
)

func TestRuntimeFieldsReportedOverWSHTTPAndInfoHealth(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, ".dockerenv"), nil, 0o600)
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc", "machine-id"), []byte("mid-node-777\n"), 0o644)

	var ec updater.ExecCounter
	ec.Begin()

	lp, pp := freeTCPPort(t), freeTCPPort(t)
	var wsAuthGot xrpc.Auth
	var wsHBGot xrpc.Heartbeat
	gotAuth := make(chan struct{})
	gotHB := make(chan struct{})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/remote/ws" {
			http.NotFound(w, r)
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
		m, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var a xrpc.Auth
		_ = xrpc.Decode(m, &a)
		wsAuthGot = a
		close(gotAuth)
		_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 1})
		hbMsg, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var hb xrpc.Heartbeat
		_ = xrpc.Decode(hbMsg, &hb)
		wsHBGot = hb
		close(gotHB)
		_ = conn.Write(r.Context(), xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now().UTC()})
		<-r.Context().Done()
	}))
	defer srv.Close()

	// Note: 伪造 TLS 客户端给 HTTP/probe 用；WS Dial 下面直接测 pull/manage 端口即可，WS 用明文/TLS 默认 Dial，
	// 这里改为 http:// httptest.Server 给 WS 测试连。
	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		conn := xrpc.NewConn(ws)
		if err := xrpc.ServerHandshake(r.Context(), conn, priv); err != nil {
			return
		}
		m, _ := conn.Read(r.Context())
		_ = xrpc.Decode(m, &wsAuthGot)
		select {
		case <-gotAuth:
		default:
			close(gotAuth)
		}
		_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 1})
		hbMsg, err := conn.Read(r.Context())
		if err == nil {
			_ = xrpc.Decode(hbMsg, &wsHBGot)
			select {
			case <-gotHB:
			default:
				close(gotHB)
			}
			_ = conn.Write(r.Context(), xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now().UTC()})
		}
		<-r.Context().Done()
	}))
	defer wsSrv.Close()

	c := New(Config{
		MasterURL:    wsSrv.URL,
		Token:        "tok-up",
		AgentToken:   "agt-1",
		PullToken:    "pul-1",
		MasterKey:    pub,
		Mode:         config.ModeAuto,
		ListenHost:   "127.0.0.1",
		ListenPort:   lp,
		PullPort:     pp,
		StealthDelay: 5 * time.Second,
		AgentVersion: "0.2.0",
		Root:         root,
		Execs:        &ec,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	<-gotAuth
	<-gotHB
	if !wsAuthGot.InDocker || wsAuthGot.MachineID != "mid-node-777" || wsAuthGot.MasterURL != wsSrv.URL {
		t.Fatalf("WS Auth 运行态字段不对：%+v", wsAuthGot)
	}
	if !wsHBGot.InDocker || wsHBGot.MachineID != "mid-node-777" || wsHBGot.AgentVersion != "0.2.0" {
		t.Fatalf("WS Heartbeat 运行态字段不对：%+v", wsHBGot)
	}

	mAddr, pAddr := waitListenersReady(t, c)
	sid, sess, err := handshakeNode(t, priv, "http://"+mAddr, "agt-1")
	if err != nil {
		t.Fatal(err)
	}
	code, rep, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-1", sid, sess, xrpc.MethodAgentInfo, nil)
	if err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("agent.info 失败：code=%d err=%v rep=%+v", code, err, rep)
	}
	var info xrpc.AgentInfo
	_ = json.Unmarshal(rep.Result, &info)
	if !info.InDocker || info.MachineID != "mid-node-777" || info.MasterURL != wsSrv.URL || !info.ExecRunning {
		t.Fatalf("agent.info 字段不对：%+v", info)
	}

	resp, err := signedNodeReq(t, priv, "http://"+pAddr, xrpc.HTTPNodePathHealth, "pul-1", "", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("pull /health 失败：%v", err)
	}
	var h xrpc.AgentHealth
	_ = json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	if !h.InDocker || h.MachineID != "mid-node-777" || h.AgentVersion != "0.2.0" {
		t.Fatalf("/health 字段不对：%+v", h)
	}
}

func TestSwitchPortsInProcessWithoutStoppingKernel(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	lp1, pp1 := freeTCPPort(t), freeTCPPort(t)
	initCfg := config.Config{
		MasterURL:       "https://panel.example.com",
		Token:           "t1",
		AgentToken:      "agt-1",
		PullToken:       "pul-1",
		MasterPublicKey: securechan.EncodePublicKey(pub),
		ConnectionMode:  config.ModePull,
		ListenPort:      lp1,
		PullPort:        pp1,
	}
	if err := config.Save(cfgPath, initCfg); err != nil {
		t.Fatal(err)
	}

	var kernelRestarts atomic.Int64
	c := New(Config{
		MasterURL:    initCfg.MasterURL,
		Token:        initCfg.Token,
		AgentToken:   initCfg.AgentToken,
		PullToken:    initCfg.PullToken,
		MasterKey:    pub,
		Mode:         config.ModePull,
		ListenHost:   "127.0.0.1",
		ListenPort:   lp1,
		PullPort:     pp1,
		ConfigPath:   cfgPath,
		AgentVersion: "0.2.0",
		Methods: xrpc.Methods{
			xrpc.MethodTrafficSnapshot: func(context.Context, json.RawMessage) (any, error) {
				return xrpc.TrafficSnapshot{BootID: "b1", Generation: 1, KernelRunning: true}, nil
			},
			xrpc.MethodKernelRestart: func(context.Context, json.RawMessage) (any, error) {
				kernelRestarts.Add(1)
				return xrpc.KernelRestarted{}, nil
			},
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	mAddr, _ := waitListenersReady(t, c)
	sid, sess, err := handshakeNode(t, priv, "http://"+mAddr, "agt-1")
	if err != nil {
		t.Fatal(err)
	}

	// 1. 占用目标端口导致切换失败 -> 返回 Failed，配置未改且旧端口继续正常服务。
	occupiedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	occupiedPort := occupiedLn.Addr().(*net.TCPAddr).Port
	defer occupiedLn.Close()

	_, repFail, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-1", sid, sess, xrpc.MethodAgentSwitchPorts, xrpc.SwitchPortsParams{ListenPort: occupiedPort})
	if err != nil || repFail.Error == nil {
		t.Fatalf("目标端口被占时应当失败返回错误：%v %+v", err, repFail)
	}
	if _, repCheck, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-1", sid, sess, xrpc.MethodAgentInfo, nil); err != nil || repCheck.Error != nil {
		t.Fatalf("切换失败后旧管理口必须保持完好：%v %+v", err, repCheck)
	}

	// 2. 切换至新双端口 -> config.yaml 为 0600，新管理口与新 pull 口立即可接入，pull 口仍拒绝管理 RPC，内核未重启。
	lp2, pp2 := freeTCPPort(t), freeTCPPort(t)
	code, repOK, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-1", sid, sess, xrpc.MethodAgentSwitchPorts, xrpc.SwitchPortsParams{
		ListenPort: lp2,
		PullPort:   pp2,
	})
	if err != nil || code != 200 || repOK.Error != nil {
		t.Fatalf("switch_ports 应当成功：code=%d err=%v rep=%+v", code, err, repOK)
	}
	var ack xrpc.SwitchPortsAck
	_ = json.Unmarshal(repOK.Result, &ack)
	if ack.ListenPort != lp2 || ack.PullPort != pp2 {
		t.Fatalf("SwitchPortsAck 不对：%+v", ack)
	}

	fi, _ := os.Stat(cfgPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.yaml 权限必须保持 0600，实际 %v", fi.Mode().Perm())
	}
	saved, err := config.Load(cfgPath)
	if err != nil || saved.ListenPort != lp2 || saved.PullPort != pp2 {
		t.Fatalf("config.yaml 未持久化新端口：%v %+v", err, saved)
	}

	newManageURL := "http://" + net.JoinHostPort("127.0.0.1", strings.Split(c.gate.manage.Addr(), ":")[1])
	newPullURL := "http://" + net.JoinHostPort("127.0.0.1", strings.Split(c.gate.pull.Addr(), ":")[1])
	sid2, sess2, err := handshakeNode(t, priv, newManageURL, "agt-1")
	if err != nil {
		t.Fatalf("新管理口握手失败：%v", err)
	}
	if _, rInfo, err := callNodeRPC(t, priv, newManageURL, "agt-1", sid2, sess2, xrpc.MethodAgentInfo, nil); err != nil || rInfo.Error != nil {
		t.Fatalf("新管理口调用 agent.info 失败：%v %+v", err, rInfo)
	}

	sidPull, sessPull, err := handshakeNode(t, priv, newPullURL, "pul-1")
	if err != nil {
		t.Fatalf("新 pull 口握手失败：%v", err)
	}
	if _, rSnap, err := callNodeRPC(t, priv, newPullURL, "pul-1", sidPull, sessPull, xrpc.MethodTrafficSnapshot, nil); err != nil || rSnap.Error != nil {
		t.Fatalf("新 pull 口拉流量失败：%v %+v", err, rSnap)
	}
	if _, rForbid, err := callNodeRPC(t, priv, newPullURL, "pul-1", sidPull, sessPull, xrpc.MethodAgentSwitchPorts, xrpc.SwitchPortsParams{ListenPort: 12345}); err != nil || rForbid.Error == nil || rForbid.Error.Code != xrpc.CodeUnknownMethod {
		t.Fatalf("pull 口绝不能暴露管理控制方法：%v %+v", err, rForbid)
	}
	if kernelRestarts.Load() != 0 {
		t.Fatalf("切换端口期间内核不应重启：%d", kernelRestarts.Load())
	}
}

func TestProbeAndUpdateMasterURLHotSwitch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	serveMaster := func(signKey ed25519.PrivateKey) (*httptest.Server, chan xrpc.Auth) {
		authed := make(chan xrpc.Auth, 2)
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case xrpc.HTTPMasterPathHandshake:
				var req xrpc.HTTPHandshakeReq
				_ = json.NewDecoder(r.Body).Decode(&req)
				ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
				ephPub := ephPriv.PublicKey().Bytes()
				_ = json.NewEncoder(w).Encode(xrpc.HTTPHandshakeResp{
					SessionID:       "sid-probe",
					MasterEphemeral: ephPub,
					Signature:       securechan.SignHandshake(signKey, req.AgentEphemeral, ephPub),
				})
			case "/api/remote/ws":
				ws, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer ws.CloseNow()
				conn := xrpc.NewConn(ws)
				if err := xrpc.ServerHandshake(r.Context(), conn, signKey); err != nil {
					return
				}
				m, err := conn.Read(r.Context())
				if err != nil {
					return
				}
				var a xrpc.Auth
				_ = xrpc.Decode(m, &a)
				select {
				case authed <- a:
				default:
				}
				_ = conn.Write(r.Context(), xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 60})
				<-r.Context().Done()
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(s.Close)
		return s, authed
	}

	goodMaster, _ := serveMaster(priv)
	badKeyMaster, _ := serveMaster(wrongPriv)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	initCfg := config.Config{
		MasterURL:       goodMaster.URL,
		Token:           "tok-m",
		AgentToken:      "agt-m",
		MasterPublicKey: securechan.EncodePublicKey(pub),
		ConnectionMode:  config.ModeHTTP,
		ListenPort:      freeTCPPort(t),
	}
	_ = config.Save(cfgPath, initCfg)

	var gotMasterURLs []string
	var mu sync.Mutex
	targetMaster, _ := serveMaster(priv)

	c := New(Config{
		MasterURL:             initCfg.MasterURL,
		Token:                 initCfg.Token,
		AgentToken:            initCfg.AgentToken,
		MasterKey:             pub,
		Mode:                  config.ModeHTTP,
		ListenHost:            "127.0.0.1",
		ListenPort:            initCfg.ListenPort,
		ConfigPath:            cfgPath,
		AgentVersion:          "0.2.0",
		HTTPClient:            goodMaster.Client(),
		HTTPHeartbeatInterval: time.Hour,
		Backoff: Backoff{
			Base: 5 * time.Millisecond, Max: 20 * time.Millisecond,
			AuthStep: 5 * time.Millisecond, AuthMax: 20 * time.Millisecond,
			Penalty: 50 * time.Millisecond, PenaltyAfter: 5,
		},
	})
	// 捕获 TLS 探测客户端证书信任。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	mAddr, _ := waitListenersReady(t, c)
	sid, sess, err := handshakeNode(t, priv, "http://"+mAddr, "agt-m")
	if err != nil {
		t.Fatal(err)
	}

	// 1. probe 正确公钥主控 -> reachable=true，config 未变。
	// goodMaster 使用 httptest.NewTLSServer 的 Client（带自签 CA）作为 HTTPClient；这里测试 badKeyMaster 的 TLS CA 注入。
	code, rep, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-m", sid, sess, xrpc.MethodAgentProbeMaster, xrpc.ProbeMasterParams{URL: goodMaster.URL, TimeoutMS: 3000})
	if err != nil || code != 200 || rep.Error != nil {
		t.Fatalf("probe 失败：code=%d err=%v rep=%+v", code, err, rep)
	}
	var pr xrpc.ProbeMasterResult
	_ = json.Unmarshal(rep.Result, &pr)
	if !pr.Reachable {
		t.Fatalf("合法公钥主控应当可达：%+v", pr)
	}

	// 2. 错误公钥验签失败 -> reachable=false。
	c.cfg.HTTPClient = badKeyMaster.Client()
	_, repBad, _ := callNodeRPC(t, priv, "http://"+mAddr, "agt-m", sid, sess, xrpc.MethodAgentProbeMaster, xrpc.ProbeMasterParams{URL: badKeyMaster.URL, TimeoutMS: 3000})
	var prBad xrpc.ProbeMasterResult
	_ = json.Unmarshal(repBad.Result, &prBad)
	if prBad.Reachable || !strings.Contains(prBad.Error, "签名") {
		t.Fatalf("错误公钥主控应当握手失败：%+v", prBad)
	}

	// 3. 热切换 master_url 并原子落盘 0600，通道不退出。
	c.cfg.HTTPClient = targetMaster.Client()
	targetMaster.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMasterURLs = append(gotMasterURLs, r.URL.Path)
		mu.Unlock()
		var req xrpc.HTTPHandshakeReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		ephPub := ephPriv.PublicKey().Bytes()
		_ = json.NewEncoder(w).Encode(xrpc.HTTPHandshakeResp{
			SessionID:       "new-hs",
			MasterEphemeral: ephPub,
			Signature:       securechan.SignHandshake(priv, req.AgentEphemeral, ephPub),
		})
	})

	_, repUM, err := callNodeRPC(t, priv, "http://"+mAddr, "agt-m", sid, sess, xrpc.MethodAgentUpdateMaster, xrpc.UpdateMasterParams{MasterURL: targetMaster.URL})
	if err != nil || repUM.Error != nil {
		t.Fatalf("update_master_url 失败：%v %+v", err, repUM)
	}
	if c.getMasterURL() != targetMaster.URL {
		t.Fatalf("内存 masterURL 未切换：%q", c.getMasterURL())
	}
	saved, _ := config.Load(cfgPath)
	if saved.MasterURL != targetMaster.URL {
		t.Fatalf("config.yaml master_url 未更新：%q", saved.MasterURL)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		hits := len(gotMasterURLs)
		mu.Unlock()
		if hits > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("热切后 HTTP 通道应立即唤醒重连新主控")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestAgentUpdateAndUninstallRPCAndExecMutex(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var ec updater.ExecCounter
	ec.Begin()

	var execTarget string
	var stopped atomic.Bool
	c := New(Config{
		MasterURL:    "https://panel.example.com",
		Token:        "t1",
		MasterKey:    pub,
		Mode:         config.ModeWebsocket,
		AgentVersion: "0.1.0",
		Execs:        &ec,
		RequestExec:  func(p string) { execTarget = p },
		RequestStop:  func() { stopped.Store(true) },
		UpdateApply: func(_ context.Context, opts updater.Options) (*updater.Result, error) {
			return &updater.Result{
				PreviousVersion: "0.1.0",
				TargetVersion:   opts.TargetVersion,
				Source:          "cdn",
				Executable:      "/usr/local/bin/satchel-agent",
			}, nil
		},
		UninstallSpawn: func(context.Context, updater.DetachOptions) (string, error) {
			return "systemd-run", nil
		},
	})

	// 1. exec 运行中拒绝 agent.update 与 agent.uninstall。
	updParams, _ := json.Marshal(xrpc.AgentUpdateParams{Version: "0.2.0"})
	if r := c.methods.Serve(context.Background(), xrpc.Call{ID: "1", Method: xrpc.MethodAgentUpdate, Params: updParams}); r.Error == nil || !strings.Contains(r.Error.Message, "exec") {
		t.Fatalf("exec 运行中应拒绝 agent.update：%+v", r.Error)
	}
	if r := c.methods.Serve(context.Background(), xrpc.Call{ID: "2", Method: xrpc.MethodAgentUninstall}); r.Error == nil || !strings.Contains(r.Error.Message, "exec") {
		t.Fatalf("exec 运行中应拒绝 agent.uninstall：%+v", r.Error)
	}
	ec.End()

	// 2. exec 结束后，update 成功并入队 post-reply exec，uninstall 入队 post-reply stop。
	rUpd := c.methods.Serve(context.Background(), xrpc.Call{ID: "3", Method: xrpc.MethodAgentUpdate, Params: updParams})
	if rUpd.Error != nil {
		t.Fatalf("agent.update 应当成功：%+v", rUpd.Error)
	}
	c.flushPendingCleanup()
	if execTarget != "/usr/local/bin/satchel-agent" {
		t.Fatalf("flushPendingCleanup 应当触发 RequestExec，实际 %q", execTarget)
	}

	rUn := c.methods.Serve(context.Background(), xrpc.Call{ID: "4", Method: xrpc.MethodAgentUninstall})
	if rUn.Error != nil {
		t.Fatalf("agent.uninstall 应当成功：%+v", rUn.Error)
	}
	c.flushPendingCleanup()
	if !stopped.Load() {
		t.Fatal("flushPendingCleanup 应当触发 RequestStop")
	}
	_ = io.Discard
}

func waitListenersReady(t *testing.T, c *Client) (manageAddr, pullAddr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		m, p := c.InboundAddrs()
		if m != "" {
			return m, p
		}
		if time.Now().After(deadline) {
			t.Fatal("等待端口开启超时")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

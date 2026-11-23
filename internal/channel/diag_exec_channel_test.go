package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/diag"
	"github.com/satchel/satchel-agent/internal/execctl"
	"github.com/satchel/satchel-agent/internal/updater"
)

// node-channel「轮询只读口拒绝 diag.run 与全部 exec.* 方法」+ 自升级/卸载互斥校验：
func TestPullPortRejectsDiagExecAndUpdateBlockedWhileExecRunning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	execs := &updater.ExecCounter{}
	diagEng := diag.New(diag.Options{
		ConfigDir: dir,
		InDocker:  func() bool { return false },
		RunCmd:    func(context.Context, string, ...string) ([]byte, error) { return []byte("ok"), nil },
	})
	execMgr := execctl.New(execctl.Options{
		AllowExec: true,
		DataDir:   dir,
		Execs:     execs,
	})
	t.Cleanup(func() { execMgr.Shutdown() })

	methods := control.Methods(control.Deps{
		ConfigDir: dir,
		Diag:      diagEng,
		Exec:      execMgr,
	})

	listenPort := freeTCPPort(t)
	pullPort := freeTCPPort(t)
	c := New(Config{
		Mode:         config.ModePull,
		MasterURL:    "http://127.0.0.1:1",
		MasterKey:    pub,
		Token:        "tok-main",
		AgentToken:   "tok-agent",
		PullToken:    "tok-pull",
		ListenHost:   "127.0.0.1",
		ListenPort:   listenPort,
		PullPort:     pullPort,
		AgentVersion: "0.2.0-test",
		AllowExec:    true,
		Execs:        execs,
		Methods:      methods,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	manageBase := fmt.Sprintf("http://127.0.0.1:%d", listenPort)
	pullBase := fmt.Sprintf("http://127.0.0.1:%d", pullPort)

	deadline := time.Now().Add(5 * time.Second)
	var pullSID, manageSID string
	var pullSess, manageSess interface{ Encrypt([]byte) ([]byte, error) }
	_ = pullSess
	_ = manageSess
	for {
		var serr error
		if pullSID == "" {
			pullSID, _, serr = handshakeNode(t, priv, pullBase, "tok-pull")
		}
		if serr == nil && manageSID == "" {
			manageSID, _, serr = handshakeNode(t, priv, manageBase, "tok-agent")
		}
		if serr == nil && pullSID != "" && manageSID != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待节点端口就绪超时：%v", serr)
		}
		time.Sleep(40 * time.Millisecond)
	}

	pullSID, pSess, err := handshakeNode(t, priv, pullBase, "tok-pull")
	if err != nil {
		t.Fatal(err)
	}
	manageSID, mSess, err := handshakeNode(t, priv, manageBase, "tok-agent")
	if err != nil {
		t.Fatal(err)
	}

	// 1. agent.info 报告 ExecEnabled=true, ExecRunning=false
	st, rep, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodAgentInfo, nil)
	if err != nil || st != http.StatusOK || rep.Error != nil {
		t.Fatalf("agent.info 失败：st=%d err=%v rerr=%+v", st, err, rep.Error)
	}
	var info xrpc.AgentInfo
	if err := json.Unmarshal(rep.Result, &info); err != nil {
		t.Fatal(err)
	}
	if !info.ExecEnabled || info.ExecRunning {
		t.Fatalf("agent.info 期望 exec_enabled=true exec_running=false，得到 %+v", info)
	}

	// 2. pull_port 严格拒绝 diag.run / exec.start / exec.status / exec.cancel
	pullChecks := []struct {
		method string
		params any
	}{
		{xrpc.MethodDiagRun, xrpc.DiagRunParams{Items: []string{xrpc.DiagItemClock}}},
		{xrpc.MethodExecStart, xrpc.ExecStartParams{JobID: "pull-j1", Command: "echo hi", TimeoutMS: 5000}},
		{xrpc.MethodExecStatus, xrpc.ExecStatusParams{JobID: "pull-j1"}},
		{xrpc.MethodExecCancel, xrpc.ExecCancelParams{JobID: "pull-j1"}},
	}
	for _, tc := range pullChecks {
		ps, pr, err := callNodeRPC(t, priv, pullBase, "tok-pull", pullSID, pSess, tc.method, tc.params)
		if err != nil || ps != http.StatusOK || pr.Error == nil || pr.Error.Code != xrpc.CodeUnknownMethod {
			t.Errorf("pull_port 应对 %s 返回 unknown_method，得到 st=%d err=%v rerr=%+v", tc.method, ps, err, pr.Error)
		}
	}

	// 3. listen_port 正常受理 diag.run
	ms, mr, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodDiagRun, xrpc.DiagRunParams{Items: []string{xrpc.DiagItemClock, xrpc.DiagItemSpeedtest}})
	if err != nil || ms != http.StatusOK || mr.Error != nil {
		t.Fatalf("listen_port diag.run 失败：st=%d err=%v rerr=%+v", ms, err, mr.Error)
	}

	// 4. 启动长命令，验证 exec 运行期间 agent.update 与 agent.uninstall 均被拒绝
	ms, mr, err = callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodExecStart, xrpc.ExecStartParams{
		JobID:     "chan-long-1",
		Command:   "sleep 10",
		TimeoutMS: 20000,
	})
	if err != nil || ms != http.StatusOK || mr.Error != nil {
		t.Fatalf("listen_port exec.start 失败：st=%d err=%v rerr=%+v", ms, err, mr.Error)
	}

	// agent.info 应显示 ExecRunning=true
	_, rep, _ = callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodAgentInfo, nil)
	_ = json.Unmarshal(rep.Result, &info)
	if !info.ExecRunning {
		t.Fatalf("exec 运行期间 agent.info.exec_running 应为 true")
	}

	// agent.update 应被拒绝
	_, urep, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodAgentUpdate, xrpc.AgentUpdateParams{})
	if err != nil || urep.Error == nil || !strings.Contains(urep.Error.Message, updater.ErrExecInFlight.Error()) {
		t.Fatalf("exec 运行期间 agent.update 应报 ErrExecInFlight，得到 err=%v rerr=%+v", err, urep.Error)
	}

	// agent.uninstall 应被拒绝
	_, unrep, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodAgentUninstall, xrpc.AgentUninstallParams{})
	if err != nil || unrep.Error == nil || !strings.Contains(unrep.Error.Message, updater.ErrExecInFlight.Error()) {
		t.Fatalf("exec 运行期间 agent.uninstall 应报 ErrExecInFlight，得到 err=%v rerr=%+v", err, unrep.Error)
	}

	// 取消该任务后，验证 exec.status 收敛且 ExecRunning 归零
	ms, mr, err = callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodExecCancel, xrpc.ExecCancelParams{JobID: "chan-long-1"})
	if err != nil || ms != http.StatusOK || mr.Error != nil {
		t.Fatalf("listen_port exec.cancel 失败：st=%d err=%v rerr=%+v", ms, err, mr.Error)
	}
	waitUntil := time.Now().Add(5 * time.Second)
	for {
		_, srep, _ := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, mSess, xrpc.MethodExecStatus, xrpc.ExecStatusParams{JobID: "chan-long-1"})
		var stRes xrpc.ExecStatusResult
		_ = json.Unmarshal(srep.Result, &stRes)
		if stRes.Done && !execs.Running() {
			if stRes.State != xrpc.ExecStateCanceled {
				t.Fatalf("取消后状态应为 canceled，得到 %q", stRes.State)
			}
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatalf("等待取消终态超时：done=%v running=%v", stRes.Done, execs.Running())
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func TestWSReportsExecEnabledAndStreamsExecEvents(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	execs := &updater.ExecCounter{}
	execMgr := execctl.New(execctl.Options{
		AllowExec: true,
		DataDir:   dir,
		Execs:     execs,
	})
	t.Cleanup(func() { execMgr.Shutdown() })

	var (
		mu         sync.Mutex
		gotAuth    xrpc.Auth
		gotHB      bool
		gotHBExec  bool
		gotEvents  []xrpc.ExecEvent
		doneEvents = make(chan struct{})
		doneOnce   sync.Once
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		ctx := r.Context()
		if err := xrpc.ServerHandshake(ctx, conn, priv); err != nil {
			return
		}
		m, err := conn.Read(ctx)
		if err != nil || m.Type != xrpc.TypeAuth {
			return
		}
		var a xrpc.Auth
		_ = xrpc.Decode(m, &a)
		mu.Lock()
		gotAuth = a
		mu.Unlock()
		_ = conn.Write(ctx, xrpc.TypeAuthResult, xrpc.AuthResult{OK: true, HeartbeatInterval: 1})

		// 发起一次 exec.start RPC，验证节点通过 WS 单向推回 exec_event
		rawStart, _ := json.Marshal(xrpc.ExecStartParams{
			JobID:     "ws-exec-1",
			Command:   "echo line1; echo line2",
			TimeoutMS: 5000,
		})
		_ = conn.Write(ctx, xrpc.TypeCall, xrpc.Call{ID: "call-1", Method: xrpc.MethodExecStart, Params: rawStart})

		for {
			msg, err := conn.Read(ctx)
			if err != nil {
				return
			}
			switch msg.Type {
			case xrpc.TypeHeartbeat:
				var hb xrpc.Heartbeat
				_ = xrpc.Decode(msg, &hb)
				mu.Lock()
				gotHB = true
				gotHBExec = hb.ExecEnabled
				mu.Unlock()
				_ = conn.Write(ctx, xrpc.TypeHeartbeatAck, xrpc.HeartbeatAck{ServerTime: time.Now().UTC()})
			case xrpc.TypeExecEvent:
				var ev xrpc.ExecEvent
				_ = xrpc.Decode(msg, &ev)
				mu.Lock()
				gotEvents = append(gotEvents, ev)
				mu.Unlock()
				if ev.Done {
					doneOnce.Do(func() { close(doneEvents) })
				}
			}
		}
	}))
	defer srv.Close()

	c := New(Config{
		Mode:         config.ModeWebsocket,
		MasterURL:    srv.URL,
		MasterKey:    pub,
		Token:        "tok-ws",
		AgentVersion: "0.2.0-test",
		AllowExec:    true,
		Execs:        execs,
		Methods:      control.Methods(control.Deps{ConfigDir: dir, Exec: execMgr}),
	})
	execMgr.SetOnEvent(func(ev xrpc.ExecEvent) {
		c.SendExecEvent(ev)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-doneEvents:
	case <-time.After(5 * time.Second):
		t.Fatal("等待 WS exec_event 终态帧超时")
	}

	mu.Lock()
	defer mu.Unlock()
	if !gotAuth.ExecEnabled {
		t.Errorf("WS Auth 应携带 ExecEnabled=true")
	}
	if !gotHB || !gotHBExec {
		t.Errorf("WS Heartbeat 应携带 ExecEnabled=true，gotHB=%v gotHBExec=%v", gotHB, gotHBExec)
	}
	var combined strings.Builder
	var sawDone bool
	for _, ev := range gotEvents {
		combined.WriteString(ev.Chunk)
		if ev.Done {
			sawDone = true
			if ev.State != xrpc.ExecStateDone || ev.ExitCode != 0 {
				t.Errorf("终态帧不对：%+v", ev)
			}
		}
	}
	if !sawDone || !strings.Contains(combined.String(), "line1") || !strings.Contains(combined.String(), "line2") {
		t.Errorf("WS 流式输出不完整：done=%v out=%q", sawDone, combined.String())
	}
}

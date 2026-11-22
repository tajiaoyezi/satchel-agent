package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/nginxctl"
	"github.com/satchel/satchel-agent/internal/tracker"
)

type fakeNginxChanRunner struct{}

func (fakeNginxChanRunner) LookPath(file string) (string, error) {
	if file == "nginx" {
		return "/usr/sbin/nginx", nil
	}
	return "", os.ErrNotExist
}

func (fakeNginxChanRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "nginx" && len(args) > 0 && args[0] == "-v" {
		return "nginx version: nginx/1.26.2\n", nil
	}
	return "", nil
}

// node-channel「轮询只读口拒绝全部 config.* 配置事务与读取方法」：
// pull 模式下向 pull_port 发起 5 个 config.* RPC 一律返回 unknown_method，向 listen_port 发起则全部正常受理。
func TestPullPortRejectsAllConfigMethodsAndManagePortAccepts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfgDir := t.TempDir()
	kpath := filepath.Join(cfgDir, "kernel.json")
	validCfg := `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`
	if err := os.WriteFile(kpath, []byte(validCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := tracker.New()
	k := kernel.New(tr)
	t.Cleanup(func() { _ = k.Stop() })
	nginxRoot := t.TempDir()
	methods := control.Methods(control.Deps{
		Tracker:   tr,
		Kernel:    k,
		Inbounds:  control.NewInbounds([]string{}),
		ConfigDir: cfgDir,
		Nginx: nginxctl.New(nginxctl.Options{
			RootDir:      nginxRoot,
			InDocker:     func() bool { return true },
			Runner:       fakeNginxChanRunner{},
			CheckRunning: func(context.Context, string) bool { return true },
		}),
		InDocker: func() bool { return true },
	})

	listenPort := freeTCPPort(t)
	pullPort := freeTCPPort(t)
	c := New(Config{
		Mode:       config.ModePull,
		MasterURL:  "http://127.0.0.1:1",
		MasterKey:  pub,
		Token:      "tok-main",
		AgentToken: "tok-agent",
		PullToken:  "tok-pull",
		ListenHost: "127.0.0.1",
		ListenPort: listenPort,
		PullPort:   pullPort,
		Methods:    methods,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	manageBase := fmt.Sprintf("http://127.0.0.1:%d", listenPort)
	pullBase := fmt.Sprintf("http://127.0.0.1:%d", pullPort)

	deadline := time.Now().Add(5 * time.Second)
	var pullSID, manageSID string
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
		time.Sleep(50 * time.Millisecond)
	}

	pullSID, pullSess, err := handshakeNode(t, priv, pullBase, "tok-pull")
	if err != nil {
		t.Fatal(err)
	}
	manageSID, manageSess, err := handshakeNode(t, priv, manageBase, "tok-agent")
	if err != nil {
		t.Fatal(err)
	}

	noRestart := false
	calls := []struct {
		method string
		params any
	}{
		{xrpc.MethodConfigStatus, nil},
		{xrpc.MethodConfigTest, xrpc.ConfigTestParams{Config: validCfg}},
		{xrpc.MethodConfigApply, xrpc.ConfigApplyParams{Config: validCfg, ForceInitial: true, Restart: &noRestart}},
		{xrpc.MethodConfigFiles, xrpc.ConfigFilesParams{Scope: "kernel"}},
		{xrpc.MethodConfigRead, xrpc.ConfigReadParams{Path: kpath}},
	}

	for _, tc := range calls {
		status, reply, err := callNodeRPC(t, priv, pullBase, "tok-pull", pullSID, pullSess, tc.method, tc.params)
		if err != nil || status != http.StatusOK || reply.Error == nil || reply.Error.Code != xrpc.CodeUnknownMethod {
			t.Errorf("pull_port 应对 %s 返回 unknown_method，得到 status=%d err=%v replyErr=%+v", tc.method, status, err, reply.Error)
		}
		mStatus, mReply, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, manageSess, tc.method, tc.params)
		if err != nil || mStatus != http.StatusOK || mReply.Error != nil {
			t.Errorf("listen_port 应正常受理 %s，却得到 status=%d err=%v replyErr=%+v", tc.method, mStatus, err, mReply.Error)
		}
	}
	var st xrpc.ConfigStatusResult
	mStatus, mReply, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, manageSess, xrpc.MethodConfigStatus, nil)
	if err != nil || mStatus != http.StatusOK || mReply.Error != nil || json.Unmarshal(mReply.Result, &st) != nil || !st.Exists || st.Hash == "" {
		t.Fatalf("listen_port config.status 返回不对：status=%d err=%v reply=%s rerr=%+v", mStatus, err, mReply.Result, mReply.Error)
	}

	// node-channel「轮询只读口拒绝 outbound.probe」：pull_port 返回 unknown_method，listen_port 正常执行真实内核出站探活。
	if err := k.Start(context.Background(), []byte(validCfg)); err != nil {
		t.Fatalf("启动测试内核失败：%v", err)
	}
	probeTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probeTarget.Close()

	probeParams := xrpc.OutboundProbeParams{Tag: "direct", URL: probeTarget.URL, TimeoutMS: 5000}
	pStatus, pReply, err := callNodeRPC(t, priv, pullBase, "tok-pull", pullSID, pullSess, xrpc.MethodOutboundProbe, probeParams)
	if err != nil || pStatus != http.StatusOK || pReply.Error == nil || pReply.Error.Code != xrpc.CodeUnknownMethod {
		t.Fatalf("pull_port 应对 outbound.probe 返回 unknown_method，得到 status=%d err=%v replyErr=%+v", pStatus, err, pReply.Error)
	}
	mStatus, mReply, err = callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, manageSess, xrpc.MethodOutboundProbe, probeParams)
	var pr xrpc.OutboundProbeResult
	if err != nil || mStatus != http.StatusOK || mReply.Error != nil || json.Unmarshal(mReply.Result, &pr) != nil || !pr.OK || pr.StatusCode != http.StatusNoContent {
		t.Fatalf("listen_port 应正常受理 outbound.probe，得到 status=%d err=%v reply=%s rerr=%+v", mStatus, err, mReply.Result, mReply.Error)
	}

	// node-channel「轮询只读口拒绝全部 8 个 service.* 与 nginx.* 管理方法」：
	// pull_port 一律返回 unknown_method；listen_port 全部正常路由（docker uninstall 返回预期 conflict 而非 unknown_method）。
	nginxCalls := []struct {
		method      string
		params      any
		wantErrCode string
	}{
		{xrpc.MethodServiceStatus, nil, ""},
		{xrpc.MethodServiceControl, xrpc.ServiceControlParams{Service: "nginx", Action: "reload"}, ""},
		{xrpc.MethodNginxInstall, xrpc.NginxInstallParams{}, ""},
		{xrpc.MethodNginxUninstall, xrpc.NginxUninstallParams{}, xrpc.CodeConflict},
		{xrpc.MethodNginxServers, nil, ""},
		{xrpc.MethodNginxClearStream, xrpc.NginxClearStreamParams{Port: 8443}, ""},
		{xrpc.MethodNginxWebsitesScan, nil, ""},
		{xrpc.MethodNginxWebsitesApply, xrpc.NginxWebsitesApplyParams{
			Sites: []xrpc.ManagedWebsiteFile{
				{Domain: "chan.example.com", Conf: xrpc.SatchelManagedHeader + " id=1\nserver { listen 80; server_name chan.example.com; }\n"},
			},
		}, ""},
	}
	for _, tc := range nginxCalls {
		ps, pr, err := callNodeRPC(t, priv, pullBase, "tok-pull", pullSID, pullSess, tc.method, tc.params)
		if err != nil || ps != http.StatusOK || pr.Error == nil || pr.Error.Code != xrpc.CodeUnknownMethod {
			t.Errorf("pull_port 应对 %s 返回 unknown_method，得到 status=%d err=%v replyErr=%+v", tc.method, ps, err, pr.Error)
		}
		ms, mr, err := callNodeRPC(t, priv, manageBase, "tok-agent", manageSID, manageSess, tc.method, tc.params)
		if err != nil || ms != http.StatusOK {
			t.Errorf("listen_port 调用 %s 传输失败：status=%d err=%v", tc.method, ms, err)
			continue
		}
		if tc.wantErrCode == "" && mr.Error != nil {
			t.Errorf("listen_port 应正常受理 %s，却得到 %+v", tc.method, mr.Error)
		} else if tc.wantErrCode != "" && (mr.Error == nil || mr.Error.Code != tc.wantErrCode) {
			t.Errorf("listen_port 调用 %s 期望错误码 %q，得到 %+v", tc.method, tc.wantErrCode, mr.Error)
		}
	}
}

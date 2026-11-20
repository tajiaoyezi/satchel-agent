package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/tracker"
)

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
	methods := control.Methods(control.Deps{
		Tracker:   tr,
		Kernel:    k,
		Inbounds:  control.NewInbounds([]string{}),
		ConfigDir: cfgDir,
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
}

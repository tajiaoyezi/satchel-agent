package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/tracker"
	kt "github.com/satchel/satchel-agent/pkg/kerneltest"
)

func callMethod[T any](t *testing.T, m xrpc.Methods, method string, params any) (T, *xrpc.Error) {
	t.Helper()
	var zero T
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	reply := m.Serve(context.Background(), xrpc.Call{ID: "1", Method: method, Params: raw})
	if reply.Error != nil {
		return zero, reply.Error
	}
	var out T
	if err := json.Unmarshal(reply.Result, &out); err != nil {
		t.Fatalf("unmarshal %s result: %v", method, err)
	}
	return out, nil
}

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

func directInboundCfg(tag string, port int) string {
	return fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"direct","tag":%q,"listen":"127.0.0.1","listen_port":%d,"network":"tcp","override_address":"127.0.0.1","override_port":9}],"outbounds":[{"type":"direct","tag":"direct"}]}`, tag, port)
}

func TestConfigApplyConflictAndAutoRollback(t *testing.T) {
	cfgDir := t.TempDir()
	tr := tracker.New()
	k := kernel.New(tr)
	t.Cleanup(func() { _ = k.Stop() })
	inbounds := control.NewInbounds(nil)
	m := control.Methods(control.Deps{
		Tracker:   tr,
		Kernel:    k,
		Inbounds:  inbounds,
		ConfigDir: cfgDir,
	})

	// 1. 初始无 kernel.json 时 status 返回 exists=false。
	st0, xerr := callMethod[xrpc.ConfigStatusResult](t, m, xrpc.MethodConfigStatus, nil)
	if xerr != nil || st0.Exists || st0.Hash != "" || st0.KernelRunning {
		t.Fatalf("初始 status 不对：%+v err=%v", st0, xerr)
	}

	// 2. 首次下发遇到端口占用失败：必须删除残留 kernel.json、清空 Inbounds、返回 rolled_back=true。
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busyLn.Close()
	busyPort := busyLn.Addr().(*net.TCPAddr).Port

	resInitFail, xerr := callMethod[xrpc.ConfigApplyResult](t, m, xrpc.MethodConfigApply, xrpc.ConfigApplyParams{
		Config:       directInboundCfg("broken-init", busyPort),
		ForceInitial: true,
	})
	if xerr != nil {
		t.Fatalf("首次失败应返回结构化回滚结果而非 RPC 错误：%v", xerr)
	}
	if resInitFail.Applied || !resInitFail.RolledBack || resInitFail.RollbackError != "" {
		t.Fatalf("首次失败回滚标志不对：%+v", resInitFail)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, control.KernelConfig)); !os.IsNotExist(err) {
		t.Fatalf("首次下发失败必须清理残留 kernel.json，stat err=%v", err)
	}
	if inbounds.Get() != nil {
		t.Fatalf("首次失败后 Inbounds 应为 nil，得到 %v", inbounds.Get())
	}

	// 3. 首次合法下发：写入 0600 kernel.json 并启动内核。
	port1 := freeTCPPort(t)
	cfg1 := directInboundCfg("in-v1", port1)
	res1, xerr := callMethod[xrpc.ConfigApplyResult](t, m, xrpc.MethodConfigApply, xrpc.ConfigApplyParams{
		Config:       cfg1,
		ForceInitial: true,
	})
	if xerr != nil || !res1.Applied || !res1.KernelRunning || res1.Generation != 1 {
		t.Fatalf("首次合法下发失败：%+v err=%v", res1, xerr)
	}
	fi, err := os.Stat(filepath.Join(cfgDir, control.KernelConfig))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kernel.json 权限应为 0600，得到 %v err=%v", fi.Mode().Perm(), err)
	}

	// 4. config.test 合法与非法校验都不影响运行中内核。
	testOK, xerr := callMethod[xrpc.ConfigTestResult](t, m, xrpc.MethodConfigTest, xrpc.ConfigTestParams{Config: cfg1})
	if xerr != nil || !testOK.OK || testOK.Hash != res1.AppliedHash {
		t.Fatalf("config.test 合法配置失败：%+v err=%v", testOK, xerr)
	}
	testBad, xerr := callMethod[xrpc.ConfigTestResult](t, m, xrpc.MethodConfigTest, xrpc.ConfigTestParams{Config: `{"unknown_field":1}`})
	if xerr != nil || testBad.OK || testBad.Error == "" {
		t.Fatalf("config.test 非法配置应回 ok=false：%+v err=%v", testBad, xerr)
	}

	// 5. 错误的 expected_current_hash 返回 conflict 且不改磁盘。
	_, xerr = callMethod[xrpc.ConfigApplyResult](t, m, xrpc.MethodConfigApply, xrpc.ConfigApplyParams{
		Config:              directInboundCfg("in-v2", freeTCPPort(t)),
		ExpectedCurrentHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if xerr == nil || xerr.Code != xrpc.CodeConflict {
		t.Fatalf("哈希不匹配应报 conflict，得到 %+v", xerr)
	}

	// 6. 正确 expected_current_hash 但新配置端口被占：自动恢复旧 kernel.json 并拉回旧内核。
	resRB, xerr := callMethod[xrpc.ConfigApplyResult](t, m, xrpc.MethodConfigApply, xrpc.ConfigApplyParams{
		Config:              directInboundCfg("in-busy", busyPort),
		ExpectedCurrentHash: res1.AppliedHash,
	})
	if xerr != nil {
		t.Fatalf("端口冲突重启失败应返回结构化回滚结果：%v", xerr)
	}
	if resRB.Applied || !resRB.RolledBack || resRB.RollbackError != "" || !resRB.KernelRunning || resRB.CurrentHash != res1.AppliedHash {
		t.Fatalf("自动回滚结果不对：%+v", resRB)
	}
	// 验证旧端口仍在监听且磁盘已恢复 cfg1。
	onDisk, err := os.ReadFile(filepath.Join(cfgDir, control.KernelConfig))
	if err != nil || xrpc.CanonicalConfigHash(onDisk) != res1.AppliedHash {
		t.Fatalf("磁盘 kernel.json 未恢复为旧配置：%v", err)
	}
	if conn, dialErr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port1)); dialErr != nil {
		t.Fatalf("回滚后旧内核端口 %d 应重新可连：%v", port1, dialErr)
	} else {
		_ = conn.Close()
	}

	// 7. 正常增量更新（带正确 expected_current_hash）成功生效。
	port2 := freeTCPPort(t)
	cfg2 := directInboundCfg("in-v2", port2)
	res2, xerr := callMethod[xrpc.ConfigApplyResult](t, m, xrpc.MethodConfigApply, xrpc.ConfigApplyParams{
		Config:              cfg2,
		ExpectedCurrentHash: res1.AppliedHash,
	})
	if xerr != nil || !res2.Applied || !res2.KernelRunning || res2.AppliedHash != xrpc.CanonicalConfigHash([]byte(cfg2)) {
		t.Fatalf("增量更新失败：%+v err=%v", res2, xerr)
	}
	st2, xerr := callMethod[xrpc.ConfigStatusResult](t, m, xrpc.MethodConfigStatus, nil)
	if xerr != nil || !st2.Exists || st2.Hash != res2.AppliedHash || len(st2.Inbounds) != 1 || st2.Inbounds[0] != "in-v2" {
		t.Fatalf("更新后 config.status 不对：%+v err=%v", st2, xerr)
	}
}

func TestConfigFilesAndReadAllowlistAndGuards(t *testing.T) {
	cfgDir := t.TempDir()
	nginxRoot := t.TempDir()
	outsideFile := filepath.Join(t.TempDir(), "outside.conf")
	_ = os.WriteFile(outsideFile, []byte("secret-outside"), 0o600)

	// 准备 kernel 目录文件（只有 kernel.json 允许）。
	kpath := filepath.Join(cfgDir, "kernel.json")
	_ = os.WriteFile(kpath, []byte(`{"log":{"level":"warn"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("token: top-secret"), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, "limiter-state.json"), []byte(`{}`), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, ".kernel.json.tmp"), []byte(`{}`), 0o600)

	// 准备 nginx 目录文件与敏感目录/私钥/越界软链。
	_ = os.MkdirAll(filepath.Join(nginxRoot, "conf.d"), 0o755)
	_ = os.MkdirAll(filepath.Join(nginxRoot, "sites-available"), 0o755)
	_ = os.MkdirAll(filepath.Join(nginxRoot, "sites-enabled"), 0o755)
	_ = os.MkdirAll(filepath.Join(nginxRoot, "cert"), 0o755)
	_ = os.MkdirAll(filepath.Join(nginxRoot, "html"), 0o755)

	mainConf := filepath.Join(nginxRoot, "nginx.conf")
	siteConf := filepath.Join(nginxRoot, "conf.d", "site.conf")
	availSite := filepath.Join(nginxRoot, "sites-available", "default")
	enabledOK := filepath.Join(nginxRoot, "sites-enabled", "default")
	enabledEscape := filepath.Join(nginxRoot, "sites-enabled", "escape.conf")
	certKey := filepath.Join(nginxRoot, "cert", "site.key")
	confKey := filepath.Join(nginxRoot, "conf.d", "leak.pem")
	htmlFile := filepath.Join(nginxRoot, "html", "index.html")

	_ = os.WriteFile(mainConf, []byte("worker_processes auto;\n"), 0o644)
	_ = os.WriteFile(siteConf, []byte(strings.Repeat("server {}\n", 100)), 0o644)
	_ = os.WriteFile(availSite, []byte("server { listen 80; }\n"), 0o644)
	_ = os.Symlink(availSite, enabledOK)
	_ = os.Symlink(outsideFile, enabledEscape)
	_ = os.WriteFile(certKey, []byte("PRIVATE KEY"), 0o600)
	_ = os.WriteFile(confKey, []byte("PRIVATE PEM"), 0o600)
	_ = os.WriteFile(htmlFile, []byte("<html></html>"), 0o644)

	m := control.Methods(control.Deps{
		ConfigDir:  cfgDir,
		NginxRoots: []string{nginxRoot},
	})

	// 1. config.files 仅列出白名单文件，绝不包含 config.yaml / limiter-state.json / cert / html / .pem / 越界软链。
	listed, xerr := callMethod[xrpc.ConfigFilesResult](t, m, xrpc.MethodConfigFiles, xrpc.ConfigFilesParams{Scope: "all"})
	if xerr != nil {
		t.Fatalf("config.files 失败：%v", xerr)
	}
	var paths []string
	for _, f := range listed.Files {
		paths = append(paths, f.Path)
	}
	joined := strings.Join(paths, "\n")
	for _, want := range []string{kpath, mainConf, siteConf, availSite} {
		if !strings.Contains(joined, want) {
			t.Errorf("应列出白名单文件 %s，实际：\n%s", want, joined)
		}
	}
	for _, banned := range []string{"config.yaml", "limiter-state.json", ".kernel.json.tmp", "site.key", "leak.pem", "index.html", "escape.conf"} {
		if strings.Contains(joined, banned) {
			t.Errorf("绝不能暴露敏感或越界文件 %s，实际：\n%s", banned, joined)
		}
	}

	// 2. config.read 正常读取与截断。
	rKernel, xerr := callMethod[xrpc.ConfigReadResult](t, m, xrpc.MethodConfigRead, xrpc.ConfigReadParams{Path: kpath})
	if xerr != nil || rKernel.Scope != "kernel" || rKernel.Truncated || !strings.Contains(rKernel.Content, `"warn"`) {
		t.Fatalf("读 kernel.json 失败：%+v err=%v", rKernel, xerr)
	}
	rTrunc, xerr := callMethod[xrpc.ConfigReadResult](t, m, xrpc.MethodConfigRead, xrpc.ConfigReadParams{Path: siteConf, MaxBytes: 32})
	if xerr != nil || !rTrunc.Truncated || len(rTrunc.Content) != 32 {
		t.Fatalf("限长截断失败：%+v err=%v", rTrunc, xerr)
	}

	// 3. 阻断全部敏感与越界路径（一律返回 CodeNotFound）。
	for _, denied := range []string{
		filepath.Join(cfgDir, "config.yaml"),
		filepath.Join(cfgDir, "limiter-state.json"),
		certKey,
		confKey,
		htmlFile,
		enabledEscape,
		outsideFile,
		filepath.Join(cfgDir, "..", "etc", "passwd"),
	} {
		if _, xerr := callMethod[xrpc.ConfigReadResult](t, m, xrpc.MethodConfigRead, xrpc.ConfigReadParams{Path: denied}); xerr == nil || xerr.Code != xrpc.CodeNotFound {
			t.Errorf("敏感或越界路径 %q 应返回 not_found，得到 %+v", denied, xerr)
		}
	}
}

// 验证运行中代理连接（真实 VLESS）在 config.test 期间零中断。
func TestConfigTestDoesNotDisruptLiveProxy(t *testing.T) {
	s := kt.StartServer(t)
	c := kt.StartClient(t, s.Target(), kt.UserA, kt.InVLESS)
	kt.Echo(t, c, 1)
	m := control.Methods(control.Deps{Kernel: s.Kernel, Tracker: s.Tracker(), ConfigDir: t.TempDir()})
	res, xerr := callMethod[xrpc.ConfigTestResult](t, m, xrpc.MethodConfigTest, xrpc.ConfigTestParams{Config: string(s.Config())})
	if xerr != nil || !res.OK {
		t.Fatalf("config.test 失败：%+v err=%v", res, xerr)
	}
	kt.Echo(t, c, 1)
}

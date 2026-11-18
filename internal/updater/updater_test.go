package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/release"
)

func signTestArtifact(t *testing.T, priv ed25519.PrivateKey, data []byte) []byte {
	t.Helper()
	return ed25519.Sign(priv, data)
}

func makeVerifyFunc(pub ed25519.PublicKey) func(bin, sig string) error {
	return func(bin, sig string) error {
		b, err := os.ReadFile(bin)
		if err != nil {
			return err
		}
		s, err := os.ReadFile(sig)
		if err != nil {
			return err
		}
		if len(s) != ed25519.SignatureSize || !ed25519.Verify(pub, b, s) {
			return release.ErrBadSignature
		}
		return nil
	}
}

func TestUpdaterFourHardRulesAndPoisoning(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	goodBin := []byte("#!/bin/sh\necho satchel-agent 0.2.0\n")
	goodSig := signTestArtifact(t, priv, goodBin)
	poisonBin := []byte("#!/bin/sh\necho malicious\n")
	poisonSig := signTestArtifact(t, priv, []byte("other"))

	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "bin", "satchel-agent")
	stagingDir := filepath.Join(tmp, "staging")
	if err := os.MkdirAll(filepath.Dir(exePath), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin := []byte("#!/bin/sh\necho satchel-agent 0.1.0\n")
	if err := os.WriteFile(exePath, oldBin, 0o755); err != nil {
		t.Fatal(err)
	}

	// 非 Docker 测试根，与模拟 Docker 测试根。
	cleanRoot := filepath.Join(tmp, "clean-root")
	_ = os.MkdirAll(cleanRoot, 0o755)
	dockerRoot := filepath.Join(tmp, "docker-root")
	_ = os.MkdirAll(dockerRoot, 0o755)
	_ = os.WriteFile(filepath.Join(dockerRoot, ".dockerenv"), nil, 0o600)

	// 1. Docker 容器内拒绝更新，且不改现网文件。
	_, err := Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		Root:           dockerRoot,
		Executable:     func() (string, error) { return exePath, nil },
	})
	if !errors.Is(err, ErrDockerRestricted) {
		t.Fatalf("Docker 环境应当返回 ErrDockerRestricted，得到 %v", err)
	}

	// 2. exec 运行中拒绝更新。
	var ec ExecCounter
	ec.Begin()
	_, err = Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		Root:           cleanRoot,
		Execs:          &ec,
		Executable:     func() (string, error) { return exePath, nil },
	})
	if !errors.Is(err, ErrExecInFlight) {
		t.Fatalf("exec 运行中应当返回 ErrExecInFlight，得到 %v", err)
	}
	ec.End()

	// 可编程三源服务器。
	type modeSpec struct {
		cdnBin, cdnSig, ghBin, ghSig, pxBin, pxSig []byte
		metaProto                                  int
	}
	spec := modeSpec{
		cdnBin: poisonBin, cdnSig: goodSig, // 默认先测试 CDN 掉包 bin + 原签名，GitHub 完好
		ghBin: goodBin, ghSig: goodSig,
		pxBin: goodBin, pxSig: goodSig,
		metaProto: 1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cdn/satchel-agent/channels/stable/version.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "0.2.0", "tag": "v0.2.0", "control_protocol": spec.metaProto})
	})
	mux.HandleFunc("/cdn/satchel-agent/releases/0.2.0/satchel-agent-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.cdnBin)
	})
	mux.HandleFunc("/cdn/satchel-agent/releases/0.2.0/satchel-agent-linux-amd64.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.cdnSig)
	})
	mux.HandleFunc("/api/repos/tajiaoyezi/satchel-agent/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.2.0", "body": "ok"})
	})
	mux.HandleFunc("/web/tajiaoyezi/satchel-agent/releases/download/v0.2.0/satchel-agent-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.ghBin)
	})
	mux.HandleFunc("/web/tajiaoyezi/satchel-agent/releases/download/v0.2.0/satchel-agent-linux-amd64.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.ghSig)
	})
	mux.HandleFunc("/proxy/web/tajiaoyezi/satchel-agent/releases/download/v0.2.0/satchel-agent-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.pxBin)
	})
	mux.HandleFunc("/proxy/web/tajiaoyezi/satchel-agent/releases/download/v0.2.0/satchel-agent-linux-amd64.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(spec.pxSig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	src := release.Sources{
		CDN:     srv.URL + "/cdn",
		Project: "satchel-agent",
		Repo:    "tajiaoyezi/satchel-agent",
		API:     srv.URL + "/api",
		Web:     srv.URL + "/web",
		Proxy:   srv.URL + "/proxy/",
		Client:  srv.Client(),
	}

	// 3. 暂存目录空间不足 128 MiB（64 MiB）直接拒绝，不下载、不写现网文件。
	_, err = Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		TargetVersion:  "0.2.0",
		UseCDN:         true,
		Sources:        src,
		Root:           cleanRoot,
		GOARCH:         "amd64",
		StagingDir:     stagingDir,
		Executable:     func() (string, error) { return exePath, nil },
		Verify:         makeVerifyFunc(pub),
		FreeSpaceProbe: func(string) (uint64, error) { return 64 << 20, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "128 MiB") {
		t.Fatalf("空间不足 128 MiB 应当明确拒绝，得到 %v", err)
	}

	// 4. 三源各自投毒：CDN 换二进制、GitHub 坏签名、gh-proxy 二进制与签名不配对 -> 全部失败且点名三源，现网与 .bak 零改动。
	spec.cdnBin, spec.cdnSig = poisonBin, goodSig
	spec.ghBin, spec.ghSig = goodBin, []byte("short")
	spec.pxBin, spec.pxSig = goodBin, poisonSig
	_, err = Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		TargetVersion:  "0.2.0",
		UseCDN:         true,
		Sources:        src,
		Root:           cleanRoot,
		GOARCH:         "amd64",
		StagingDir:     stagingDir,
		Executable:     func() (string, error) { return exePath, nil },
		Verify:         makeVerifyFunc(pub),
		FreeSpaceProbe: func(string) (uint64, error) { return 512 << 20, nil },
		RunVersion:     func(context.Context, string) (string, error) { return "0.2.0", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "cdn") || !strings.Contains(err.Error(), "github") || !strings.Contains(err.Error(), "gh-proxy") {
		t.Fatalf("三源各自投毒应当失败并点名全部三源，得到 %v", err)
	}
	if curBytes, _ := os.ReadFile(exePath); string(curBytes) != string(oldBin) {
		t.Fatalf("三源全败后现网二进制绝不能被改写")
	}
	if _, err := os.Stat(release.PreviousPath(exePath)); !os.IsNotExist(err) {
		t.Fatalf("三源全败后不应提前写入 .bak")
	}

	// 5. 试跑 --version 版本不对 -> 拒绝替换，现网与 .bak 零改动。
	spec.ghBin, spec.ghSig = goodBin, goodSig // 恢复 GitHub 完好对；CDN 仍保持掉包 bin + 原 sig 测试跨源回退！
	_, err = Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		TargetVersion:  "0.2.0",
		UseCDN:         true,
		Sources:        src,
		Root:           cleanRoot,
		GOARCH:         "amd64",
		StagingDir:     stagingDir,
		Executable:     func() (string, error) { return exePath, nil },
		Verify:         makeVerifyFunc(pub),
		FreeSpaceProbe: func(string) (uint64, error) { return 512 << 20, nil },
		RunVersion:     func(context.Context, string) (string, error) { return "0.9.9", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("--version 试跑版本不符应当拒绝：%v", err)
	}
	if _, err := os.Stat(release.PreviousPath(exePath)); !os.IsNotExist(err) {
		t.Fatalf("试跑失败前不应动 .bak")
	}

	// 6. bin 与 sig 跨源混配被拦截（CDN 丢弃不混配 GitHub 签名），整组切到 GitHub 验签+试跑成功并写 .bak 与新二进制！
	res, err := Apply(context.Background(), Options{
		CurrentVersion: "0.1.0",
		TargetVersion:  "0.2.0",
		UseCDN:         true,
		Sources:        src,
		Root:           cleanRoot,
		GOARCH:         "amd64",
		StagingDir:     stagingDir,
		Executable:     func() (string, error) { return exePath, nil },
		Verify:         makeVerifyFunc(pub),
		FreeSpaceProbe: func(string) (uint64, error) { return 512 << 20, nil },
		RunVersion:     func(context.Context, string) (string, error) { return "0.2.0", nil },
	})
	if err != nil {
		t.Fatalf("CDN 投毒回落 GitHub 成对下载应当成功：%v", err)
	}
	if res.Source != release.SourceGitHub || res.PreviousVersion != "0.1.0" || res.TargetVersion != "0.2.0" {
		t.Fatalf("升级返回不对：%+v", res)
	}
	if gotNew, _ := os.ReadFile(exePath); string(gotNew) != string(goodBin) {
		t.Fatalf("现网可执行文件未换成新二进制")
	}
	if gotBak, _ := os.ReadFile(release.PreviousPath(exePath)); string(gotBak) != string(oldBin) {
		t.Fatalf(".bak 未保留旧二进制")
	}
}

func TestUninstallWhitelistAndDetachedSpawn(t *testing.T) {
	// 1. 卸载路径白名单严格拦截越界路径与系统根目录。
	for _, bad := range []string{"/", "/etc/passwd", "/etc/satchel-agent/../../etc/shadow", "/tmp/random", "/usr/local/bin/other"} {
		if _, err := ValidateUninstallPath(bad, nil); err == nil {
			t.Fatalf("白名单应当拦截越界路径 %q", bad)
		}
	}
	if _, err := ValidateUninstallPath("/etc/satchel-agent/config.yaml", nil); err != nil {
		t.Fatalf("允许的配置目录子路径应当通过：%v", err)
	}

	// 2. 在隔离临时树执行 RunUninstall：停服务命令记录、文件删除、且 Docker 下拒绝。
	tmp := t.TempDir()
	allowed := []string{
		filepath.Join(tmp, "bin", "satchel-agent"),
		filepath.Join(tmp, "bin", "satchel-agent.bak"),
		filepath.Join(tmp, "etc", "satchel-agent"),
		filepath.Join(tmp, "lib", "satchel-agent"),
		filepath.Join(tmp, "systemd", "satchel-agent.service"),
		filepath.Join(tmp, "initd", "satchel-agent"),
	}
	cleanRoot := filepath.Join(tmp, "clean-root")
	dockerRoot := filepath.Join(tmp, "docker-root")
	_ = os.MkdirAll(cleanRoot, 0o755)
	_ = os.MkdirAll(dockerRoot, 0o755)
	_ = os.WriteFile(filepath.Join(dockerRoot, ".dockerenv"), nil, 0o600)

	binPath := allowed[0]
	bakPath := allowed[1]
	cfgDir := allowed[2]
	stateDir := allowed[3]
	sdUnit := allowed[4]
	rcInit := allowed[5]
	outsideFile := filepath.Join(tmp, "untouched.txt")

	for _, dir := range []string{filepath.Dir(binPath), cfgDir, stateDir, filepath.Dir(sdUnit), filepath.Dir(rcInit)} {
		_ = os.MkdirAll(dir, 0o755)
	}
	_ = os.WriteFile(binPath, []byte("bin"), 0o755)
	_ = os.WriteFile(bakPath, []byte("bak"), 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("k: v"), 0o600)
	_ = os.WriteFile(filepath.Join(stateDir, "limiter-state.json"), []byte("{}"), 0o600)
	_ = os.WriteFile(sdUnit, []byte("[Unit]"), 0o644)
	_ = os.WriteFile(rcInit, []byte("#!/sbin/openrc-run"), 0o755)
	_ = os.WriteFile(outsideFile, []byte("keep"), 0o600)

	if err := RunUninstall(context.Background(), UninstallOptions{Root: dockerRoot}); !errors.Is(err, ErrDockerRestricted) {
		t.Fatalf("Docker 内应当拒绝卸载：%v", err)
	}

	var cmds []string
	err := RunUninstall(context.Background(), UninstallOptions{
		Root:         cleanRoot,
		Delay:        5 * time.Millisecond,
		BinaryPath:   binPath,
		ConfigDir:    cfgDir,
		StateDir:     stateDir,
		SystemdUnit:  sdUnit,
		OpenRCInit:   rcInit,
		AllowedRoots: allowed,
		RunCmd: func(_ context.Context, name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RunUninstall 应当成功：%v", err)
	}
	for _, gone := range allowed {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("卸载后 %q 应当被清理", gone)
		}
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("白名单外的无关文件不该被删：%v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "systemctl disable --now satchel-agent") || !strings.Contains(joined, "rc-service satchel-agent stop") {
		t.Fatalf("应当依次停用 systemd 与 OpenRC 服务：%s", joined)
	}

	// 3. 尝试注入越界 ConfigDir 立即被白名单拒绝，不删任何文件。
	if err := RunUninstall(context.Background(), UninstallOptions{
		Root:         cleanRoot,
		BinaryPath:   binPath,
		ConfigDir:    filepath.Join(tmp, "etc", "passwd"),
		StateDir:     stateDir,
		SystemdUnit:  sdUnit,
		OpenRCInit:   rcInit,
		AllowedRoots: allowed,
	}); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("越界 ConfigDir 应当被白名单拒绝：%v", err)
	}

	// 4. SpawnDetachedUninstall 测试 fallback setsid 派生路径。
	var spawnedArgs []string
	spawner, err := SpawnDetachedUninstall(context.Background(), DetachOptions{
		Root:       cleanRoot,
		Executable: "/usr/local/bin/satchel-agent",
		Delay:      time.Second,
		SystemdRun: func(context.Context, string, string, ...string) error {
			return errors.New("no systemd")
		},
		SpawnSetsid: func(exe string, args ...string) error {
			spawnedArgs = append([]string{exe}, args...)
			return nil
		},
	})
	if err != nil || spawner != "setsid" || len(spawnedArgs) < 4 || spawnedArgs[1] != "uninstall" {
		t.Fatalf("SpawnDetachedUninstall 兜底 setsid 不对：spawner=%q err=%v args=%v", spawner, err, spawnedArgs)
	}
}

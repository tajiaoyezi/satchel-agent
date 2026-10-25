package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/satchel/satchel/pkg/securechan"
)

func TestVersionFlag(t *testing.T) {
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--version"}, out, os.Stderr); code != 0 {
		t.Fatalf("--version 退出码 %d", code)
	}
	data, _ := os.ReadFile(out.Name())
	if !strings.Contains(string(data), "0.0.0-dev") {
		t.Fatalf("输出应当含默认版本，得到 %q", data)
	}
	if code := run([]string{"--bogus"}, out, out); code != 2 {
		t.Fatalf("未知 flag 应当退出码 2，得到 %d", code)
	}
	if code := run(nil, out, out); code != 2 {
		t.Fatalf("没有子命令应当退出码 2，得到 %d", code)
	}
	if code := run([]string{"bogus"}, out, out); code != 2 {
		t.Fatalf("不认识的子命令应当退出码 2，得到 %d", code)
	}
	var help bytes.Buffer
	if code := run([]string{"--help"}, &help, &help); code != 0 || !strings.Contains(help.String(), "satchel-agent join") ||
		!strings.Contains(help.String(), "satchel-agent run") {
		t.Fatalf("--help 应当退出码 0 并列出 join 与 run：%d %s", code, help.String())
	}
}

func joinArgs(path, key string) []string {
	return []string{"--master-url", "https://panel.example.com", "--token", "tok", "--master-key", key, "--mode", "websocket", "--config", path}
}

// node-pairing「写出 0600 的配置」「没有主控公钥不写」「http 主控地址不写」。
func TestJoin(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := securechan.EncodePublicKey(pub)
	dir := filepath.Join(t.TempDir(), "sa")
	path := filepath.Join(dir, "config.yaml")
	var out, errOut bytes.Buffer
	if code := run(append([]string{"join"}, joinArgs(path, key)...), &out, &errOut); code != 0 {
		t.Fatalf("join 应当成功：%d %s", code, errOut.String())
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("配置文件应当是 0600：%v %v", fi, err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("配置目录应当是 0700：%v", di.Mode())
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"master_url: https://panel.example.com", "token: tok", "master_public_key: " + key, "connection_mode: websocket"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("配置里应当有 %q：%s", want, data)
		}
	}

	bad := map[string][]string{
		"缺主控公钥":   {"--master-url", "https://panel.example.com", "--token", "tok", "--mode", "websocket"},
		"公钥不是公钥":  {"--master-url", "https://panel.example.com", "--token", "tok", "--master-key", "not-a-key", "--mode", "websocket"},
		"http 地址": {"--master-url", "http://panel.example.com", "--token", "tok", "--master-key", key, "--mode", "websocket"},
		"别的模式":    {"--master-url", "https://panel.example.com", "--token", "tok", "--master-key", key, "--mode", "auto"},
		"缺 token": {"--master-url", "https://panel.example.com", "--master-key", key, "--mode", "websocket"},
	}
	for name, args := range bad {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			var o, e bytes.Buffer
			if code := run(append([]string{"join"}, append(args, "--config", p)...), &o, &e); code != 1 {
				t.Fatalf("应当以退出码 1 拒绝：%d %s", code, e.String())
			}
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatal("拒绝时不应当写出配置文件")
			}
		})
	}
	if code := run(append([]string{"join"}, joinArgs(path, key)...), &out, &errOut); code != 0 {
		t.Fatal("已存在的配置应当整份覆盖（重新配对）")
	}
}

// node-channel「没有主控公钥不启动」：配置里去掉主控公钥，run 以退出码 1 结束，不连主控。
func TestRunRefusesWithoutMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("master_url: https://127.0.0.1:1\ntoken: tok\nconnection_mode: websocket\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"run", "--config", path}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "主控公钥") {
		t.Fatalf("缺主控公钥应当拒绝启动：%d %s", code, errOut.String())
	}
}

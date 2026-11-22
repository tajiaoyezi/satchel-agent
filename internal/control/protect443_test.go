package control

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
)

func TestProtectMasterHTTPSPort443StartupSelfHeal(t *testing.T) {
	dir := t.TempDir()
	nginxRoot := filepath.Join(dir, "nginx")
	streamDir := filepath.Join(nginxRoot, "stream_servers")
	if err := os.MkdirAll(streamDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kpath := filepath.Join(dir, KernelConfig)

	rawWith443 := `{
  "log": {"level": "warn"},
  "inbounds": [
    {"type": "direct", "tag": "tunnel-in", "listen": "::", "listen_port": 443, "network": "tcp"},
    {"type": "direct", "tag": "keep-18443", "listen": "127.0.0.1", "listen_port": 18443}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "final": "direct",
    "rules": [
      {"action": "sniff"},
      {"inbound": ["tunnel-in"], "domain": ["decoy.example.com"], "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": 8001},
      {"inbound": ["tunnel-in", "keep-18443"], "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": 9999}
    ]
  }
}`
	if err := os.WriteFile(kpath, []byte(rawWith443), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. 无主控 443 标记时绝不改写文件。
	mod, _, _, err := ProtectMasterHTTPSPort443(kpath, []string{nginxRoot})
	if err != nil || mod {
		t.Fatalf("无标记时不应改写：mod=%v err=%v", mod, err)
	}

	// 2. 放置 master_https_443.conf 后触发自愈。
	if err := os.WriteFile(filepath.Join(streamDir, "master_https_443.conf"), []byte("server { listen 443; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mod, backupPath, removedTags, err := ProtectMasterHTTPSPort443(kpath, []string{nginxRoot})
	if err != nil || !mod {
		t.Fatalf("期望触发启动自愈：mod=%v err=%v", mod, err)
	}
	if backupPath != kpath+Protect443BackupSuffix {
		t.Fatalf("备份路径不对：%q", backupPath)
	}
	if len(removedTags) != 1 || removedTags[0] != "tunnel-in" {
		t.Fatalf("removedTags 期望 [tunnel-in]，得到 %v", removedTags)
	}
	// 验证备份存在、权限 0600 且内容完整一致。
	bfi, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("备份文件不存在：%v", err)
	}
	if perm := bfi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("备份文件权限期望 0600，实际 %04o", perm)
	}
	braw, err := os.ReadFile(backupPath)
	if err != nil || string(braw) != rawWith443 {
		t.Fatalf("备份内容与原配置不一致")
	}

	// 验证自愈后的 kernel.json 合法、不含 tunnel-in、保留 keep-18443 与其规则。
	healed, err := os.ReadFile(kpath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(healed), "tunnel-in") || strings.Contains(string(healed), "decoy.example.com") {
		t.Fatalf("自愈后仍残留 443 入站或独占规则：\n%s", healed)
	}
	if !strings.Contains(string(healed), "keep-18443") {
		t.Fatalf("自愈误删了非 443 入站：\n%s", healed)
	}
	tags, err := kernel.Validate(healed)
	if err != nil {
		t.Fatalf("自愈后配置未通过 sing-box 校验：%v\n%s", err, healed)
	}
	if len(tags) != 1 || tags[0] != "keep-18443" {
		t.Fatalf("自愈后入站期望 [keep-18443]，实际 %v", tags)
	}

	// 3. 再次运行自愈应幂等跳过（无 443 入站不改写）。
	mod2, _, _, err := ProtectMasterHTTPSPort443(kpath, []string{nginxRoot})
	if err != nil || mod2 {
		t.Fatalf("无 443 入站时二次自愈应返回 modified=false：mod=%v err=%v", mod2, err)
	}
}

func TestConfigApplyProtectMaster443Guard(t *testing.T) {
	dir := t.TempDir()
	nginxRoot := filepath.Join(dir, "nginx")
	streamDir := filepath.Join(nginxRoot, "stream_servers")
	if err := os.MkdirAll(streamDir, 0o755); err != nil {
		t.Fatal(err)
	}

	d := Deps{
		ConfigDir:  dir,
		NginxRoots: []string{nginxRoot},
		Inbounds:   NewInbounds(nil),
		ConfigMu:   &sync.Mutex{},
	}

	cfg443 := `{"log":{"level":"warn"},"inbounds":[{"type":"direct","tag":"in-443","listen":"127.0.0.1","listen_port":443,"network":"tcp"}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	cfg18443 := `{"log":{"level":"warn"},"inbounds":[{"type":"direct","tag":"in-18443","listen":"127.0.0.1","listen_port":18443,"network":"tcp"}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	noRestart := false

	// 1. ProtectMaster443=true 拒绝 443 配置返回 conflict 且不写盘。
	_, err := d.handleConfigApply(xrpc.ConfigApplyParams{
		Config:           cfg443,
		ProtectMaster443: true,
		Restart:          &noRestart,
	})
	if xe, ok := err.(*xrpc.Error); !ok || xe.Code != xrpc.CodeConflict {
		t.Fatalf("ProtectMaster443=true 应拒绝 443 配置并返回 conflict，得到：%v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, KernelConfig)); !os.IsNotExist(serr) {
		t.Fatalf("被拒后不应落盘 kernel.json")
	}

	// 2. 即使 ProtectMaster443=false，但磁盘含 # satchel-master-443 标记时同样拒绝 443。
	if err := os.WriteFile(filepath.Join(streamDir, "custom.conf"), []byte(xrpc.SatchelMaster443Marker+"\nserver { listen 443; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = d.handleConfigApply(xrpc.ConfigApplyParams{
		Config:  cfg443,
		Restart: &noRestart,
	})
	if xe, ok := err.(*xrpc.Error); !ok || xe.Code != xrpc.CodeConflict {
		t.Fatalf("磁盘含主控 443 标记时应拒绝 443 配置并返回 conflict，得到：%v", err)
	}

	// 3. 非 443 配置照常放行。
	res, err := d.handleConfigApply(xrpc.ConfigApplyParams{
		Config:           cfg18443,
		ProtectMaster443: true,
		Restart:          &noRestart,
	})
	if err != nil || !res.Applied {
		t.Fatalf("非 443 配置应放行成功：res=%+v err=%v", res, err)
	}
}

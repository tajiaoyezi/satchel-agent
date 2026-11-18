package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/satchel/satchel/pkg/securechan"
)

func testKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return securechan.EncodePublicKey(pub)
}

func TestConfigModesPortsAndAtomicSave(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "sa")
	path := filepath.Join(dir, "config.yaml")

	cfg := Config{
		MasterURL:       "https://panel.example.com/",
		Token:           "tok-1",
		AgentToken:      "agt-1",
		PullToken:       "pul-1",
		MasterPublicKey: key,
		ConnectionMode:  ModeAuto,
		ListenPort:      24889,
		PullPort:        24890,
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save auto 应当成功：%v", err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("配置文件权限应当为 0600：%v %v", fi, err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失败：%v", err)
	}
	if loaded.MasterURL != "https://panel.example.com" || loaded.AgentToken != "agt-1" ||
		loaded.PullToken != "pul-1" || loaded.EffectiveListenPort() != 24889 || loaded.EffectivePullPort() != 24890 {
		t.Fatalf("读回配置不对：%+v", loaded)
	}

	// 仅 http 不需要 pull_token；仅 websocket 不需要 agent_token/pull_token，且默认值生效。
	if err := Save(path, Config{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", MasterPublicKey: key, ConnectionMode: ModeHTTP}); err != nil {
		t.Fatalf("http 模式不需 pull_token：%v", err)
	}
	if l, err := Load(path); err != nil || l.EffectiveListenPort() != DefaultListenPort || l.EffectivePullPort() != DefaultPullPort {
		t.Fatalf("默认端口不对：%+v %v", l, err)
	}

	// 反向用例：缺模式必需凭据、端口超界/冲突、控制字符注入、未知 YAML 字段。
	bad := []Config{
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", MasterPublicKey: key, ConnectionMode: ModeAuto},                // 缺 pull_token
		{MasterURL: "https://p.example.com", Token: "t", MasterPublicKey: key, ConnectionMode: ModeHTTP},                                 // 缺 agent_token
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", MasterPublicKey: key, ConnectionMode: ModePull},                // 缺 pull_token
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", PullToken: "p", MasterPublicKey: key, ConnectionMode: "bogus"}, // 非法模式
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", PullToken: "p", MasterPublicKey: key, ConnectionMode: ModeAuto, ListenPort: 23889, PullPort: 23889},
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", PullToken: "p", MasterPublicKey: key, ConnectionMode: ModeAuto, ListenPort: 23890}, // 撞默认 pull_port
		{MasterURL: "https://p.example.com", Token: "t", AgentToken: "a", PullToken: "p", MasterPublicKey: key, ConnectionMode: ModeAuto, PullPort: 70000},
		{MasterURL: "https://p.example.com", Token: "t\nevil: true", AgentToken: "a", PullToken: "p", MasterPublicKey: key, ConnectionMode: ModeAuto},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("第 %d 组非法配置应当被拒：%+v", i, c)
		}
	}

	// Unknown field rejection
	badYAML := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(badYAML, []byte("master_url: https://p.example.com\ntoken: t\nmaster_public_key: "+key+"\nconnection_mode: websocket\nunknown_key: 1\n"), 0o600)
	if _, err := Load(badYAML); err == nil {
		t.Fatal("未知字段应当被 KnownFields(true) 拒绝")
	}
}

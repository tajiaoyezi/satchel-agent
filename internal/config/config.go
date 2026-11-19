// Package config 是节点守护的配置文件（m2-02 node-pairing「satchel-agent join 写配置」）：主控地址、这台服务器的 token、
// 主控公钥与连接模式四项，YAML，权限 0600（mmwx 写成 0644，token 谁都能读，这里不照抄）。
package config

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/satchel/satchel/pkg/securechan"

	"github.com/satchel/satchel-agent/internal/pathguard"
)

// DefaultPath 是配置文件的默认位置。
const DefaultPath = "/etc/satchel-agent/config.yaml"

// DefaultStateLogPath 是默认系统配置路径对应的节点轮转日志路径。
const DefaultStateLogPath = "/var/lib/satchel-agent/logs/satchel-agent.log"

// EffectiveLogPath 返回配置生效的日志文件路径：优先配置里的 log_path，其次按配置位置决定默认路径。
func EffectiveLogPath(configPath, configuredLogPath string) string {
	if p := strings.TrimSpace(configuredLogPath); p != "" {
		return p
	}
	if filepath.Clean(strings.TrimSpace(configPath)) == DefaultPath {
		return DefaultStateLogPath
	}
	dir := filepath.Dir(strings.TrimSpace(configPath))
	if dir == "" || dir == "." {
		return filepath.Join("logs", "satchel-agent.log")
	}
	return filepath.Join(dir, "logs", "satchel-agent.log")
}

// 四种连接模式与节点入站默认端口。
const (
	ModeAuto      = "auto"
	ModeWebsocket = "websocket"
	ModeHTTP      = "http"
	ModePull      = "pull"

	DefaultListenPort = 23889
	DefaultPullPort   = 23890
)

// Modes 是允许的连接模式清单。
var Modes = []string{ModeAuto, ModeWebsocket, ModeHTTP, ModePull}

// ValidMode 报告 mode 是否受支持。
func ValidMode(mode string) bool { return slices.Contains(Modes, mode) }

// Config 是配置文件的内容。
type Config struct {
	MasterURL       string `yaml:"master_url"`
	Token           string `yaml:"token"`
	AgentToken      string `yaml:"agent_token,omitempty"`
	PullToken       string `yaml:"pull_token,omitempty"`
	MasterPublicKey string `yaml:"master_public_key"`
	ConnectionMode  string `yaml:"connection_mode"`
	ListenPort      int    `yaml:"listen_port,omitempty"`
	PullPort        int    `yaml:"pull_port,omitempty"`
	LogPath         string `yaml:"log_path,omitempty"`
}

// EffectiveListenPort 返回生效的管理监听端口（未配置时取默认 23889）。
func (c Config) EffectiveListenPort() int {
	if c.ListenPort > 0 {
		return c.ListenPort
	}
	return DefaultListenPort
}

// EffectivePullPort 返回生效的只读轮询端口（未配置时取默认 23890）。
func (c Config) EffectivePullPort() int {
	if c.PullPort > 0 {
		return c.PullPort
	}
	return DefaultPullPort
}

// Validate 校验配置项：防控制字符注入、主控 https 地址、Ed25519 公钥、连接模式、各模式所需令牌与端口合法性；
// 并去掉主控地址末尾的 /。
func (c *Config) Validate() error {
	for field, val := range map[string]string{
		"master_url":        c.MasterURL,
		"token":             c.Token,
		"agent_token":       c.AgentToken,
		"pull_token":        c.PullToken,
		"master_public_key": c.MasterPublicKey,
		"connection_mode":   c.ConnectionMode,
		"log_path":          c.LogPath,
	} {
		if err := pathguard.RejectControlChars(field, val); err != nil {
			return err
		}
	}
	c.MasterURL = strings.TrimRight(strings.TrimSpace(c.MasterURL), "/")
	switch {
	case c.MasterURL == "":
		return errors.New("缺少主控地址（--master-url）")
	case c.Token == "":
		return errors.New("缺少 token（--token）")
	case c.MasterPublicKey == "":
		return errors.New("缺少主控公钥（--master-key）：没有它就验不了主控的身份，不连")
	case c.ConnectionMode == "":
		return errors.New("缺少连接模式（--mode）")
	}
	u, err := url.Parse(c.MasterURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("主控地址必须是 https 的地址，得到 %q", c.MasterURL)
	}
	if _, err := securechan.ParsePublicKey(c.MasterPublicKey); err != nil {
		return fmt.Errorf("主控公钥不合法：%w", err)
	}
	if !ValidMode(c.ConnectionMode) {
		return fmt.Errorf("连接模式 %q 不支持：必须是 auto、websocket、http 或 pull 之一", c.ConnectionMode)
	}
	if c.ConnectionMode != ModeWebsocket && c.AgentToken == "" {
		return fmt.Errorf("%s 模式缺少 --agent-token（agent_token）", c.ConnectionMode)
	}
	if (c.ConnectionMode == ModeAuto || c.ConnectionMode == ModePull) && c.PullToken == "" {
		return fmt.Errorf("%s 模式缺少 --pull-token（pull_token）", c.ConnectionMode)
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("listen_port 必须在 0..65535 之间，得到 %d", c.ListenPort)
	}
	if c.PullPort < 0 || c.PullPort > 65535 {
		return fmt.Errorf("pull_port 必须在 0..65535 之间，得到 %d", c.PullPort)
	}
	if c.EffectiveListenPort() == c.EffectivePullPort() {
		return fmt.Errorf("管理监听端口（%d）与只读轮询端口（%d）不能相同", c.EffectiveListenPort(), c.EffectivePullPort())
	}
	return nil
}

// MasterKey 是解析好的主控公钥；先 Validate 过才调用。
func (c Config) MasterKey() ed25519.PublicKey {
	pub, _ := securechan.ParsePublicKey(c.MasterPublicKey)
	return pub
}

// Save 校验后写配置文件：所在目录不存在时建成 0700，先写同目录的临时文件、改成 0600 再改名，已存在的整份覆盖。
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("建配置目录 %s 失败：%w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("写配置文件失败：%w", err)
	}
	return nil
}

// Load 读配置文件并校验；不认识的键也算不合法。
func Load(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("读配置文件 %s 失败：%w（先用 satchel-agent join 写配置）", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return c, fmt.Errorf("配置文件 %s 解析失败：%w", path, err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("配置文件 %s 不合法：%w", path, err)
	}
	return c, nil
}

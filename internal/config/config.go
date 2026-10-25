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
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/satchel/satchel/pkg/securechan"
)

// DefaultPath 是配置文件的默认位置。
const DefaultPath = "/etc/satchel-agent/config.yaml"

// ModeWebsocket 是这一版唯一支持的连接模式。
const ModeWebsocket = "websocket"

// Config 是配置文件的内容。
type Config struct {
	MasterURL       string `yaml:"master_url"`
	Token           string `yaml:"token"`
	MasterPublicKey string `yaml:"master_public_key"`
	ConnectionMode  string `yaml:"connection_mode"`
}

// Validate 校验四项：都要有；主控地址是 https；主控公钥能解析成 Ed25519 公钥；连接模式是 websocket。
// 主控地址末尾的 / 去掉。
func (c *Config) Validate() error {
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
	if c.ConnectionMode != ModeWebsocket {
		return fmt.Errorf("连接模式 %q 这一版还不支持：只支持 websocket", c.ConnectionMode)
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

package channel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/pathguard"
	"github.com/satchel/satchel-agent/internal/updater"
)

func readAgentMachineID(root string) string {
	for _, rel := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id
		}
	}
	return ""
}

func (c *Client) getMasterURL() string {
	c.masterMu.RLock()
	defer c.masterMu.RUnlock()
	return c.master
}

func (c *Client) setMasterURL(u string) {
	c.masterMu.Lock()
	c.master = strings.TrimRight(strings.TrimSpace(u), "/")
	c.masterMu.Unlock()
}

func (c *Client) setActiveWSCancel(cancel context.CancelFunc) {
	c.wsMu.Lock()
	c.wsCancel = cancel
	c.wsMu.Unlock()
}

func (c *Client) clearActiveWSCancel(_ context.CancelFunc) {
	c.wsMu.Lock()
	c.wsCancel = nil
	c.wsMu.Unlock()
}

func (c *Client) cancelActiveWS() {
	c.wsMu.Lock()
	cancel := c.wsCancel
	c.wsMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *Client) runtimeInfo() xrpc.AgentInfo {
	return xrpc.AgentInfo{
		AgentVersion:     c.cfg.AgentVersion,
		ControlProtocol:  xrpc.ControlProtocol,
		MinMasterVersion: MinMasterVersion,
		InDocker:         c.inDocker,
		MachineID:        c.machineID,
		MasterURL:        c.getMasterURL(),
		ExecRunning:      c.cfg.Execs != nil && c.cfg.Execs.Running(),
	}
}

func (c *Client) runtimeHealth() xrpc.AgentHealth {
	return xrpc.AgentHealth{
		Status:       "ok",
		Mode:         c.cfg.Mode,
		AgentVersion: c.cfg.AgentVersion,
		InDocker:     c.inDocker,
		MachineID:    c.machineID,
		MasterURL:    c.getMasterURL(),
	}
}

// loadConfigForEditLocked 必须持 c.rotateMu 调用：优先从 ConfigPath 读回现有配置，无文件时按当前运行态构建完整基准配置。
func (c *Client) loadConfigForEditLocked() (config.Config, error) {
	var updated config.Config
	if c.cfg.ConfigPath != "" {
		loaded, err := config.Load(c.cfg.ConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return updated, err
		}
		if err == nil {
			updated = loaded
		}
	}
	if updated.MasterURL == "" {
		updated.MasterURL = c.getMasterURL()
		updated.MasterPublicKey = securechan.EncodePublicKey(c.cfg.MasterKey)
		updated.ConnectionMode = c.cfg.Mode
		updated.ListenPort = c.cfg.ListenPort
		updated.PullPort = c.cfg.PullPort
		c.creds.FillConfig(&updated)
	}
	return updated, nil
}

// persistConfigLocked 必须持 c.rotateMu 调用：先校验再以 0600 原子写回。
func (c *Client) persistConfigLocked(updated config.Config) error {
	if err := updated.Validate(); err != nil {
		return err
	}
	if c.cfg.SaveConfig != nil {
		return c.cfg.SaveConfig(updated)
	}
	if c.cfg.ConfigPath != "" {
		return config.Save(c.cfg.ConfigPath, updated)
	}
	return errors.New("未配置 config_path，无法持久化配置变更")
}

func (c *Client) handleAgentUpdate(ctx context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.AgentUpdateParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("agent.update 参数解不开：%v", err)}
		}
	}
	if c.cfg.Execs != nil && c.cfg.Execs.Running() {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: updater.ErrExecInFlight.Error()}
	}
	applyFn := c.cfg.UpdateApply
	if applyFn == nil {
		applyFn = updater.Apply
	}
	opts := updater.Options{
		CurrentVersion:          c.cfg.AgentVersion,
		TargetVersion:           p.Version,
		Channel:                 p.Channel,
		UseCDN:                  p.UseCDN,
		ExpectedControlProtocol: p.ExpectedControlProtocol,
		Sources:                 c.cfg.ReleaseSources,
		Root:                    c.root,
		StagingDir:              c.cfg.StagingDir,
		Execs:                   c.cfg.Execs,
	}
	res, err := applyFn(ctx, opts)
	if err != nil {
		if res != nil && res.DiskState != "" {
			return xrpc.AgentUpdateAck{
				Accepted:        false,
				PreviousVersion: res.PreviousVersion,
				TargetVersion:   res.TargetVersion,
				Source:          res.Source,
				DiskState:       res.DiskState,
				Retryable:       res.DiskState != xrpc.DiskStateNewUnconfirmed,
				BatchContinue:   res.DiskState != xrpc.DiskStateNewUnconfirmed,
				Message:         err.Error(),
			}, nil
		}
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: err.Error()}
	}
	c.addPostAction(func() {
		if c.cfg.RequestExec != nil {
			c.cfg.RequestExec(res.Executable)
		}
	})
	return xrpc.AgentUpdateAck{
		Accepted:        true,
		PreviousVersion: res.PreviousVersion,
		TargetVersion:   res.TargetVersion,
		Source:          res.Source,
	}, nil
}

func (c *Client) handleAgentUninstall(ctx context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.AgentUninstallParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("agent.uninstall 参数解不开：%v", err)}
		}
	}
	if c.cfg.Execs != nil && c.cfg.Execs.Running() {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: updater.ErrExecInFlight.Error()}
	}
	delay := time.Duration(p.DetachDelayMS) * time.Millisecond
	if delay <= 0 {
		delay = time.Second
	}
	spawnFn := c.cfg.UninstallSpawn
	if spawnFn == nil {
		spawnFn = updater.SpawnDetachedUninstall
	}
	spawner, err := spawnFn(ctx, updater.DetachOptions{
		Root:  c.root,
		Delay: delay,
		Execs: c.cfg.Execs,
	})
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: err.Error()}
	}
	c.addPostAction(func() {
		if c.cfg.RequestStop != nil {
			c.cfg.RequestStop()
		}
	})
	return xrpc.AgentUninstallAck{
		Accepted:    true,
		ScheduledAt: c.cfg.Now().UTC(),
		Spawner:     spawner,
	}, nil
}

func (c *Client) handleAgentSwitchPorts(_ context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.SwitchPortsParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("agent.switch_ports 参数解不开：%v", err)}
	}
	if p.ListenPort == 0 && p.PullPort == 0 {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "agent.switch_ports 至少需要提供 listen_port 或 pull_port 之一"}
	}
	if (p.ListenPort != 0 && (p.ListenPort < 1 || p.ListenPort > 65535)) ||
		(p.PullPort != 0 && (p.PullPort < 1 || p.PullPort > 65535)) {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "端口号必须在 1..65535 之间"}
	}

	c.rotateMu.Lock()
	defer c.rotateMu.Unlock()

	updated, err := c.loadConfigForEditLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	if p.ListenPort > 0 {
		updated.ListenPort = p.ListenPort
	}
	if p.PullPort > 0 {
		updated.PullPort = p.PullPort
	}
	if err := updated.Validate(); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}

	cleanupOld, err := c.gate.SwitchPorts(updated.EffectiveListenPort(), updated.EffectivePullPort(), func() error {
		return c.persistConfigLocked(updated)
	})
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("热切换端口失败：%v", err)}
	}
	onceClose := sync.OnceFunc(cleanupOld)
	c.addPostAction(onceClose)
	time.AfterFunc(2*time.Second, onceClose)

	return xrpc.SwitchPortsAck{
		ListenPort: updated.EffectiveListenPort(),
		PullPort:   updated.EffectivePullPort(),
		UpdatedAt:  c.cfg.Now().UTC(),
	}, nil
}

func (c *Client) handleAgentProbeMaster(ctx context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.ProbeMasterParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("agent.probe_master_url 参数解不开：%v", err)}
	}
	targetURL := strings.TrimRight(strings.TrimSpace(p.URL), "/")
	if err := pathguard.RejectControlChars("url", targetURL); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	u, err := url.ParseRequestURI(targetURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("探测目标必须是合法 https:// 地址，得到 %q", p.URL)}
	}
	if len(c.cfg.MasterKey) != 32 {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: "缺少本地 master_public_key，无法做握手验签"}
	}

	timeout := time.Duration(p.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := c.cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	start := time.Now()
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, Error: err.Error()}, nil
	}
	ephPub := ephPriv.PublicKey().Bytes()
	reqBytes, err := json.Marshal(xrpc.HTTPHandshakeReq{AgentEphemeral: ephPub})
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, Error: err.Error()}, nil
	}
	req, err := http.NewRequestWithContext(pctx, http.MethodPost, targetURL+xrpc.HTTPMasterPathHandshake, bytes.NewReader(reqBytes))
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	req.Header.Set("User-Agent", "satchel-agent/"+c.cfg.AgentVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return xrpc.ProbeMasterResult{
			URL:       targetURL,
			Reachable: false,
			LatencyMS: time.Since(start).Milliseconds(),
			Error:     fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),
		}, nil
	}
	var hs xrpc.HTTPHandshakeResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&hs); err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	if len(hs.MasterEphemeral) != 32 || !securechan.VerifyHandshake(c.cfg.MasterKey, ephPub, hs.MasterEphemeral, hs.Signature) {
		return xrpc.ProbeMasterResult{
			URL:       targetURL,
			Reachable: false,
			LatencyMS: time.Since(start).Milliseconds(),
			Error:     "候选主控返回了不匹配本地 master_public_key 的握手签名",
		}, nil
	}
	masterEph, err := ecdh.X25519().NewPublicKey(hs.MasterEphemeral)
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	shared, err := ephPriv.ECDH(masterEph)
	if err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	if _, err := securechan.DeriveSession(shared, ephPub, hs.MasterEphemeral, false); err != nil {
		return xrpc.ProbeMasterResult{URL: targetURL, Reachable: false, LatencyMS: time.Since(start).Milliseconds(), Error: err.Error()}, nil
	}
	return xrpc.ProbeMasterResult{
		URL:       targetURL,
		Reachable: true,
		LatencyMS: time.Since(start).Milliseconds(),
	}, nil
}

func (c *Client) handleAgentUpdateMaster(_ context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.UpdateMasterParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("agent.update_master_url 参数解不开：%v", err)}
	}
	if err := pathguard.RejectControlChars("master_url", p.MasterURL); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	u, err := url.ParseRequestURI(strings.TrimSpace(p.MasterURL))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("master_url 必须是干净的 https:// origin，得到 %q", p.MasterURL)}
	}
	cleanURL := "https://" + u.Host

	c.rotateMu.Lock()
	defer c.rotateMu.Unlock()

	updated, err := c.loadConfigForEditLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	updated.MasterURL = cleanURL
	if err := c.persistConfigLocked(updated); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("保存新 master_url 失败：%v", err)}
	}

	c.setMasterURL(cleanURL)
	c.uplink.ClearSession()
	// 待 RPC 回复写完并 flush 后立即取消旧 WS 并唤醒通道状态机按新地址重连，全程不重启内核。
	c.addPostAction(func() {
		c.cancelActiveWS()
		c.triggerWakeup()
	})
	return xrpc.UpdateMasterAck{
		MasterURL: cleanURL,
		UpdatedAt: c.cfg.Now().UTC(),
	}, nil
}

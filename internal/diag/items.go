package diag

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

func (e *Engine) checkServices(ctx context.Context) xrpc.DiagItemResult {
	now := e.opts.Now().UTC()
	var kinfo KernelInfo
	if e.opts.KernelInfo != nil {
		kinfo = e.opts.KernelInfo()
	}
	nginxInfo := map[string]any{"installed": false, "running": false}
	if e.opts.Nginx != nil {
		st := e.opts.Nginx.Status(ctx)
		nginxInfo = map[string]any{
			"installed": st.Installed,
			"running":   st.Running,
			"version":   st.Version,
			"in_docker": st.InDocker,
			"error":     st.Error,
		}
	}
	inDocker := false
	if e.opts.InDocker != nil {
		inDocker = e.opts.InDocker()
	}
	uptimeSec := int64(0)
	if !e.opts.StartedAt.IsZero() {
		uptimeSec = int64(now.Sub(e.opts.StartedAt).Seconds())
		if uptimeSec < 0 {
			uptimeSec = 0
		}
	}
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemServices,
		OK:     true,
		Status: xrpc.DiagStatusOK,
		Data: map[string]any{
			"agent": map[string]any{
				"running":        true,
				"version":        e.opts.AgentVersion,
				"in_docker":      inDocker,
				"uptime_seconds": uptimeSec,
			},
			"kernel": map[string]any{
				"running":    kinfo.Running,
				"version":    kinfo.Version,
				"started_at": kinfo.StartedAt,
				"inbounds":   kinfo.Inbounds,
			},
			"nginx": nginxInfo,
		},
	}
}

func (e *Engine) checkLogs(ctx context.Context, lines int) xrpc.DiagItemResult {
	if lines <= 0 {
		lines = defaultLogLines
	}
	if lines > maxLogLines {
		lines = maxLogLines
	}
	if e.opts.Logs == nil {
		return xrpc.DiagItemResult{
			Name:          xrpc.DiagItemLogs,
			OK:            true,
			Status:        xrpc.DiagStatusOK,
			ContentType:   "data",
			UntrustedData: true,
			Data: map[string]any{
				"agent": []xrpc.AgentLogEntry{},
				"core":  []xrpc.AgentLogEntry{},
				"nginx": []xrpc.AgentLogEntry{},
			},
		}
	}
	out := map[string]any{}
	for _, svc := range []string{"agent", "core", "nginx"} {
		res, err := e.opts.Logs.List(ctx, xrpc.AgentLogsParams{Service: svc, Limit: lines})
		if err != nil {
			out[svc] = map[string]any{"error": err.Error()}
			continue
		}
		out[svc] = map[string]any{
			"file":      res.File,
			"total":     res.Total,
			"truncated": res.Truncated,
			"items":     res.Items,
		}
	}
	return xrpc.DiagItemResult{
		Name:          xrpc.DiagItemLogs,
		OK:            true,
		Status:        xrpc.DiagStatusOK,
		ContentType:   "data",
		UntrustedData: true,
		Data:          out,
	}
}

var (
	pemKeyRe     = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	jsonSecretRe = regexp.MustCompile(`(?i)("(?:private_key|password|uuid|short_id|short_ids|pre_shared_key|psk|token|access_token|license_key|secret|secret_key)"\s*:\s*)"([^"]*)"`)
	satchelTokRe = regexp.MustCompile(`\bsat_[A-Za-z0-9_-]{8,}\b`)
)

// RedactSensitiveText 对配置或输出文本中的已知密钥模式做纵深脱敏。
func RedactSensitiveText(s string) string {
	s = pemKeyRe.ReplaceAllString(s, "***")
	s = jsonSecretRe.ReplaceAllString(s, `$1"***"`)
	s = satchelTokRe.ReplaceAllString(s, "***")
	return s
}

func (e *Engine) checkConfig(_ context.Context, includeSecrets bool) xrpc.DiagItemResult {
	data := map[string]any{
		"redacted": !includeSecrets,
	}
	if e.opts.ConfigDir != "" {
		kp := filepath.Join(e.opts.ConfigDir, "kernel.json")
		if raw, err := e.opts.ReadFile(kp); err == nil {
			sum := sha256.Sum256(raw)
			text := string(raw)
			if !includeSecrets {
				text = redactKernelJSON(raw)
			}
			trimmed, truncated := trimText(text, maxConfigBytes)
			data["kernel_exists"] = true
			data["kernel_hash"] = hex.EncodeToString(sum[:])
			data["kernel_bytes"] = len(raw)
			data["kernel_truncated"] = truncated
			data["kernel_config"] = trimmed
		} else {
			data["kernel_exists"] = false
		}
	}

	// 列出受管 nginx 站点文件名（绝不读取 config.yaml 或私钥）。
	var nginxFiles []string
	for _, root := range e.opts.NginxRoots {
		for _, sub := range []string{"servers", "stream_servers"} {
			dir := filepath.Join(root, sub)
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, ent := range ents {
				if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".conf") {
					nginxFiles = append(nginxFiles, filepath.Join(sub, ent.Name()))
				}
			}
		}
	}
	data["nginx_files"] = nginxFiles

	return xrpc.DiagItemResult{
		Name:          xrpc.DiagItemConfig,
		OK:            true,
		Status:        xrpc.DiagStatusOK,
		ContentType:   "data",
		UntrustedData: true,
		Data:          data,
	}
}

func redactKernelJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return RedactSensitiveText(string(raw))
	}
	redacted := redactJSONValue(v)
	out, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return RedactSensitiveText(string(raw))
	}
	return RedactSensitiveText(string(out))
}

var secretJSONKeys = map[string]bool{
	"private_key":    true,
	"password":       true,
	"uuid":           true,
	"short_id":       true,
	"short_ids":      true,
	"pre_shared_key": true,
	"psk":            true,
	"key":            true,
	"token":          true,
	"access_token":   true,
	"license_key":    true,
	"secret":         true,
	"secret_key":     true,
}

func redactJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if secretJSONKeys[strings.ToLower(k)] {
				if s, ok := val.(string); ok && s == "" {
					out[k] = ""
				} else {
					out[k] = "***"
				}
				continue
			}
			out[k] = redactJSONValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = redactJSONValue(elem)
		}
		return out
	default:
		return v
	}
}

func (e *Engine) checkConnectivity(ctx context.Context, overrideMasterURL string) xrpc.DiagItemResult {
	masterURL := strings.TrimSpace(overrideMasterURL)
	if masterURL == "" {
		masterURL = strings.TrimSpace(e.opts.MasterURL)
	}
	type probeResult struct {
		Target    string   `json:"target"`
		Resolved  []string `json:"resolved,omitempty"`
		Reachable bool     `json:"reachable"`
		LatencyMS int64    `json:"latency_ms"`
		Error     string   `json:"error,omitempty"`
	}
	targets := make([]string, 0, len(e.opts.ProbeTargets)+1)
	if masterURL != "" {
		if u, err := url.Parse(masterURL); err == nil && u.Host != "" {
			hostPort := u.Host
			if _, _, err := net.SplitHostPort(hostPort); err != nil {
				if strings.EqualFold(u.Scheme, "http") {
					hostPort = net.JoinHostPort(hostPort, "80")
				} else {
					hostPort = net.JoinHostPort(hostPort, "443")
				}
			}
			targets = append(targets, hostPort)
		}
	}
	targets = append(targets, e.opts.ProbeTargets...)

	results := make([]probeResult, 0, len(targets))
	anyOK := false
	for _, tgt := range targets {
		host, _, err := net.SplitHostPort(tgt)
		if err != nil {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		t0 := time.Now()
		pr := probeResult{Target: tgt}
		if net.ParseIP(host) == nil {
			if ips, rerr := net.DefaultResolver.LookupHost(pctx, host); rerr == nil {
				pr.Resolved = ips
			}
		}
		d := &net.Dialer{Timeout: 2 * time.Second}
		conn, derr := d.DialContext(pctx, "tcp", tgt)
		pr.LatencyMS = time.Since(t0).Milliseconds()
		if derr != nil {
			pr.Error = derr.Error()
		} else {
			pr.Reachable = true
			anyOK = true
			// 对 443 仅确认 TCP 连通后优雅关闭（不强制校验证书以免自签内部域名报错）。
			_ = tls.VersionTLS13
			_ = conn.Close()
		}
		cancel()
		results = append(results, pr)
	}
	ok := len(results) == 0 || anyOK
	status := xrpc.DiagStatusOK
	errMsg := ""
	if !ok {
		status = xrpc.DiagStatusFailed
		errMsg = "全部连通性探测目标均不可达"
	}
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemConnectivity,
		OK:     ok,
		Status: status,
		Error:  errMsg,
		Data: map[string]any{
			"probes": results,
		},
	}
}

func (e *Engine) checkClock(ctx context.Context, masterTimeUnixMS int64) xrpc.DiagItemResult {
	now := e.opts.Now().UTC()
	data := map[string]any{
		"node_time_utc": now.Format(time.RFC3339Nano),
	}
	if masterTimeUnixMS > 0 {
		mTime := time.UnixMilli(masterTimeUnixMS).UTC()
		offsetSec := now.Sub(mTime).Seconds()
		data["master_time_utc"] = mTime.Format(time.RFC3339Nano)
		data["offset_seconds"] = offsetSec
	}
	// 可选采集 timedatectl / chronyc 同步摘要（非必需，不可用不判失败）。
	if out, err := e.opts.RunCmd(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		data["ntp_synchronized"] = strings.TrimSpace(string(out)) == "yes"
	} else if out, err := e.opts.RunCmd(ctx, "chronyc", "tracking"); err == nil {
		s, _ := trimText(string(out), 1024)
		data["chrony_tracking"] = strings.TrimSpace(s)
	}
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemClock,
		OK:     true,
		Status: xrpc.DiagStatusOK,
		Data:   data,
	}
}

func (e *Engine) checkResources(_ context.Context) xrpc.DiagItemResult {
	if e.opts.Sys == nil {
		return xrpc.DiagItemResult{
			Name:   xrpc.DiagItemResources,
			OK:     false,
			Status: xrpc.DiagStatusFailed,
			Error:  "系统资源采集器未装配",
		}
	}
	info := e.opts.Sys.Info()
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemResources,
		OK:     true,
		Status: xrpc.DiagStatusOK,
		Data:   info,
	}
}

func (e *Engine) checkSpeedtest() xrpc.DiagItemResult {
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemSpeedtest,
		OK:     true,
		Status: xrpc.DiagStatusNotAvailable,
		Data: map[string]any{
			"message": "测速诊断项将在 M7 接入",
		},
	}
}

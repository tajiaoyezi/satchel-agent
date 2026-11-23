// Package diag 实现节点侧纯 Go 固定只读诊断集（10 项），供远程 diag.run RPC 与本地 satchel-agent diag 子命令共用。
// 每项诊断独立超时，单项失败仅记录在该项的 ok=false / error 中，绝不中断其余项。
package diag

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/nginxctl"
	"github.com/satchel/satchel-agent/internal/telemetry"
)

const (
	defaultItemTimeout = 5 * time.Second
	minItemTimeout     = 1 * time.Second
	maxItemTimeout     = 15 * time.Second
	defaultLogLines    = 50
	maxLogLines        = 200
	maxConfigBytes     = 64 << 10
	maxCmdOutputBytes  = 64 << 10
)

// CmdRunner 执行受超时与输出上限约束的只读命令（用于防火墙/时钟/端口回退探查；测试可注入）。
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// KernelInfo 描述运行中内核的只读状态摘要。
type KernelInfo struct {
	Running   bool
	Version   string
	StartedAt *time.Time
	Inbounds  []string
}

// Options 配置诊断引擎依赖与可测试注入点。
type Options struct {
	ConfigDir     string
	NginxRoots    []string
	CertDirs      []string
	MasterURL     string
	AgentVersion  string
	StartedAt     time.Time
	InDocker      func() bool
	KernelInfo    func() KernelInfo
	Nginx         *nginxctl.Controller
	Sys           *telemetry.SysCollector
	Logs          *telemetry.LogInspector
	Now           func() time.Time
	ReadFile      func(string) ([]byte, error)
	Stat          func(string) (os.FileInfo, error)
	RunCmd        CmdRunner
	AlpineRelease string   // 默认 /etc/alpine-release，测试可注入
	ProbeTargets  []string // 连通性探测额外目标 host:port，默认 ["1.1.1.1:443"]
}

// Engine 是节点固定诊断集执行器。
type Engine struct {
	opts Options
}

// New 构造诊断引擎。
func New(opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ReadFile == nil {
		opts.ReadFile = os.ReadFile
	}
	if opts.Stat == nil {
		opts.Stat = os.Stat
	}
	if opts.RunCmd == nil {
		opts.RunCmd = defaultRunCmd
	}
	if opts.AlpineRelease == "" {
		opts.AlpineRelease = "/etc/alpine-release"
	}
	if len(opts.NginxRoots) == 0 {
		opts.NginxRoots = []string{"/etc/nginx"}
	}
	if len(opts.CertDirs) == 0 {
		dirs := []string{"/etc/nginx/cert"}
		if opts.ConfigDir != "" {
			dirs = append(dirs, opts.ConfigDir)
		}
		opts.CertDirs = dirs
	}
	if opts.ProbeTargets == nil {
		opts.ProbeTargets = []string{"1.1.1.1:443"}
	}
	return &Engine{opts: opts}
}

func defaultRunCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, max: maxCmdOutputBytes}
	cmd.Stdout = lw
	cmd.Stderr = lw
	err := cmd.Run()
	return buf.Bytes(), err
}

type limitedWriter struct {
	w   *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	rem := l.max - l.w.Len()
	if rem > 0 {
		if len(p) > rem {
			_, _ = l.w.Write(p[:rem])
		} else {
			_, _ = l.w.Write(p)
		}
	}
	return len(p), nil
}

// Run 按请求参数执行单项或全量固定诊断项；未知诊断项名返回 xrpc.CodeBadParams。
func (e *Engine) Run(ctx context.Context, p xrpc.DiagRunParams) (*xrpc.DiagRunResult, error) {
	items := p.Items
	if len(items) == 0 {
		items = xrpc.DiagItems
	} else {
		seen := make(map[string]bool, len(items))
		clean := make([]string, 0, len(items))
		for _, raw := range items {
			name := xrpc.NormalizeDiagItem(raw)
			if !xrpc.ValidDiagItem(name) {
				return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("未知诊断项 %q，可选：%s", raw, strings.Join(xrpc.DiagItems, ", "))}
			}
			if !seen[name] {
				seen[name] = true
				clean = append(clean, name)
			}
		}
		items = clean
	}

	itemTimeout := defaultItemTimeout
	if p.ItemTimeoutMS > 0 {
		d := time.Duration(p.ItemTimeoutMS) * time.Millisecond
		if d < minItemTimeout {
			d = minItemTimeout
		} else if d > maxItemTimeout {
			d = maxItemTimeout
		}
		itemTimeout = d
	}

	now := e.opts.Now().UTC()
	res := &xrpc.DiagRunResult{
		CollectedAt: now,
		NodeTimeUTC: now,
		Items:       make([]xrpc.DiagItemResult, 0, len(items)),
	}

	for _, name := range items {
		res.Items = append(res.Items, e.runOne(ctx, name, p, itemTimeout))
	}
	return res, nil
}

func (e *Engine) runOne(ctx context.Context, name string, p xrpc.DiagRunParams, timeout time.Duration) xrpc.DiagItemResult {
	itemCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()

	var item xrpc.DiagItemResult
	switch name {
	case xrpc.DiagItemPorts:
		item = e.checkPorts(itemCtx)
	case xrpc.DiagItemServices:
		item = e.checkServices(itemCtx)
	case xrpc.DiagItemLogs:
		item = e.checkLogs(itemCtx, p.LogLines)
	case xrpc.DiagItemConfig:
		item = e.checkConfig(itemCtx, p.IncludeSecrets)
	case xrpc.DiagItemConnectivity:
		item = e.checkConnectivity(itemCtx, p.MasterURL)
	case xrpc.DiagItemFirewall:
		item = e.checkFirewall(itemCtx)
	case xrpc.DiagItemClock:
		item = e.checkClock(itemCtx, p.MasterTimeUnixMS)
	case xrpc.DiagItemResources:
		item = e.checkResources(itemCtx)
	case xrpc.DiagItemCerts:
		item = e.checkCerts(itemCtx)
	case xrpc.DiagItemSpeedtest:
		item = e.checkSpeedtest()
	default:
		item = xrpc.DiagItemResult{Name: name, OK: false, Status: xrpc.DiagStatusFailed, Error: "不支持的诊断项"}
	}
	item.Name = name
	item.DurationMS = time.Since(start).Milliseconds()
	if item.Status == "" {
		if item.OK {
			item.Status = xrpc.DiagStatusOK
		} else {
			item.Status = xrpc.DiagStatusFailed
		}
	}
	return item
}

// Package control 是节点上连接管控、流量与重启内核的通道方法（m2-03 design 第 4 条，node-limiter「通道上的连接管控方法」、
// node-traffic「定时拉取计数快照」；m2-04 design 第 2 条，agent-kernel「重启内核」）：校验参数后交给限速来源的存储
// （internal/limits）、tracker 与内核。参数问题一律回 xrpc.CodeBadParams，主控据此报 bad_request 并带上这里给的原因。
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/telemetry"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// KernelConfig 是内核配置（一份 sing-box 配置）的文件名，与 config.yaml 放在同一个目录。
const KernelConfig = "kernel.json"

// ReadKernelConfig 读 dir 下的 kernel.json 并解析入站名。文件不存在、读不了或解析不了时返回错误。
func ReadKernelConfig(dir string) ([]byte, []string, error) {
	if dir == "" {
		return nil, nil, fmt.Errorf("配置目录里没有 %s：%w", KernelConfig, os.ErrNotExist)
	}
	config, err := os.ReadFile(filepath.Join(dir, KernelConfig))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("配置目录里没有 %s：%w", KernelConfig, err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("读 %s 失败：%w", KernelConfig, err)
	}
	tags, err := kernel.InboundTags(config)
	if err != nil {
		return nil, nil, fmt.Errorf("%s 解析不了：%w", KernelConfig, err)
	}
	return config, tags, nil
}

// Inbounds 存当前内核配置里的入站名（kernel.InboundTags），带锁供重启内核更新、连接管控方法读取；
// 切片为 nil 表示节点没有可用的内核配置（文件不存在或解析不了）。
type Inbounds struct {
	mu   sync.RWMutex
	tags []string
}

// NewInbounds 用给定的入站名建一份 Inbounds（tags 为 nil 表示没有可用的内核配置）。
func NewInbounds(tags []string) *Inbounds {
	return &Inbounds{tags: slices.Clone(tags)}
}

// Get 返回当前入站名的副本（没有可用的内核配置时返回 nil）。
func (in *Inbounds) Get() []string {
	if in == nil {
		return nil
	}
	in.mu.RLock()
	defer in.mu.RUnlock()
	return slices.Clone(in.tags)
}

// Set 更新入站名。
func (in *Inbounds) Set(tags []string) {
	in.mu.Lock()
	in.tags = slices.Clone(tags)
	in.mu.Unlock()
}

// Deps 是这些方法的依赖。Inbounds 存 kernel.json 里的入站名；KernelCtx 是内核启动用的 context（随进程退出取消，
// 不随通道连接取消）；ConfigDir 是放 kernel.json 的目录。Now 为空时用 time.Now。
type Deps struct {
	Limits     *limits.Store
	Tracker    *tracker.Tracker
	Kernel     *kernel.Kernel
	Inbounds   *Inbounds
	KernelCtx  context.Context
	ConfigDir  string
	NginxRoots []string
	ConfigMu   *sync.Mutex
	Now        func() time.Time
	Sys        *telemetry.SysCollector
	Speed      *telemetry.SpeedCollector
	Logs       *telemetry.LogInspector
	ListNICs   func() ([]xrpc.NICInfo, error)
}

func badParams(format string, args ...any) *xrpc.Error {
	return &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf(format, args...)}
}

// decode 解参数；解不开回参数不合法。
func decode(raw json.RawMessage, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return badParams("参数解不开：%v", err)
	}
	return nil
}

func (d Deps) checkHasKernel() ([]string, error) {
	tags := d.Inbounds.Get()
	if tags == nil {
		return nil, badParams("节点没有内核配置（配置目录里没有可用的 kernel.json）")
	}
	return tags, nil
}

func (d Deps) checkInbound(tag string) error {
	tags, err := d.checkHasKernel()
	if err != nil {
		return err
	}
	if !slices.Contains(tags, tag) {
		return badParams("节点上没有入站 %q（内核配置里的入站：%s）", tag, strings.Join(tags, "、"))
	}
	return nil
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) kernelCtx() context.Context {
	if d.KernelCtx != nil {
		return d.KernelCtx
	}
	return context.Background()
}

func checkCredential(credential string) error {
	if credential == "" {
		return badParams("凭据名不能为空")
	}
	return nil
}

func checkSource(source string) error {
	if !xrpc.ValidSource(source) {
		return badParams("不认识的限速来源 %q（只有 %s）", source, strings.Join(xrpc.Sources, "、"))
	}
	return nil
}

// Methods 返回连接管控、流量、内核与遥测日志方法的处理函数。
func Methods(d Deps) xrpc.Methods {
	if d.Inbounds == nil {
		d.Inbounds = NewInbounds(nil)
	}
	if d.ConfigMu == nil {
		d.ConfigMu = &sync.Mutex{}
	}
	m := xrpc.Methods{
		xrpc.MethodLimiterSet: func(_ context.Context, raw json.RawMessage) (any, error) {
			// 外层的 BPS 是指针，用来分出「没给」与「给了 0」（0 是显式不限速，没给不能当成 0）；JSON 解码时外层字段优先。
			var p struct {
				xrpc.LimiterSetParams
				BPS *int64 `json:"bps"`
			}
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			if err := checkSource(p.Source); err != nil {
				return nil, err
			}
			if p.BPS == nil {
				return nil, badParams("缺少限速值 bps")
			}
			if *p.BPS < 0 {
				return nil, badParams("限速值 %d 不能是负数", *p.BPS)
			}
			if p.Deadline != nil && !p.Deadline.After(d.now()) {
				return nil, badParams("截止时间 %s 已经过了", p.Deadline.UTC().Format(time.RFC3339))
			}
			if err := checkCredential(p.Credential); err != nil {
				return nil, err
			}
			if err := d.checkInbound(p.Inbound); err != nil {
				return nil, err
			}
			st, err := d.Limits.Set(p.Inbound, p.Credential, p.Source, *p.BPS, p.Deadline)
			if errors.Is(err, limits.ErrExpired) { // 入口校验之后、写之前过期的
				return nil, badParams("截止时间 %s 已经过了", p.Deadline.UTC().Format(time.RFC3339))
			}
			return st, err
		},
		xrpc.MethodLimiterUnset: func(_ context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.LimiterUnsetParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			if err := checkSource(p.Source); err != nil {
				return nil, err
			}
			if err := checkCredential(p.Credential); err != nil {
				return nil, err
			}
			if err := d.checkInbound(p.Inbound); err != nil {
				return nil, err
			}
			return d.Limits.Unset(p.Inbound, p.Credential, p.Source)
		},
		xrpc.MethodConnectionsList: func(_ context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.ConnectionsListParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			if err := checkCredential(p.Credential); err != nil {
				return nil, err
			}
			if err := d.checkInbound(p.Inbound); err != nil {
				return nil, err
			}
			list := xrpc.ConnectionsList{Connections: []xrpc.Connection{}}
			for _, c := range d.Tracker.Connections(p.Inbound, p.Credential) {
				list.Connections = append(list.Connections, xrpc.Connection{ID: c.ID, Network: c.Network, Peer: c.Source, Outbound: c.Outbound, Start: c.Start})
			}
			return list, nil
		},
		xrpc.MethodConnectionsKick: func(_ context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.ConnectionsKickParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			if err := checkCredential(p.Credential); err != nil {
				return nil, err
			}
			if p.Inbound == "" {
				if _, err := d.checkHasKernel(); err != nil {
					return nil, err
				}
				return xrpc.ConnectionsKicked{Kicked: d.Tracker.KickUser(p.Credential)}, nil
			}
			if err := d.checkInbound(p.Inbound); err != nil {
				return nil, err
			}
			return xrpc.ConnectionsKicked{Kicked: d.Tracker.Kick(p.Inbound, p.Credential)}, nil
		},
		xrpc.MethodTrafficSnapshot: func(context.Context, json.RawMessage) (any, error) {
			s := d.Tracker.Snapshot()
			out := xrpc.TrafficSnapshot{BootID: s.BootID, Generation: s.Generation, At: s.At.UTC(), Counts: []xrpc.TrafficCount{},
				KernelRunning: d.Kernel.Running()}
			for _, c := range s.Counts {
				out.Counts = append(out.Counts, xrpc.TrafficCount{Inbound: c.Inbound, Outbound: c.Outbound, Credential: c.User, Up: c.Up, Down: c.Down})
			}
			if out.KernelRunning {
				out.KernelVersion = kernel.Version
			}
			if at := d.Kernel.StartedAt(); !at.IsZero() {
				out.KernelStartedAt = &at
			}
			return out, nil
		},
		xrpc.MethodKernelRestart: func(_ context.Context, _ json.RawMessage) (any, error) {
			d.ConfigMu.Lock()
			defer d.ConfigMu.Unlock()
			config, tags, err := ReadKernelConfig(d.ConfigDir)
			if err != nil {
				return nil, badParams("%v", err)
			}
			if err := d.Kernel.Restart(d.kernelCtx(), config); err != nil {
				return nil, err
			}
			d.Inbounds.Set(tags)
			out := xrpc.KernelRestarted{
				Running:  d.Kernel.Running(),
				Version:  kernel.Version,
				Inbounds: tags,
			}
			if at := d.Kernel.StartedAt(); !at.IsZero() {
				out.StartedAt = &at
			}
			return out, nil
		},
	}
	registerConfigMethods(m, d)
	registerOutboundMethods(m, d)
	if d.Sys != nil {
		m[xrpc.MethodSystemInfo] = func(context.Context, json.RawMessage) (any, error) {
			return d.Sys.Info(), nil
		}
	}
	if d.ListNICs != nil {
		m[xrpc.MethodSystemNICs] = func(context.Context, json.RawMessage) (any, error) {
			nics, err := d.ListNICs()
			if err != nil {
				return nil, err
			}
			if nics == nil {
				nics = []xrpc.NICInfo{}
			}
			return xrpc.SystemNICs{NICs: nics}, nil
		}
	}
	if d.Speed != nil {
		m[xrpc.MethodSpeedGet] = func(context.Context, json.RawMessage) (any, error) {
			return d.Speed.LatestOrSample(), nil
		}
	}
	if d.Logs != nil {
		m[xrpc.MethodAgentLogs] = func(ctx context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.AgentLogsParams
			if len(raw) > 0 && string(raw) != "null" {
				if err := decode(raw, &p); err != nil {
					return nil, err
				}
			}
			return d.Logs.List(ctx, p)
		}
		m[xrpc.MethodAgentLogFiles] = func(context.Context, json.RawMessage) (any, error) {
			return d.Logs.Files()
		}
	}
	return m
}

// Package control 是节点上连接管控与流量的通道方法（m2-03 design 第 4 条，node-limiter「通道上的连接管控方法」、
// node-traffic「定时拉取计数快照」）：校验参数后交给限速来源的存储（internal/limits）与 tracker。参数问题一律回
// xrpc.CodeBadParams，主控据此报 bad_request 并带上这里给的原因。
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// Deps 是这些方法的依赖。Inbounds 是 kernel.json 里的入站名（kernel.InboundTags）；为 nil 表示节点没有可用的内核配置
// （文件不存在或解析不了）。Now 为空时用 time.Now。
type Deps struct {
	Limits   *limits.Store
	Tracker  *tracker.Tracker
	Kernel   *kernel.Kernel
	Inbounds []string
	Now      func() time.Time
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

func (d Deps) checkInbound(tag string) error {
	if d.Inbounds == nil {
		return badParams("节点没有内核配置（配置目录里没有可用的 kernel.json）")
	}
	if !slices.Contains(d.Inbounds, tag) {
		return badParams("节点上没有入站 %q（内核配置里的入站：%s）", tag, strings.Join(d.Inbounds, "、"))
	}
	return nil
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
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

// Methods 返回五个方法的处理函数。
func Methods(d Deps) xrpc.Methods {
	return xrpc.Methods{
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
	}
}

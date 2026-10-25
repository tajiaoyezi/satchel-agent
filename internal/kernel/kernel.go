// Package kernel 管 satchel-agent 内嵌的 sing-box：按 JSON 格式的 sing-box 配置在进程里起停，同一个进程里可以停掉再启动，
// 每次启动都把同一个 tracker 挂上去（agent-kernel「内核起停」）。sing-box 以 go.mod 依赖引用官方版本，不改源码。
package kernel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/satchel/satchel-agent/internal/tracker"
)

// ErrRunning 是内核已经在跑时再次 Start 的错误。
var ErrRunning = errors.New("内核已经在运行，先 Stop 再 Start")

// Kernel 是一个可以反复起停的 sing-box 内核。
type Kernel struct {
	tracker *tracker.Tracker

	mu        sync.Mutex
	instance  *box.Box
	cancel    context.CancelFunc
	startedAt time.Time // 最近一次启动成功的时间；没启动成功过时为零
}

// New 建一个内核，t 在每次启动时挂上去。
func New(t *tracker.Tracker) *Kernel {
	return &Kernel{tracker: t}
}

// Tracker 返回挂在这个内核上的 tracker。
func (k *Kernel) Tracker() *tracker.Tracker { return k.tracker }

// Start 按 sing-box 的 JSON 配置建内核并启动，把 tracker 挂上去；启动成功后 tracker 的内核代数加一（失败不算，否则接收方会多记一次重启）。
// ctx 只管启动这一段：启动期间 ctx 结束（比如卡在下载远程规则集时收到退出信号）就放弃，返回带 ctx 错误的 error；启动成功以后
// 内核一直跑到 Stop，不跟着 ctx。
func (k *Kernel) Start(ctx context.Context, config []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.instance != nil {
		return ErrRunning
	}
	boxCtx, cancel := context.WithCancel(include.Context(context.Background()))
	options, err := json.UnmarshalExtendedContext[option.Options](boxCtx, config)
	if err != nil {
		cancel()
		return err
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: options})
	if err != nil {
		cancel()
		return err
	}
	instance.Router().AppendTracker(k.tracker)
	stop := context.AfterFunc(ctx, cancel) // 启动期间 ctx 结束就取消实例的 context，卡住的启动步骤随之返回
	err = instance.Start()                 // Start 失败时 sing-box 自己会 Close
	if !stop() {
		if err == nil {
			instance.Close()
		}
		cancel()
		return fmt.Errorf("内核启动期间被取消：%w", ctx.Err())
	}
	if err != nil {
		cancel()
		return err
	}
	k.tracker.KernelStarted()
	k.instance, k.cancel, k.startedAt = instance, cancel, time.Now().UTC()
	return nil
}

// InboundTags 从一份 sing-box 配置里取入站名（inbounds[].tag，没写 tag 的跳过），解析规则与 Start 相同（sing 的扩展 JSON，
// 允许注释等）。解析不了时返回错误；配置里一个入站都没有时返回空切片（不是 nil）。
func InboundTags(config []byte) ([]string, error) {
	options, err := json.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), config)
	if err != nil {
		return nil, err
	}
	tags := []string{}
	for _, in := range options.Inbounds {
		if in.Tag != "" {
			tags = append(tags, in.Tag)
		}
	}
	return tags, nil
}

// StartedAt 返回最近一次启动成功的时间（停掉以后仍是那一次）；没启动成功过时为零。
func (k *Kernel) StartedAt() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.startedAt
}

// Version 是内嵌的 sing-box 的版本，与 go.mod 里引用的一致（测试守着，升级 sing-box 时跟着改）。sing-box 自己的版本常量要
// 它的构建脚本用 ldflags 写，作为库引用时一直是 unknown，所以不用它。
const Version = "1.14.4"

// Stop 关掉内核；没在跑时什么都不做。活动的连接由 sing-box 关掉，它们已经记下的字节数不会丢。
func (k *Kernel) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.instance == nil {
		return nil
	}
	err := k.instance.Close()
	k.cancel()
	k.instance, k.cancel = nil, nil
	return err
}

// Running 报告内核是否在跑。
func (k *Kernel) Running() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.instance != nil
}

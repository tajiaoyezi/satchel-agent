// Package kernel 管 satchel-agent 内嵌的 sing-box：按 JSON 格式的 sing-box 配置在进程里起停，同一个进程里可以停掉再启动，
// 每次启动都把同一个 tracker 挂上去（agent-kernel「内核起停」）。sing-box 以 go.mod 依赖引用官方版本，不改源码。
package kernel

import (
	"context"
	"errors"
	"sync"

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

	mu       sync.Mutex
	instance *box.Box
	cancel   context.CancelFunc
}

// New 建一个内核，t 在每次启动时挂上去。
func New(t *tracker.Tracker) *Kernel {
	return &Kernel{tracker: t}
}

// Tracker 返回挂在这个内核上的 tracker。
func (k *Kernel) Tracker() *tracker.Tracker { return k.tracker }

// Start 按 sing-box 的 JSON 配置建内核并启动，把 tracker 挂上去；启动成功后 tracker 的内核代数加一（失败不算，否则接收方会多记一次重启）。
func (k *Kernel) Start(ctx context.Context, config []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.instance != nil {
		return ErrRunning
	}
	ctx = include.Context(ctx)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return err
	}
	instance.Router().AppendTracker(k.tracker)
	if err := instance.Start(); err != nil { // Start 失败时 sing-box 自己会 Close
		cancel()
		return err
	}
	k.tracker.KernelStarted()
	k.instance, k.cancel = instance, cancel
	return nil
}

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

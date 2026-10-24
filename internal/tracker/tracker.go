// Package tracker 是 satchel-agent 的连接管控：挂在 sing-box 的 Router().AppendTracker 上，所有入站的 TCP 与 UDP 都经过这里，
// 在这一处做按凭据限速、识别连接、踢线、（入站，出站，凭据）三维计数与重启基线（技术方案第 04、13 章，agent-kernel）。
// 它只依赖 sing-box 的公开接口，不改 sing-box 的源码。
//
// 锁的顺序：先 Tracker.mu，再 bucket.mu。
package tracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// Key 是桶与连接清单的键：一个入站上的一份凭据。
type Key struct {
	Inbound string
	User    string
}

// CounterKey 是三维计数的键。
type CounterKey struct {
	Inbound  string
	Outbound string
	User     string
}

// Conn 是连接清单里的一条。
type Conn struct {
	ID       uint64
	Network  string // tcp 或 udp
	Source   string // 对端地址
	Outbound string
	Start    time.Time
}

// Count 是快照里一个三维组合的累计字节数（应用层，上下行分开）。
type Count struct {
	CounterKey
	Up   int64
	Down int64
}

// Snapshot 是对外的计数快照。BootID 每个进程一个；Generation 是这个进程里内核成功启动过几次。接收方按「重启基线」的规则算累计。
type Snapshot struct {
	BootID     string
	Generation uint64
	At         time.Time
	Counts     []Count
}

type entry struct {
	Conn
	closer io.Closer
}

type counter struct {
	up, down atomic.Int64
}

// Tracker 实现 adapter.ConnectionTracker。同一个实例在内核每次启动时重新挂上去，计数与限速来源不随内核重启清零。
type Tracker struct {
	bootID     string
	generation atomic.Uint64
	nextID     atomic.Uint64

	mu       sync.Mutex
	buckets  map[Key]*bucket
	conns    map[Key]map[uint64]*entry
	counters map[CounterKey]*counter
}

var _ adapter.ConnectionTracker = (*Tracker)(nil)

// New 建一个 Tracker，生成本进程的启动标识。
func New() *Tracker {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err) // crypto/rand 失败说明系统随机源坏了，继续跑没有意义
	}
	return &Tracker{
		bootID:   hex.EncodeToString(id[:]),
		buckets:  map[Key]*bucket{},
		conns:    map[Key]map[uint64]*entry{},
		counters: map[CounterKey]*counter{},
	}
}

// BootID 返回本进程的启动标识。
func (t *Tracker) BootID() string { return t.bootID }

// Generation 返回内核在本进程里成功启动过几次。
func (t *Tracker) Generation() uint64 { return t.generation.Load() }

// KernelStarted 由内核包在每次内核启动成功之后调用。
func (t *Tracker) KernelStarted() { t.generation.Add(1) }

// RoutedConnection 包装每条经路由的 TCP 连接。凭据为空时照样登记与计数，不挂限速。
func (t *Tracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) net.Conn {
	key, ck := keys(metadata, outbound)
	w := &tcpConn{inner: conn}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.bucket, w.counter, w.release = t.attach(key, ck, N.NetworkTCP, metadata.Source.String(), w)
	return w
}

// RoutedPacketConnection 包装每个经路由的 UDP 流，规则同 RoutedConnection。
func (t *Tracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	key, ck := keys(metadata, outbound)
	w := &packetConn{inner: conn}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.bucket, w.counter, w.release = t.attach(key, ck, N.NetworkUDP, metadata.Source.String(), w)
	return w
}

// RoutedFlow 是 tun 入站的流，satchel-agent 不用 tun 入站，不处理。
func (t *Tracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

func keys(metadata adapter.InboundContext, outbound adapter.Outbound) (Key, CounterKey) {
	out := ""
	if outbound != nil {
		out = outbound.Tag()
	}
	return Key{Inbound: metadata.Inbound, User: metadata.User}, CounterKey{Inbound: metadata.Inbound, Outbound: out, User: metadata.User}
}

// attach 在同一把锁里给一条新连接找到桶（没有就建：不限速的凭据也挂桶，之后改值能作用到已有连接上；凭据为空时不挂桶）、
// 计数器，并登记进连接清单。返回的注销函数在连接关闭时调一次。
func (t *Tracker) attach(key Key, ck CounterKey, network, source string, closer io.Closer) (*bucket, *counter, func()) {
	e := &entry{Conn: Conn{ID: t.nextID.Add(1), Network: network, Source: source, Outbound: ck.Outbound, Start: time.Now()}, closer: closer}
	t.mu.Lock()
	defer t.mu.Unlock()
	var b *bucket
	if key.User != "" {
		b = t.bucketLocked(key)
	}
	c := t.counters[ck]
	if c == nil {
		c = &counter{}
		t.counters[ck] = c
	}
	m := t.conns[key]
	if m == nil {
		m = map[uint64]*entry{}
		t.conns[key] = m
	}
	m[e.ID] = e
	return b, c, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(t.conns[key], e.ID)
		if len(t.conns[key]) == 0 {
			delete(t.conns, key)
			t.reapLocked(key)
		}
	}
}

func (t *Tracker) bucketLocked(key Key) *bucket {
	b := t.buckets[key]
	if b == nil {
		b = newBucket()
		t.buckets[key] = b
	}
	return b
}

// reapLocked 在这份凭据既没有连接、三份来源也都没设时回收它的桶。
func (t *Tracker) reapLocked(key Key) {
	if b := t.buckets[key]; b != nil && len(t.conns[key]) == 0 && b.empty() {
		delete(t.buckets, key)
	}
}

// Connections 按「入站 × 凭据」列出活动连接，按编号排序。
func (t *Tracker) Connections(inbound, user string) []Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Conn, 0, len(t.conns[Key{inbound, user}]))
	for _, e := range t.conns[Key{inbound, user}] {
		out = append(out, e.Conn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Kick 断开一个入站上一份凭据的全部 TCP 连接与 UDP 流，返回断开的条数。不留黑名单，之后的新连接照常进来。
func (t *Tracker) Kick(inbound, user string) int {
	return t.kick(func(k Key) bool { return k.Inbound == inbound && k.User == user })
}

// KickUser 对这个凭据名在所有入站上的凭据各踢一次。
func (t *Tracker) KickUser(user string) int {
	return t.kick(func(k Key) bool { return k.User == user })
}

func (t *Tracker) kick(match func(Key) bool) int {
	t.mu.Lock()
	var closers []io.Closer
	for k, m := range t.conns {
		if !match(k) {
			continue
		}
		for _, e := range m {
			closers = append(closers, e.closer)
		}
	}
	t.mu.Unlock()
	for _, c := range closers {
		_ = c.Close() // 关闭会回调注销、要拿锁，所以放在锁外关
	}
	return len(closers)
}

// Snapshot 截取当前的计数快照，按（入站，出站，凭据）排序。计数只增不减。
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	counts := make([]Count, 0, len(t.counters))
	for k, c := range t.counters {
		counts = append(counts, Count{CounterKey: k, Up: c.up.Load(), Down: c.down.Load()})
	}
	t.mu.Unlock()
	sort.Slice(counts, func(i, j int) bool {
		a, b := counts[i].CounterKey, counts[j].CounterKey
		if a.Inbound != b.Inbound {
			return a.Inbound < b.Inbound
		}
		if a.Outbound != b.Outbound {
			return a.Outbound < b.Outbound
		}
		return a.User < b.User
	})
	return Snapshot{BootID: t.bootID, Generation: t.Generation(), At: time.Now(), Counts: counts}
}

// ErrNoUser 是给没有凭据名的连接设限速时的错误：认不出凭据的连接不受按凭据的限速。
var ErrNoUser = errors.New("凭据名为空：认不出凭据的连接不受按凭据的限速")

// Set 给一份凭据的某一份来源设值（比特每秒，0 表示这一份显式不限速）。deadline 非零时，到时这一份自动撤掉，效果与 Unset 相同。
func (t *Tracker) Set(inbound, user string, source Source, bps int64, deadline time.Time) error {
	if user == "" {
		return ErrNoUser
	}
	if !source.valid() {
		return fmt.Errorf("不认识的限速来源 %d", source)
	}
	if bps < 0 {
		return fmt.Errorf("限速值 %d 不能是负数", bps)
	}
	key := Key{inbound, user}
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.bucketLocked(key)
	b.set(source, bps, deadline, func(seq uint64) { t.expire(key, b, source, seq) })
	return nil
}

// Unset 撤掉一份凭据的某一份来源：它退出合成，生效值由剩下的来源重新算。
func (t *Tracker) Unset(inbound, user string, source Source) error {
	if !source.valid() {
		return fmt.Errorf("不认识的限速来源 %d", source)
	}
	key := Key{inbound, user}
	t.mu.Lock()
	defer t.mu.Unlock()
	if b := t.buckets[key]; b != nil {
		b.unset(source, 0)
		t.reapLocked(key)
	}
	return nil
}

// expire 是截止时间到了的回调：只撤掉还是那一次设值的槽位（同一只桶、seq 对得上），中间被改过就不动。
// seq 只在一只桶里递增，桶回收后新建的桶从头数，所以还要确认桶没换过，免得迟到的回调撤掉新桶上的值。
func (t *Tracker) expire(key Key, b *bucket, source Source, seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.buckets[key] == b {
		b.unset(source, seq)
		t.reapLocked(key)
	}
}

// Effective 返回一份凭据当前的生效值（比特每秒）；limited 为 false 表示不限速。
func (t *Tracker) Effective(inbound, user string) (bps int64, limited bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[Key{inbound, user}]
	if b == nil {
		return 0, false
	}
	return b.effective()
}

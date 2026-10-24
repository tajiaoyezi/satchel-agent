package tracker

import (
	"context"
	"math"
	"sync"
	"time"
)

// Source 是限速值的来源。每份凭据三份来源，生效值取已设且大于 0 的那几份里最小的一个（技术方案第 10 章）。
type Source int

const (
	SourceStatic   Source = iota // 静态：M5 起由四层覆盖算出
	SourceMaster                 // 主控临时：主控下发的临时限速（超额、白名单里的临时限速）
	SourceNodeRule               // 节点规则临时：节点按套餐里的速率规则触发
	sourceCount
)

func (s Source) valid() bool { return s >= 0 && s < sourceCount }

const (
	// burstBytes 是令牌桶的容量，也是每次读写最多一次取的额度。
	burstBytes = 16 << 10
	// minChunk 是低速时每次取额度的下限，免得一个字节一个字节地等。
	minChunk = 512
	// chunkWindow 是一次最多取多少时间的量：一次读进来的大块数据不至于先欠下一大笔额度，各条连接按小块轮流放行。
	chunkWindow = 100 * time.Millisecond
)

type slot struct {
	set   bool
	bps   int64
	seq   uint64
	timer *time.Timer
}

// bucket 是一个入站上一份凭据的令牌桶：这份凭据在这个入站上的全部连接、上行与下行、TCP 与 UDP 共用。字段由 mu 保护。
// 不用 x/time/rate（design 第 4 条）：它的 SetLimit 管不到已经排好的预约，预约的 Cancel 又只有按倒序撤才退得干净。
// 这里自己记余额 tokens（last 时刻的值，可以是负的：预约了、还没放行的额度）和 pending（还没放行的预约合计）：
//   - 连接关了，它那笔没用上的预约原数退回余额。排在后面的预约时间不变，新的预约排在它们之后，
//     所以不会多放，也不留欠账，别的等待攒下的进度也不丢；
//   - 生效值变了，先按旧速率把余额算到此刻，把 pending 全部退回，再换速率、gen 加一，并关掉 changed 叫醒正在等的读写；
//     它们的预约已经退回，按新速率重约。每一块放行之前都在锁里核对 gen，速率变过就不放行。
type bucket struct {
	mu      sync.Mutex
	slots   [sourceCount]slot
	seq     uint64
	rate    float64 // 字节每秒，0 表示不限速
	tokens  float64
	last    time.Time
	pending float64
	gen     uint64 // 每次换速率加一
	changed chan struct{}
}

func newBucket() *bucket {
	return &bucket{changed: make(chan struct{})}
}

// set 给一份来源设值；deadline 非零时起一个定时器，到时调 onExpire(这次设值的 seq)。
func (b *bucket) set(source Source, bps int64, deadline time.Time, onExpire func(seq uint64)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := &b.slots[source]
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	b.seq++
	*s = slot{set: true, bps: bps, seq: b.seq}
	if !deadline.IsZero() {
		seq := b.seq
		s.timer = time.AfterFunc(time.Until(deadline), func() { onExpire(seq) })
	}
	b.applyLocked()
}

// unset 撤掉一份来源。seq 非零时只在槽位还是那一次设值时才撤（给截止时间的回调用）。
func (b *bucket) unset(source Source, seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := &b.slots[source]
	if !s.set || (seq != 0 && s.seq != seq) {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	*s = slot{}
	b.applyLocked()
}

// effectiveLocked：已设且大于 0 的来源里取最小；一个都没有时不限速（0 表示这一份显式不限速，不参与取最小）。
func (b *bucket) effectiveLocked() (int64, bool) {
	var min int64
	for _, s := range b.slots {
		if s.set && s.bps > 0 && (min == 0 || s.bps < min) {
			min = s.bps
		}
	}
	return min, min > 0
}

func (b *bucket) effective() (int64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.effectiveLocked()
}

// applyLocked 把生效值改到令牌桶上（比特每秒换成字节每秒）：值变了就换速率，还没放行的预约全部退回，
// 叫醒正在等的读写去按新速率重约。
func (b *bucket) applyLocked() {
	var rate float64
	if bps, limited := b.effectiveLocked(); limited {
		rate = float64(bps) / 8
	}
	if rate == b.rate {
		return
	}
	now := time.Now()
	if b.rate == 0 {
		b.tokens = 0 // 从不限速变成限速：桶从空开始
	} else {
		b.advanceLocked(now)
		b.tokens = math.Min(b.tokens+b.pending, burstBytes)
	}
	b.rate, b.last, b.pending = rate, now, 0
	b.gen++
	close(b.changed)
	b.changed = make(chan struct{})
}

// advanceLocked 按当前速率把余额算到 now，不超过桶容量。
func (b *bucket) advanceLocked(now time.Time) {
	if now.After(b.last) {
		b.tokens = math.Min(b.tokens+now.Sub(b.last).Seconds()*b.rate, burstBytes)
		b.last = now
	}
}

// reserve 预约 n 个字节里的一小块，返回这一块的大小、能放行的时刻、预约时的 gen，以及换速率时会关闭的通道。
// 不限速时块的大小为 0。
func (b *bucket) reserve(n int) (int, time.Time, uint64, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := chunkFor(b.rate)
	if c == 0 {
		return 0, time.Time{}, 0, nil
	}
	if c > n {
		c = n
	}
	now := time.Now()
	b.advanceLocked(now)
	b.tokens -= float64(c)
	b.pending += float64(c)
	at := now
	if b.tokens < 0 {
		at = now.Add(time.Duration(-b.tokens / b.rate * float64(time.Second)))
	}
	return c, at, b.gen, b.changed
}

// commit 放行一笔到了时间的预约。速率变过（gen 不同）时这笔已经退回，返回 false，要按新速率重约。
func (b *bucket) commit(c int, gen uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if gen != b.gen {
		return false
	}
	b.pending -= float64(c)
	return true
}

// refund 把一笔没用上的预约退回余额（连接关了）。速率变过时这笔已经在换速率时退回，不再退。
func (b *bucket) refund(c int, gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if gen != b.gen {
		return
	}
	b.advanceLocked(time.Now())
	b.tokens = math.Min(b.tokens+float64(c), burstBytes)
	b.pending -= float64(c)
}

func (b *bucket) empty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.slots {
		if s.set {
			return false
		}
	}
	return true
}

// chunk 是当前速率下一次最多取的额度。不限速时返回 0。
func (b *bucket) chunk() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return chunkFor(b.rate)
}

// chunkFor：不超过桶容量，也不超过 chunkWindow 的量，低速时不少于 minChunk；不限速（rate 为 0）时返回 0。
func chunkFor(rate float64) int {
	if rate == 0 {
		return 0
	}
	n := int(rate * chunkWindow.Seconds())
	switch {
	case n < minChunk:
		n = minChunk
	case n > burstBytes:
		n = burstBytes
	}
	return n
}

// take 取 n 个字节的额度，切成小段等。每一块放行之前都核对速率没变过：变过就按新速率重约，
// 所以改动立刻作用到正在等的读写上，与排了多少无关。ctx 取消（连接关闭）时退回没用上的那一块并返回错误。
func (b *bucket) take(ctx context.Context, n int) error {
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, at, gen, changed := b.reserve(n)
		if c == 0 {
			return nil
		}
		if d := time.Until(at); d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-timer.C:
			case <-changed:
				timer.Stop()
				continue // 换了速率：这笔已经退回，按新速率重约
			case <-ctx.Done():
				timer.Stop()
				b.refund(c, gen)
				return ctx.Err()
			}
		}
		if !b.commit(c, gen) {
			continue // 预约之后换过速率（不论等没等、等到没有）：不按旧速率放行
		}
		n -= c
	}
	return nil
}

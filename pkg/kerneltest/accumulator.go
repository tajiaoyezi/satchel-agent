package kerneltest

import "github.com/satchel/satchel-agent/internal/tracker"

// Accumulator 是接收方按快照算累计的参考实现（design 第 8 条，agent-kernel「重启基线」），m2-03 主控侧照这个规则实现：
//   - 同一个启动标识：累计 = 基线 + 这次的值；
//   - 启动标识变了（换了进程，计数从零开始）：把上一次快照的值并进基线，这次从零开始加；
//   - 内核代数变大或启动标识变了：重启次数相应增加。
type Accumulator struct {
	Restarts int

	started    bool
	bootID     string
	generation uint64
	base       map[tracker.CounterKey][2]int64
	last       map[tracker.CounterKey][2]int64
}

// Add 收一份快照。
func (a *Accumulator) Add(s tracker.Snapshot) {
	if a.base == nil {
		a.base = map[tracker.CounterKey][2]int64{}
	}
	switch {
	case !a.started:
		a.started = true
	case s.BootID != a.bootID:
		for k, v := range a.last {
			b := a.base[k]
			a.base[k] = [2]int64{b[0] + v[0], b[1] + v[1]}
		}
		a.Restarts++ // 换了进程：这个进程里的第一次内核启动算作这一次重启
		if s.Generation > 1 {
			a.Restarts += int(s.Generation - 1)
		}
	case s.Generation > a.generation:
		a.Restarts += int(s.Generation - a.generation)
	}
	a.bootID, a.generation = s.BootID, s.Generation
	a.last = map[tracker.CounterKey][2]int64{}
	for _, c := range s.Counts {
		a.last[c.CounterKey] = [2]int64{c.Up, c.Down}
	}
}

// Total 返回一个三维组合的累计（上行，下行）。
func (a *Accumulator) Total(k tracker.CounterKey) (up, down int64) {
	b, l := a.base[k], a.last[k]
	return b[0] + l[0], b[1] + l[1]
}

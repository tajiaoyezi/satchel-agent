package kerneltest

import (
	"testing"

	"github.com/satchel/satchel-agent/internal/tracker"
)

// design 第 8 条：同一启动标识直接取这次的值；内核代数变大记重启；启动标识变了把上一次并进基线、从零接着加、记重启。
func TestAccumulator(t *testing.T) {
	k := tracker.CounterKey{Inbound: InVLESS, Outbound: Out1, User: UserA}
	snap := func(boot string, gen uint64, up, down int64) tracker.Snapshot {
		return tracker.Snapshot{BootID: boot, Generation: gen, Counts: []tracker.Count{{CounterKey: k, Up: up, Down: down}}}
	}
	var a Accumulator
	a.Add(snap("p1", 1, 10, 100))
	a.Add(snap("p1", 1, 20, 150))
	if up, down := a.Total(k); up != 20 || down != 150 || a.Restarts != 0 {
		t.Fatalf("同一进程同一代：%d %d %d", up, down, a.Restarts)
	}
	a.Add(snap("p1", 2, 25, 160)) // 同进程内核重启，计数归 tracker、不清零
	if up, down := a.Total(k); up != 25 || down != 160 || a.Restarts != 1 {
		t.Fatalf("内核重启：%d %d %d", up, down, a.Restarts)
	}
	a.Add(snap("p2", 1, 5, 40)) // 换了进程，计数从零开始
	if up, down := a.Total(k); up != 30 || down != 200 || a.Restarts != 2 {
		t.Fatalf("换了进程：%d %d %d", up, down, a.Restarts)
	}
	a.Add(snap("p2", 1, 6, 50))
	if up, down := a.Total(k); up != 31 || down != 210 || a.Restarts != 2 {
		t.Fatalf("新进程里接着加：%d %d %d", up, down, a.Restarts)
	}
	a.Add(snap("p3", 3, 1, 1)) // 新进程第一次上报时内核已经起过三次
	if a.Restarts != 5 {
		t.Fatalf("新进程里已经重启过两次，应当再加三次：%d", a.Restarts)
	}
}

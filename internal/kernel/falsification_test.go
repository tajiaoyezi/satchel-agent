package kernel_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	kt "github.com/satchel/satchel-agent/internal/kernel/kerneltest"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// M2 证伪点的五项（技术方案第 13 章，agent-kernel）。每项都有快速版与完整版（-tags falsification），数值口径照第 13 章，
// 结论以完整版为准。测得的关键数字用 t.Logf 打出来（以「结果」开头），写进 tasks.md 的结论。

type profile struct {
	name   string
	warmup time.Duration // 流起来之后等多久再开始量
	window time.Duration // 吞吐的时间窗
	mib    int64         // 这一档里「1 MB」是多少字节
}

const (
	limitMbps = 5
	bLoad     = 40_000_000 // B 的负载固定 40 Mbps：链路（本地回环）容量远大于所有并行流的目标之和
	tolerance = 0.2
	// 改动之后只等 applyWait，就单独量紧接着的 firstWindow，再量 window 作为正式数字；两档一样。
	// 30 秒的平均会把晚到的切换稀释掉，所以要看紧接着的这一小段：±20% 最多容下约 0.4 × firstWindow 的迟到
	// （用例 5；用例 6、7 更紧），这一段通过就说明改动在 applyWait + 0.8 秒 = 2.8 秒内已经生效，比第 13 章的 10 秒严。
	applyWait   = 2 * time.Second
	firstWindow = 2 * time.Second
)

var inbounds = []string{kt.InVLESS, kt.InHY2}

func mbps(n float64) int64 { return int64(n * 1e6) }

func near(got, want float64) bool { return got >= want*(1-tolerance) && got <= want*(1+tolerance) }

// measure 在同一个时间窗里量几组计数器各自的合计吞吐（Mbps）。
func measure(window time.Duration, groups ...[]*kt.Meter) []float64 {
	start := make([][]int64, len(groups))
	for i, g := range groups {
		for _, m := range g {
			start[i] = append(start[i], m.Bytes())
		}
	}
	t0 := time.Now()
	time.Sleep(window)
	elapsed := time.Since(t0).Seconds()
	out := make([]float64, len(groups))
	for i, g := range groups {
		var n int64
		for j, m := range g {
			n += m.Bytes() - start[i][j]
		}
		out[i] = float64(n) * 8 / elapsed / 1e6
	}
	return out
}

func meters(flows ...*kt.Flow) []*kt.Meter {
	out := make([]*kt.Meter, len(flows))
	for i, f := range flows {
		out[i] = f.Meter
	}
	return out
}

func stopAll(flows ...*kt.Flow) {
	for _, f := range flows {
		f.Stop()
	}
}

func downloads(t *testing.T, c *kt.Client, n int) []*kt.Flow {
	var out []*kt.Flow
	for i := 0; i < n; i++ {
		out = append(out, kt.Download(t, c, 1, 0, 0))
	}
	return out
}

func connIDs(tr *tracker.Tracker, inbound, user string) string {
	var ids []string
	for _, c := range tr.Connections(inbound, user) {
		ids = append(ids, fmt.Sprint(c.ID))
	}
	return strings.Join(ids, ",")
}

func waitDone(t *testing.T, d time.Duration, flows ...*kt.Flow) {
	t.Helper()
	deadline := time.After(d)
	for _, f := range flows {
		select {
		case <-f.Done():
		case <-deadline:
			t.Fatalf("%v 内流没有跑完", d)
		}
	}
}

// settle 在每条限速用例开始前清掉上一条留下的连接：客户端停了以后，服务端还会按限速读完缓冲里积压的上行，
// UDP 会话也要等超时才走，它们占着同一个桶，会把下一条用例的吞吐拉低。
func settle(t *testing.T, tr *tracker.Tracker) {
	t.Helper()
	for _, in := range inbounds {
		for _, user := range []string{kt.UserA, kt.UserB} {
			tr.Kick(in, user)
			if left := kt.WaitConns(t, tr, in, user, 0, 5*time.Second); len(left) != 0 {
				t.Fatalf("%s@%s 还剩 %d 条连接", user, in, len(left))
			}
		}
	}
}

type clients struct {
	t *testing.T
	s *kt.Server
	m map[string]*kt.Client
}

func (c *clients) get(user, inbound string) *kt.Client {
	if c.m == nil {
		c.m = map[string]*kt.Client{}
	}
	key := user + "@" + inbound
	if c.m[key] == nil {
		c.m[key] = kt.StartClient(c.t, c.s, user, inbound)
	}
	return c.m[key]
}

// 第 1 项：按凭据限速（agent-kernel「按凭据限速」的七条用例加 UDP）。
func TestFalsificationLimit(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	cl := &clients{t: t, s: s}

	// 基线：B 不限速、单独跑一个时间窗，两个入站各量一次。
	baseline := map[string]float64{}
	for _, in := range inbounds {
		f := kt.Download(t, cl.get(kt.UserB, in), 1, bLoad, 0)
		time.Sleep(prof.warmup)
		baseline[in] = f.Meter.Mbps(prof.window)
		f.Stop()
		t.Logf("结果（%s）基线 %s：B 不限速 %.2f Mbps", prof.name, in, baseline[in])
		if baseline[in] < 30 {
			t.Fatalf("%s 上 B 的基线只有 %.2f Mbps，负载是 40 Mbps，链路容量不够", in, baseline[in])
		}
	}
	for _, in := range inbounds {
		if err := tr.Set(in, kt.UserA, tracker.SourceStatic, mbps(limitMbps), time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	checkB := func(t *testing.T, in string, got float64) {
		t.Helper()
		if got < 0.9*baseline[in] {
			t.Errorf("%s 上 B 只有 %.2f Mbps，低于基线 %.2f 的 90%%", in, got, baseline[in])
		}
	}

	for _, in := range inbounds {
		name := map[string]string{kt.InVLESS: "1. VLESS 上的 TCP", kt.InHY2: "2. Hysteria2 上"}[in]
		t.Run(name, func(t *testing.T) {
			settle(t, tr)
			a := downloads(t, cl.get(kt.UserA, in), 4)
			b := kt.Download(t, cl.get(kt.UserB, in), 1, bLoad, 0)
			defer stopAll(append(a, b)...)
			time.Sleep(prof.warmup)
			got := measure(prof.window, meters(a...), meters(b))
			t.Logf("结果（%s）%s：A 合计 %.2f Mbps（目标 5），B %.2f Mbps", prof.name, name, got[0], got[1])
			if !near(got[0], limitMbps) {
				t.Errorf("A 合计 %.2f Mbps，不在 5 Mbps 的 ±20%%", got[0])
			}
			checkB(t, in, got[1])
		})
	}

	t.Run("3. 两个入站一起", func(t *testing.T) {
		settle(t, tr)
		a1 := downloads(t, cl.get(kt.UserA, kt.InVLESS), 4)
		a2 := downloads(t, cl.get(kt.UserA, kt.InHY2), 4)
		b1 := kt.Download(t, cl.get(kt.UserB, kt.InVLESS), 1, bLoad, 0)
		b2 := kt.Download(t, cl.get(kt.UserB, kt.InHY2), 1, bLoad, 0)
		defer stopAll(append(append(a1, a2...), b1, b2)...)
		time.Sleep(prof.warmup)
		got := measure(prof.window, meters(a1...), meters(a2...), meters(b1), meters(b2))
		t.Logf("结果（%s）3. 两个入站一起：A@VLESS %.2f、A@Hysteria2 %.2f Mbps（各自目标 5），B %.2f / %.2f Mbps", prof.name, got[0], got[1], got[2], got[3])
		if !near(got[0], limitMbps) || !near(got[1], limitMbps) {
			t.Errorf("两个入站应当各自约 5 Mbps：%.2f / %.2f", got[0], got[1])
		}
		checkB(t, kt.InVLESS, got[2])
		checkB(t, kt.InHY2, got[3])
	})

	t.Run("4. 上下行合计", func(t *testing.T) {
		settle(t, tr)
		c := cl.get(kt.UserA, kt.InVLESS)
		down := downloads(t, c, 2)
		up := []*kt.Flow{kt.Upload(t, s, c, 1, "case4-1", 0, 0), kt.Upload(t, s, c, 1, "case4-2", 0, 0)}
		b := kt.Download(t, cl.get(kt.UserB, kt.InVLESS), 1, bLoad, 0)
		defer stopAll(append(append(down, up...), b)...)
		time.Sleep(prof.warmup)
		got := measure(prof.window, meters(down...), meters(up...), meters(b))
		t.Logf("结果（%s）4. 上下行合计：A 下行 %.2f + 上行 %.2f = %.2f Mbps（目标 5），B %.2f Mbps", prof.name, got[0], got[1], got[0]+got[1], got[2])
		if !near(got[0]+got[1], limitMbps) {
			t.Errorf("上下行合计 %.2f Mbps，不在 5 Mbps 的 ±20%%", got[0]+got[1])
		}
		checkB(t, kt.InVLESS, got[2])
	})

	t.Run("UDP 也受同一个桶限制", func(t *testing.T) {
		settle(t, tr)
		f := kt.UDPDownload(t, cl.get(kt.UserA, kt.InVLESS), 1, mbps(20), prof.warmup+prof.window+5*time.Second)
		defer f.Stop()
		time.Sleep(prof.warmup)
		got := f.Meter.Mbps(prof.window)
		t.Logf("结果（%s）UDP：A 在 VLESS 上 %.2f Mbps（服务端按 20 Mbps 发，目标 5）", prof.name, got)
		if !near(got, limitMbps) {
			t.Errorf("UDP %.2f Mbps，不在 5 Mbps 的 ±20%%", got)
		}
	})

	// 上下行共用一个桶由用例 4 断言（两个方向在同一个时间窗里合计）；这里断言 TCP 与 UDP 也是同一个桶：
	// 各有一个 5 Mbps 的桶的话，合计会到 10 Mbps 左右。
	t.Run("TCP 与 UDP 共用一个桶", func(t *testing.T) {
		settle(t, tr)
		c := cl.get(kt.UserA, kt.InVLESS)
		tcp := downloads(t, c, 4)
		udp := kt.UDPDownload(t, c, 1, mbps(20), prof.warmup+prof.window+5*time.Second)
		defer stopAll(append(tcp, udp)...)
		time.Sleep(prof.warmup)
		got := measure(prof.window, meters(tcp...), meters(udp))
		t.Logf("结果（%s）TCP 与 UDP 一起跑：A 在 VLESS 上 TCP %.2f + UDP %.2f = %.2f Mbps（目标 5）", prof.name, got[0], got[1], got[0]+got[1])
		if !near(got[0]+got[1], limitMbps) {
			t.Errorf("TCP 与 UDP 合计 %.2f Mbps，不在 5 Mbps 的 ±20%%", got[0]+got[1])
		}
		if got[0] == 0 || got[1] == 0 {
			t.Errorf("时间窗里 TCP 与 UDP 都应当有数据：TCP %.2f、UDP %.2f Mbps", got[0], got[1])
		}
	})

	t.Run("5-7. 改值、加限速、撤掉，都作用在已有连接上", func(t *testing.T) {
		settle(t, tr)
		a := downloads(t, cl.get(kt.UserA, kt.InVLESS), 4)
		b := kt.Download(t, cl.get(kt.UserB, kt.InVLESS), 1, bLoad, 0)
		defer stopAll(append(a, b)...)
		time.Sleep(prof.warmup)
		aIDs, bIDs := connIDs(tr, kt.InVLESS, kt.UserA), connIDs(tr, kt.InVLESS, kt.UserB)
		sameConns := func(step string) {
			t.Helper()
			if connIDs(tr, kt.InVLESS, kt.UserA) != aIDs || connIDs(tr, kt.InVLESS, kt.UserB) != bIDs {
				t.Fatalf("%s：连接变了，说明发生了重连", step)
			}
		}

		if err := tr.Set(kt.InVLESS, kt.UserA, tracker.SourceStatic, mbps(10), time.Time{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(applyWait)
		first := measure(firstWindow, meters(a...))[0]
		got := measure(prof.window, meters(a...))[0]
		t.Logf("结果（%s）5. A 改成 10 Mbps，%v 后紧接着的 %v：%.2f Mbps，随后 %v：%.2f Mbps", prof.name, applyWait, firstWindow, first, prof.window, got)
		if !near(first, 10) || !near(got, 10) {
			t.Errorf("改成 10 Mbps 后 %.2f / %.2f Mbps，不在 ±20%%", first, got)
		}
		sameConns("5")

		if err := tr.Set(kt.InVLESS, kt.UserB, tracker.SourceMaster, mbps(limitMbps), time.Time{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(applyWait)
		first = measure(firstWindow, meters(b))[0]
		got = measure(prof.window, meters(b))[0]
		t.Logf("结果（%s）6. B 中途加主控临时 5 Mbps，%v 后紧接着的 %v：%.2f Mbps，随后 %v：%.2f Mbps", prof.name, applyWait, firstWindow, first, prof.window, got)
		if !near(first, limitMbps) || !near(got, limitMbps) {
			t.Errorf("加限速后 B %.2f / %.2f Mbps，不在 5 Mbps 的 ±20%%", first, got)
		}
		sameConns("6")

		if err := tr.Unset(kt.InVLESS, kt.UserB, tracker.SourceMaster); err != nil {
			t.Fatal(err)
		}
		time.Sleep(applyWait)
		first = measure(firstWindow, meters(b))[0]
		got = measure(prof.window, meters(b))[0]
		t.Logf("结果（%s）7. 撤掉 B 的主控临时，%v 后紧接着的 %v：%.2f Mbps，随后 %v：%.2f Mbps（基线 %.2f）", prof.name, applyWait, firstWindow, first, prof.window, got, baseline[kt.InVLESS])
		checkB(t, kt.InVLESS, first)
		checkB(t, kt.InVLESS, got)
		sameConns("7")
	})
}

// 第 2 项：按凭据识别连接（agent-kernel「按凭据识别连接」）。A 的 TCP 走 out1、UDP 走 out2，B 正好反过来，
// 记错凭据的连接会对不上出站。每个（用户，入站）的客户端经自己的 Relay 连服务端，服务端看到的对端就是这个 Relay
// 连过去用的本地地址，清单里的对端要和它逐条对上：既核对了对端，也核对了凭据归属。
//   - VLESS 每条连接一个 socket（UDP 也是一条流一条 TCP 连接）：对端与 Relay 的记录一一对应，没有重复，
//     而且每条连接的网络类型与 Relay 从这条上游连接的 VLESS 请求头认出来的一致；
//   - Hysteria2 的流共用客户端的一条 QUIC 连接：Relay 只记下一个地址，每条连接的对端都是它。
func TestFalsificationConnections(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	sinkOf := map[string][2]int{kt.UserA: {1, 2}, kt.UserB: {2, 1}} // {TCP 去的, UDP 去的}
	outOf := map[int]string{1: kt.Out1, 2: kt.Out2}
	relays := map[string]*kt.Relay{}
	for _, user := range []string{kt.UserA, kt.UserB} {
		for _, in := range inbounds {
			network, target := "tcp", s.VLESSPort
			if in == kt.InHY2 {
				network, target = "udp", s.HY2Port
			}
			r := kt.StartRelay(t, network, target)
			relays[user+"@"+in] = r
			c := kt.StartClientVia(t, s, user, in, r.Port)
			for i := 0; i < 3; i++ {
				kt.Echo(t, c, sinkOf[user][0])
			}
			for i := 0; i < 2; i++ {
				kt.EchoUDP(t, c, sinkOf[user][1])
			}
		}
	}
	for _, user := range []string{kt.UserA, kt.UserB} {
		for _, in := range inbounds {
			got := kt.WaitConns(t, tr, in, user, 5, 5*time.Second)
			counts := map[string]int{}
			var sources []string
			for _, c := range got {
				sources = append(sources, c.Source)
				if in == kt.InVLESS && relays[user+"@"+in].Network(c.Source) != c.Network {
					t.Errorf("%s@%s 的一条 %s 连接的对端 %s，在 Relay 那边装的是 %q", user, in, c.Network, c.Source, relays[user+"@"+in].Network(c.Source))
				}
				counts[c.Network]++
				wantOut := outOf[sinkOf[user][0]]
				if c.Network == "udp" {
					wantOut = outOf[sinkOf[user][1]]
				}
				if c.Outbound != wantOut {
					t.Errorf("%s@%s 的一条 %s 连接走的是 %s，应当是 %s：记错了凭据", user, in, c.Network, c.Outbound, wantOut)
				}
			}
			peers := relays[user+"@"+in].Peers()
			sort.Strings(sources)
			if in == kt.InVLESS && strings.Join(sources, " ") != strings.Join(peers, " ") {
				t.Errorf("%s@%s 的对端 %v 与 Relay 记下的 %v 对不上", user, in, sources, peers)
			}
			if in == kt.InHY2 {
				same := len(peers) == 1
				for _, src := range sources {
					same = same && src == peers[0]
				}
				if !same {
					t.Errorf("%s@%s 的对端 %v 应当都是 Relay 记下的唯一地址 %v", user, in, sources, peers)
				}
			}
			t.Logf("结果（%s）识别连接 %s@%s：TCP %d 条、UDP %d 条", prof.name, user, in, counts["tcp"], counts["udp"])
			if counts["tcp"] != 3 || counts["udp"] != 2 {
				t.Errorf("%s@%s 应当是 3 条 TCP、2 条 UDP：%+v", user, in, got)
			}
		}
	}
}

// 第 3 项：按凭据踢线（agent-kernel「按凭据踢线」）。
func TestFalsificationKick(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	cl := &clients{t: t, s: s}
	long := 5 * time.Minute
	type pair struct{ tcp, udp *kt.Flow }
	start := func(user, in string) pair {
		c := cl.get(user, in)
		return pair{kt.Download(t, c, 1, mbps(8), 0), kt.UDPDownload(t, c, 2, mbps(8), long)}
	}
	aV, aH, bV := start(kt.UserA, kt.InVLESS), start(kt.UserA, kt.InHY2), start(kt.UserB, kt.InVLESS)
	defer stopAll(aV.tcp, aV.udp, aH.tcp, aH.udp, bV.tcp, bV.udp)
	time.Sleep(prof.warmup)
	flowing := func(f *kt.Flow) bool {
		before := f.Meter.Bytes()
		time.Sleep(time.Second)
		return f.Meter.Bytes() > before
	}
	stopped := func(f *kt.Flow) bool { return !flowing(f) }
	for name, f := range map[string]*kt.Flow{"A@VLESS TCP": aV.tcp, "A@VLESS UDP": aV.udp, "A@Hysteria2 TCP": aH.tcp, "A@Hysteria2 UDP": aH.udp, "B TCP": bV.tcp, "B UDP": bV.udp} {
		if !flowing(f) {
			t.Fatalf("踢线之前 %s 应当在跑", name)
		}
	}

	t0 := time.Now()
	n := tr.Kick(kt.InVLESS, kt.UserA)
	select {
	case <-aV.tcp.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("A@VLESS 的 TCP 3 秒内没断")
	}
	tcpGone := time.Since(t0)
	time.Sleep(3*time.Second - time.Since(t0))
	if !stopped(aV.udp) {
		t.Error("A@VLESS 的 UDP 3 秒后还在收数据")
	}
	t.Logf("结果（%s）踢 A@VLESS：断开 %d 条，TCP %v 内断开，UDP 3 秒后不再收到数据", prof.name, n, tcpGone.Round(time.Microsecond))
	for name, f := range map[string]*kt.Flow{"A@Hysteria2 TCP": aH.tcp, "A@Hysteria2 UDP": aH.udp, "B TCP": bV.tcp, "B UDP": bV.udp} {
		if !flowing(f) {
			t.Errorf("%s 不该受影响", name)
		}
	}
	kt.Echo(t, cl.get(kt.UserA, kt.InVLESS), 1) // 踢线不是封禁：随后能重新连上

	n = tr.KickUser(kt.UserA)
	time.Sleep(3 * time.Second)
	if !stopped(aH.tcp) || !stopped(aH.udp) {
		t.Error("踢 A 的全部凭据后，A@Hysteria2 应当断开")
	}
	if !flowing(bV.tcp) || !flowing(bV.udp) {
		t.Error("踢 A 的全部凭据不该影响 B")
	}
	t.Logf("结果（%s）踢 A 的全部凭据：断开 %d 条，B 不受影响", prof.name, n)
}

// 第 4 项：三维流量计数（agent-kernel「三维流量计数」）。五条流交叉跑，每个（入站，出站，凭据）组合与实际值的误差不超过 1%。
func TestFalsificationCounting(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	cl := &clients{t: t, s: s}
	mb := prof.mib
	header := func(f string, args ...any) int64 { return int64(len(fmt.Sprintf(f, args...))) }
	type want struct{ up, down int64 }
	expect := map[tracker.CounterKey]want{
		{Inbound: kt.InVLESS, Outbound: kt.Out1, User: kt.UserA}: {header("D 0 %d\n", 100*mb), 100 * mb},
		{Inbound: kt.InVLESS, Outbound: kt.Out2, User: kt.UserA}: {header("U a-up\n") + 60*mb, 0},
		{Inbound: kt.InHY2, Outbound: kt.Out2, User: kt.UserA}:   {header("D 0 %d\n", 40*mb), 40 * mb},
		{Inbound: kt.InVLESS, Outbound: kt.Out2, User: kt.UserB}: {header("D 0 %d\n", 30*mb), 30 * mb},
		{Inbound: kt.InHY2, Outbound: kt.Out1, User: kt.UserB}:   {header("U b-up\n") + 20*mb, 0},
	}
	for _, user := range []string{kt.UserA, kt.UserB} {
		for _, in := range inbounds {
			cl.get(user, in) // 先起好客户端，下面的用时只算传输
		}
	}
	t0 := time.Now()
	flows := []*kt.Flow{
		kt.Download(t, cl.get(kt.UserA, kt.InVLESS), 1, 0, 100*mb),
		kt.Upload(t, s, cl.get(kt.UserA, kt.InVLESS), 2, "a-up", 0, 60*mb),
		kt.Download(t, cl.get(kt.UserA, kt.InHY2), 2, 0, 40*mb),
		kt.Download(t, cl.get(kt.UserB, kt.InVLESS), 2, 0, 30*mb),
		kt.Upload(t, s, cl.get(kt.UserB, kt.InHY2), 1, "b-up", 0, 20*mb),
	}
	waitDone(t, 5*time.Minute, flows...)
	elapsed := time.Since(t0)
	// 五条流都不限速，这个数是经过包装层的吞吐下限（按最后一条流跑完算），用来看关掉快路径之后的代价。
	t.Logf("结果（%s）不限速吞吐：五条流合计 %d 字节，用时 %v，合计不低于 %.0f Mbps（本机回环）", prof.name, 250*mb, elapsed.Round(time.Millisecond), float64(250*mb)*8/elapsed.Seconds()/1e6)
	time.Sleep(500 * time.Millisecond) // 等服务端那一侧的连接也走完
	got := map[tracker.CounterKey]want{}
	for _, c := range tr.Snapshot().Counts {
		got[c.CounterKey] = want{c.Up, c.Down}
	}
	for k, w := range expect {
		g := got[k]
		t.Logf("结果（%s）计数 %s→%s %s：上行 %d（实际 %d）、下行 %d（实际 %d）", prof.name, k.Inbound, k.Outbound, k.User, g.up, w.up, g.down, w.down)
		if !within1(g.up, w.up) || !within1(g.down, w.down) {
			t.Errorf("%+v：计数 %+v，实际 %+v，误差超过 1%%", k, g, w)
		}
	}
	for k, g := range got {
		if _, ok := expect[k]; !ok && (g.up != 0 || g.down != 0) {
			t.Errorf("没跑过的组合 %+v 应当为零：%+v", k, g)
		}
	}
}

func within1(got, want int64) bool {
	if want == 0 {
		return got == 0
	}
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return float64(diff) <= 0.01*float64(want)
}

// 第 5 项：重启基线（agent-kernel「重启基线」）：同进程内核重启与模拟 satchel-agent 进程重启两种。
func TestFalsificationRestart(t *testing.T) {
	for _, mode := range []string{"同进程内核重启", "换了进程"} {
		t.Run(mode, func(t *testing.T) {
			s := kt.StartServer(t)
			cl := &clients{t: t, s: s}
			mb := prof.mib
			k := tracker.CounterKey{Inbound: kt.InVLESS, Outbound: kt.Out1, User: kt.UserA}
			var acc kt.Accumulator
			acc.Add(s.Tracker().Snapshot())

			waitDone(t, 5*time.Minute, kt.Download(t, cl.get(kt.UserA, kt.InVLESS), 1, 0, 100*mb))
			time.Sleep(300 * time.Millisecond)
			acc.Add(s.Tracker().Snapshot())
			if mode == "同进程内核重启" {
				s.RestartKernel(t)
			} else {
				s.RestartProcess(t)
			}
			acc.Add(s.Tracker().Snapshot())
			waitDone(t, 5*time.Minute, kt.Download(t, cl.get(kt.UserA, kt.InVLESS), 1, 0, 50*mb))
			time.Sleep(300 * time.Millisecond)
			acc.Add(s.Tracker().Snapshot())

			_, down := acc.Total(k)
			t.Logf("结果（%s）重启基线（%s）：累计下行 %d（实际 %d），重启 %d 次", prof.name, mode, down, 150*mb, acc.Restarts)
			if !within1(down, 150*mb) || acc.Restarts != 1 {
				t.Errorf("累计应当是 %d、重启 1 次：%d，%d 次", 150*mb, down, acc.Restarts)
			}
		})
	}
}

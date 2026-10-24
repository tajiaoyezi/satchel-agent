package tracker

import (
	"context"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakeOutbound 只用到 Tag()。
type fakeOutbound struct {
	adapter.Outbound
	tag string
}

func (o fakeOutbound) Tag() string { return o.tag }

func meta(inbound, user string) adapter.InboundContext {
	return metaFrom(inbound, user, "127.0.0.1:40000")
}

func metaFrom(inbound, user, source string) adapter.InboundContext {
	return adapter.InboundContext{Inbound: inbound, User: user, Source: M.ParseSocksaddr(source)}
}

// design 第 3 条：包装层不能满足 sing 的拷贝会据以拆掉包装层的任何接口，否则限速与计数会被快路径绕开。
func TestWrappersAreOpaque(t *testing.T) {
	forbidden := map[string]reflect.Type{
		"ReadCounter":           reflect.TypeOf((*N.ReadCounter)(nil)).Elem(),
		"WriteCounter":          reflect.TypeOf((*N.WriteCounter)(nil)).Elem(),
		"PacketReadCounter":     reflect.TypeOf((*N.PacketReadCounter)(nil)).Elem(),
		"PacketWriteCounter":    reflect.TypeOf((*N.PacketWriteCounter)(nil)).Elem(),
		"ReaderWithUpstream":    reflect.TypeOf((*N.ReaderWithUpstream)(nil)).Elem(),
		"WriterWithUpstream":    reflect.TypeOf((*N.WriterWithUpstream)(nil)).Elem(),
		"WithUpstreamReader":    reflect.TypeOf((*N.WithUpstreamReader)(nil)).Elem(),
		"WithUpstreamWriter":    reflect.TypeOf((*N.WithUpstreamWriter)(nil)).Elem(),
		"common.WithUpstream":   reflect.TypeOf((*common.WithUpstream)(nil)).Elem(),
		"ReadWaiter":            reflect.TypeOf((*N.ReadWaiter)(nil)).Elem(),
		"ReadWaitCreator":       reflect.TypeOf((*N.ReadWaitCreator)(nil)).Elem(),
		"PacketReadWaiter":      reflect.TypeOf((*N.PacketReadWaiter)(nil)).Elem(),
		"PacketReadWaitCreator": reflect.TypeOf((*N.PacketReadWaitCreator)(nil)).Elem(),
		"CachedReader":          reflect.TypeOf((*N.CachedReader)(nil)).Elem(),
		"syscall.Conn":          reflect.TypeOf((*syscall.Conn)(nil)).Elem(),
		"io.ReaderFrom":         reflect.TypeOf((*io.ReaderFrom)(nil)).Elem(),
		"io.WriterTo":           reflect.TypeOf((*io.WriterTo)(nil)).Elem(),
	}
	for _, w := range []any{&tcpConn{}, &packetConn{}} {
		for name, iface := range forbidden {
			if reflect.TypeOf(w).Implements(iface) {
				t.Errorf("%T 不能实现 %s", w, name)
			}
		}
	}
	// 转发的握手回报要在，否则入站收不到「出站已连上」。
	for _, w := range []any{&tcpConn{}, &packetConn{}} {
		if _, ok := w.(N.HandshakeSuccess); !ok {
			t.Errorf("%T 应当转发 HandshakeSuccess", w)
		}
		if _, ok := w.(N.HandshakeFailure); !ok {
			t.Errorf("%T 应当转发 HandshakeFailure", w)
		}
	}
	if _, ok := any(&tcpConn{}).(N.ConnHandshakeSuccess); !ok {
		t.Error("tcpConn 应当转发 ConnHandshakeSuccess")
	}
	if _, ok := any(&tcpConn{}).(N.EarlyWriter); !ok {
		t.Error("tcpConn 应当转发 NeedHandshakeForWrite")
	}
	if _, ok := any(&packetConn{}).(N.PacketConnHandshakeSuccess); !ok {
		t.Error("packetConn 应当转发 PacketConnHandshakeSuccess")
	}
	// 半关闭要转发，否则 sing-box 把半关闭变成整条关闭。
	if _, ok := any(&tcpConn{}).(N.WriteCloser); !ok {
		t.Error("tcpConn 应当转发 CloseWrite")
	}
	// 缓冲区的预留量要转发，否则拷贝分配的缓冲区前面不给包头留地方。
	for _, w := range []any{&tcpConn{}, &packetConn{}} {
		_, front := w.(N.FrontHeadroom)
		_, rear := w.(N.RearHeadroom)
		_, overhead := w.(N.ReaderOverhead)
		_, rmtu := w.(N.ReaderWithMTU)
		_, wmtu := w.(N.WriterWithMTU)
		if !front || !rear || !overhead || !rmtu || !wmtu {
			t.Errorf("%T 应当转发 FrontHeadroom、RearHeadroom、ReaderOverhead、ReaderMTU、WriterMTU", w)
		}
	}
}

// agent-kernel「按凭据限速」：三份来源取最小、0 不参与、设 0 与撤掉不同。
func TestSourcesTakeMinimum(t *testing.T) {
	tr := New()
	check := func(step string, want int64, wantLimited bool) {
		t.Helper()
		if got, limited := tr.Effective("in1", "A"); got != want || limited != wantLimited {
			t.Fatalf("%s：生效值应当是 %d（限速 %v），得到 %d（%v）", step, want, wantLimited, got, limited)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tr.Set("in1", "A", SourceStatic, 8_000_000, time.Time{}))
	must(tr.Set("in1", "A", SourceMaster, 3_000_000, time.Time{}))
	check("静态 8、主控临时 3", 3_000_000, true)
	must(tr.Set("in1", "A", SourceMaster, 0, time.Time{}))
	check("主控临时设成 0", 8_000_000, true)
	must(tr.Unset("in1", "A", SourceMaster))
	check("撤掉主控临时", 8_000_000, true)
	must(tr.Set("in1", "A", SourceStatic, 0, time.Time{}))
	check("静态也设成 0", 0, false)
	must(tr.Set("in1", "A", SourceNodeRule, 2_000_000, time.Time{}))
	check("节点规则临时 2", 2_000_000, true)

	if err := tr.Set("in1", "", SourceStatic, 1, time.Time{}); err != ErrNoUser {
		t.Fatalf("凭据为空应当拒绝：%v", err)
	}
	if err := tr.Set("in1", "A", Source(9), 1, time.Time{}); err == nil {
		t.Fatal("不认识的来源应当拒绝")
	}
	if err := tr.Set("in1", "A", SourceStatic, -1, time.Time{}); err == nil {
		t.Fatal("负数应当拒绝")
	}
}

// agent-kernel「截止时间到了自动撤掉」；中途改过的槽位不被旧定时器撤掉。
func TestSourceDeadline(t *testing.T) {
	tr := New()
	_ = tr.Set("in1", "A", SourceStatic, 8_000_000, time.Time{})
	_ = tr.Set("in1", "A", SourceMaster, 3_000_000, time.Now().Add(150*time.Millisecond))
	if got, _ := tr.Effective("in1", "A"); got != 3_000_000 {
		t.Fatalf("截止之前应当是 3：%d", got)
	}
	time.Sleep(400 * time.Millisecond)
	if got, _ := tr.Effective("in1", "A"); got != 8_000_000 {
		t.Fatalf("截止之后应当回到 8：%d", got)
	}
	// 带截止时间设了之后又改成不带截止时间：旧定时器不能撤掉新值。
	_ = tr.Set("in1", "A", SourceMaster, 3_000_000, time.Now().Add(150*time.Millisecond))
	_ = tr.Set("in1", "A", SourceMaster, 4_000_000, time.Time{})
	time.Sleep(400 * time.Millisecond)
	if got, _ := tr.Effective("in1", "A"); got != 4_000_000 {
		t.Fatalf("改过之后旧的截止时间不该生效：%d", got)
	}
}

// 桶回收之后新建的桶 seq 从头数：第一次设值的定时器回调迟到（已经触发、在等锁），不能撤掉回收后再设的值。
func TestStaleDeadlineAfterReap(t *testing.T) {
	tr := New()
	key := Key{"in1", "A"}
	_ = tr.Set("in1", "A", SourceMaster, 3_000_000, time.Now().Add(time.Hour))
	old := tr.buckets[key]
	_ = tr.Unset("in1", "A", SourceMaster) // 没有连接，桶被回收
	_ = tr.Set("in1", "A", SourceMaster, 8_000_000, time.Time{})
	tr.expire(key, old, SourceMaster, 1) // 模拟第一次设值的回调这时才拿到锁
	if got, _ := tr.Effective("in1", "A"); got != 8_000_000 {
		t.Fatalf("迟到的回调撤掉了回收后再设的值：%d", got)
	}
}

// 没有连接、三份来源都撤掉之后回收桶；有连接时不回收。
func TestBucketReaped(t *testing.T) {
	tr := New()
	_ = tr.Set("in1", "A", SourceMaster, 1_000_000, time.Time{})
	_ = tr.Unset("in1", "A", SourceMaster)
	if len(tr.buckets) != 0 {
		t.Fatalf("没有连接也没有来源时应当回收：%d", len(tr.buckets))
	}
	a, b := net.Pipe()
	defer b.Close()
	w := tr.RoutedConnection(t.Context(), a, meta("in1", "A"), nil, fakeOutbound{tag: "out1"})
	if len(tr.buckets) != 1 {
		t.Fatal("不限速的凭据也要挂桶")
	}
	w.Close()
	if len(tr.buckets) != 0 {
		t.Fatal("最后一条连接关掉、没有来源时应当回收")
	}
}

// 改了速率之后，正在跑的读写立刻用上新速率（agent-kernel 场景 5、6、7 的机制）。
func TestRateChangeAppliesToRunningConn(t *testing.T) {
	tr := New()
	_ = tr.Set("in1", "A", SourceMaster, 400_000, time.Time{}) // 50 KB/s
	a, b := net.Pipe()
	defer b.Close()
	w := tr.RoutedConnection(t.Context(), a, meta("in1", "A"), nil, fakeOutbound{tag: "out1"})
	defer w.Close()
	go io.Copy(io.Discard, b)
	measure := func(d time.Duration) float64 {
		data := make([]byte, 1024)
		deadline := time.Now().Add(d)
		n := 0
		for time.Now().Before(deadline) {
			m, err := w.Write(data)
			n += m
			if err != nil {
				t.Fatal(err)
			}
		}
		return float64(n) / d.Seconds()
	}
	if got := measure(time.Second); got < 35_000 || got > 70_000 {
		t.Fatalf("50 KB/s 时实测 %.0f B/s", got)
	}
	_ = tr.Set("in1", "A", SourceMaster, 1_600_000, time.Time{}) // 200 KB/s
	if got := measure(time.Second); got < 150_000 || got > 260_000 {
		t.Fatalf("改成 200 KB/s 后实测 %.0f B/s", got)
	}
	_ = tr.Unset("in1", "A", SourceMaster)
	if got := measure(300 * time.Millisecond); got < 1_000_000 {
		t.Fatalf("撤掉后应当不限速，实测 %.0f B/s", got)
	}
}

// 内层不支持半关闭（net.Pipe）时，CloseWrite 整条关掉：对端读到 EOF，连接从清单里注销。支持时的转发由 kernel 的集成测试覆盖。
func TestCloseWriteFallback(t *testing.T) {
	tr := New()
	a, b := net.Pipe()
	defer b.Close()
	w := tr.RoutedConnection(t.Context(), a, meta("in1", "A"), nil, fakeOutbound{tag: "out1"})
	if err := w.(N.WriteCloser).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("对端应当读到 EOF：%v", err)
	}
	if got := tr.Connections("in1", "A"); len(got) != 0 {
		t.Fatalf("整条关掉之后应当注销：%+v", got)
	}
}

// 排着队等额度的读写在生效值变化时立刻用上新值，与排了多少无关。只改速率、不管已经排好的预约的话（x/time/rate 的 SetLimit 就是这样），
// 5 Mbps 下排 512 块 16 KiB 要排十几秒；撤掉限速后它们要在 1 秒内全部返回。
func TestQueuedWaitersFollowChange(t *testing.T) {
	b := newBucket()
	b.set(SourceStatic, 5_000_000, time.Time{}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 512; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = b.take(t.Context(), burstBytes) }()
	}
	time.Sleep(200 * time.Millisecond)
	b.unset(SourceStatic, 0)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("撤掉限速 1 秒后还有读写按旧速率排着队")
	}
}

// 降速时排队的读写按新速率重取，不留旧预约的欠账：改成 5 Mbps 后的 1 秒里放行约 5 Mbps 的量，不会断流。
func TestQueuedWaitersSlowDown(t *testing.T) {
	b := newBucket()
	b.set(SourceStatic, 10_000_000, time.Time{}, nil)
	var finished atomic.Int64
	for i := 0; i < 128; i++ {
		go func() {
			if b.take(t.Context(), burstBytes) == nil {
				finished.Add(1)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	b.set(SourceStatic, 5_000_000, time.Time{}, nil)
	before := finished.Load()
	time.Sleep(time.Second)
	got := float64((finished.Load()-before)*burstBytes) * 8 / 1e6
	if got < 4 || got > 6 {
		t.Fatalf("改成 5 Mbps 后的 1 秒放行了 %.2f Mbps", got)
	}
}

// 等额度的读写被取消（连接关了）时不给这份凭据留欠账。x/time/rate 的 Cancel 只有倒序撤才退得干净，这里按先后顺序取消三个等待，
// 之后新的一次取额度只等自己那一块的时间（约 1 秒）；背着前面的欠账的话要等 3 秒左右。
func TestCancelledWaitersLeaveNoDebt(t *testing.T) {
	b := newBucket()
	b.set(SourceStatic, 4096, time.Time{}, nil) // 512 字节每秒，一块 512 字节要 1 秒
	b.mu.Lock()
	b.tokens = 0 // 桶里原来有额度的话先清零
	b.mu.Unlock()
	var cancels []context.CancelFunc
	var dones []chan struct{}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = b.take(ctx, minChunk); close(done) }()
		cancels, dones = append(cancels, cancel), append(dones, done)
		time.Sleep(20 * time.Millisecond) // 按顺序排进去
	}
	for i := range cancels {
		cancels[i]()
		<-dones[i]
	}
	start := time.Now()
	if err := b.take(t.Context(), minChunk); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("取消三个等待之后，新的一次取额度等了 %v：背着前面的欠账", d)
	}
}

// 频繁取消不拖累别的连接：一条流一直取额度，同一个 5 Mbps 的桶上每 10 ms 建一个等待、10 ms 后取消。
// 取消只退回自己没用上的那一块，不清空别的等待攒下的进度，1 秒里放行的合计仍约 5 Mbps，也不多放。
func TestFrequentCancelsDoNotStarve(t *testing.T) {
	b := newBucket()
	b.set(SourceStatic, 5_000_000, time.Time{}, nil)
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	var got atomic.Int64
	go func() {
		for b.take(ctx, burstBytes) == nil {
			got.Add(burstBytes)
		}
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		go func() {
			if b.take(short, burstBytes) == nil {
				got.Add(burstBytes)
			}
			cancel()
		}()
		<-tick.C
	}
	if mbps := float64(got.Load()) * 8 / 1e6; mbps < 4 || mbps > 6 {
		t.Fatalf("每 10 ms 取消一个等待，1 秒里合计放行 %.2f Mbps", mbps)
	}
}

// agent-kernel「按凭据识别连接」「按凭据踢线」「三维流量计数」的单元部分：连接清单、踢线、TCP 与 UDP 的计数与快照。
func TestConnectionsKickAndCounting(t *testing.T) {
	tr := New()
	pipes := func() (net.Conn, net.Conn) { return net.Pipe() }
	a1, b1 := pipes()
	a2, b2 := pipes()
	a3, b3 := pipes()
	defer b1.Close()
	defer b2.Close()
	defer b3.Close()
	vlessA := tr.RoutedConnection(t.Context(), a1, meta("in1", "A"), nil, fakeOutbound{tag: "out1"})
	// 每条连接的对端都不同，清单里的对端要逐条对得上。
	hy2A := tr.RoutedConnection(t.Context(), a2, metaFrom("in2", "A", "127.0.0.1:40001"), nil, fakeOutbound{tag: "out2"})
	vlessB := tr.RoutedConnection(t.Context(), a3, metaFrom("in1", "B", "127.0.0.1:40003"), nil, fakeOutbound{tag: "out1"})
	udp := &fakePacketConn{}
	udpA := tr.RoutedPacketConnection(t.Context(), udp, metaFrom("in1", "A", "127.0.0.1:40002"), nil, fakeOutbound{tag: "out2"})

	if got := tr.Connections("in1", "A"); len(got) != 2 || got[0].Network != N.NetworkTCP || got[1].Network != N.NetworkUDP || got[0].Source != "127.0.0.1:40000" || got[1].Source != "127.0.0.1:40002" || got[1].Outbound != "out2" {
		t.Fatalf("in1 上 A 应当有一条 TCP、一条 UDP：%+v", got)
	}

	go func() { buf := make([]byte, 10); io.ReadFull(b1, buf) }()
	if _, err := vlessA.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	go func() { b1.Write(make([]byte, 7)) }()
	if _, err := io.ReadFull(vlessA, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	if err := udpA.WritePacket(buf.As(make([]byte, 5)), M.ParseSocksaddr("127.0.0.1:9")); err != nil {
		t.Fatal(err)
	}
	snap := tr.Snapshot()
	want := map[CounterKey][2]int64{
		{"in1", "out1", "A"}: {7, 10},
		{"in1", "out2", "A"}: {0, 5},
		{"in2", "out2", "A"}: {0, 0},
		{"in1", "out1", "B"}: {0, 0},
	}
	if len(snap.Counts) != len(want) || snap.BootID != tr.BootID() {
		t.Fatalf("快照不对：%+v", snap)
	}
	for _, c := range snap.Counts {
		if w := want[c.CounterKey]; c.Up != w[0] || c.Down != w[1] {
			t.Fatalf("%+v 应当是 上 %d 下 %d", c, w[0], w[1])
		}
	}

	if n := tr.Kick("in1", "A"); n != 2 {
		t.Fatalf("应当踢掉 in1 上 A 的两条：%d", n)
	}
	if !udp.closed || len(tr.Connections("in1", "A")) != 0 {
		t.Fatal("被踢的 TCP 与 UDP 都应当关掉、注销")
	}
	if h, v := tr.Connections("in2", "A"), tr.Connections("in1", "B"); len(h) != 1 || len(v) != 1 || h[0].Source != "127.0.0.1:40001" || v[0].Source != "127.0.0.1:40003" {
		t.Fatalf("别的入站与别的凭据不受影响，对端各自对得上：%+v %+v", h, v)
	}
	if n := tr.KickUser("A"); n != 1 {
		t.Fatalf("KickUser 应当再踢掉 in2 上的一条：%d", n)
	}
	_ = hy2A
	_ = vlessB
	// 计数在连接关掉之后照样留着。
	if c := tr.Snapshot().Counts; len(c) != 4 {
		t.Fatalf("计数不随连接关闭消失：%+v", c)
	}
}

// 凭据为空：照样登记与计数，不挂桶。
func TestEmptyUserCountedNotLimited(t *testing.T) {
	tr := New()
	a, b := net.Pipe()
	defer b.Close()
	w := tr.RoutedConnection(t.Context(), a, meta("in3", ""), nil, fakeOutbound{tag: "out1"})
	defer w.Close()
	if w.(*tcpConn).bucket != nil || len(tr.buckets) != 0 {
		t.Fatal("凭据为空不挂桶")
	}
	if len(tr.Connections("in3", "")) != 1 {
		t.Fatal("凭据为空照样登记")
	}
}

func TestGeneration(t *testing.T) {
	tr := New()
	tr.KernelStarted()
	tr.KernelStarted()
	if tr.Generation() != 2 || tr.Snapshot().Generation != 2 || New().BootID() == tr.BootID() {
		t.Fatal("内核代数与启动标识不对")
	}
}

type fakePacketConn struct{ closed bool }

func (f *fakePacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, io.EOF }
func (f *fakePacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	b.Release()
	return nil
}
func (f *fakePacketConn) Close() error                     { f.closed = true; return nil }
func (f *fakePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

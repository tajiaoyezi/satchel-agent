package limits

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/tracker"
)

const mbps = 1_000_000

func open(t *testing.T, path string, now func() time.Time) (*Store, *tracker.Tracker) {
	t.Helper()
	tr := tracker.New()
	s, err := Open(path, tr, now)
	if err != nil {
		t.Fatal(err)
	}
	return s, tr
}

// mustOK 返回一个取 Set / Unset 结果的函数：出错就让测试失败。
func mustOK(t *testing.T) func(xrpc.LimiterState, error) xrpc.LimiterState {
	return func(st xrpc.LimiterState, err error) xrpc.LimiterState {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
}

// 三份来源取最小、撤掉一份后由剩下的重新算；写进文件、权限 0600；换一个 tracker 读回来，状态与生效值不变。
func TestRoundTrip(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	s, tr := open(t, path, time.Now)
	deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	ok(s.Set("vless-in", "a", xrpc.SourceStatic, 10*mbps, nil))
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, &deadline))
	st := ok(s.Set("vless-in", "a", xrpc.SourceNodeRule, 8*mbps, nil))
	if !st.Limited || st.EffectiveBPS != 5*mbps || len(st.Sources) != 3 || st.Sources[1].Source != xrpc.SourceMaster || !st.Sources[1].Deadline.Equal(deadline) {
		t.Fatalf("三份来源应当取最小 5 Mbps：%+v", st)
	}
	if bps, _ := tr.Effective("vless-in", "a"); bps != 5*mbps {
		t.Fatalf("tracker 的生效值应当是 5 Mbps：%d", bps)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("状态文件应当是 0600：%v %v", info, err)
	}
	s2, tr2 := open(t, path, time.Now)
	if bps, limited := tr2.Effective("vless-in", "a"); !limited || bps != 5*mbps {
		t.Fatalf("读回来以后生效值应当仍是 5 Mbps：%d %v", bps, limited)
	}
	st = ok(s2.Unset("vless-in", "a", xrpc.SourceMaster))
	if st.EffectiveBPS != 8*mbps || len(st.Sources) != 2 {
		t.Fatalf("撤掉主控临时以后应当是 8 Mbps：%+v", st)
	}
	if st := ok(s2.Unset("vless-in", "a", xrpc.SourceMaster)); st.EffectiveBPS != 8*mbps {
		t.Fatalf("没设的来源再撤一次也算成功：%+v", st)
	}
	// 设成 0 与撤掉不同：0 仍在来源里、这一份不限速。
	st = ok(s2.Set("vless-in", "a", xrpc.SourceNodeRule, 0, nil))
	if st.EffectiveBPS != 10*mbps || len(st.Sources) != 2 || st.Sources[1].BPS != 0 {
		t.Fatalf("节点规则设成 0 以后应当只剩静态 10 Mbps 起作用：%+v", st)
	}
}

// 过期的来源不重放；下次写文件时不再出现。
func TestExpiredNotReplayed(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	start := time.Now()
	s, _ := open(t, path, func() time.Time { return start })
	deadline := start.Add(time.Minute)
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, &deadline))
	ok(s.Set("vless-in", "b", xrpc.SourceMaster, 3*mbps, nil))
	later := func() time.Time { return start.Add(2 * time.Minute) }
	_, tr2 := open(t, path, later)
	if _, limited := tr2.Effective("vless-in", "a"); limited {
		t.Fatal("过期的来源不应当重放")
	}
	if bps, _ := tr2.Effective("vless-in", "b"); bps != 3*mbps {
		t.Fatalf("没过期的应当照旧：%d", bps)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"credential": "a"`) || !strings.Contains(string(data), `"credential": "b"`) {
		t.Fatalf("启动时丢掉了过期的，文件里就不应当再有它：%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("重写之后仍是 0600：%v", info.Mode())
	}
}

// 重放之后，没过期的来源按原截止时间到期：重放时还剩 300 毫秒的那一份，到时 tracker 自己撤掉、回到不限速。
func TestReplayedDeadlineStillExpires(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	s, _ := open(t, path, time.Now)
	deadline := time.Now().Add(300 * time.Millisecond)
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, &deadline))
	_, tr := open(t, path, time.Now)
	if _, limited := tr.Effective("vless-in", "a"); !limited {
		t.Fatal("还没到期的来源应当重放")
	}
	time.Sleep(time.Until(deadline) + 200*time.Millisecond)
	if _, limited := tr.Effective("vless-in", "a"); limited {
		t.Fatal("重放的来源应当按原截止时间到期")
	}
}

// 写失败时什么都不改：tracker 的生效值与文件都和之前一样。
func TestSaveFailureChangesNothing(t *testing.T) {
	ok := mustOK(t)
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	s, tr := open(t, path, time.Now)
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, nil))
	before, _ := os.ReadFile(path)
	s.path = filepath.Join(dir, "missing", FileName) // 目录不存在，临时文件建不出来
	if _, err := s.Set("vless-in", "a", xrpc.SourceMaster, 1*mbps, nil); err == nil {
		t.Fatal("写不出文件时应当报错")
	}
	if _, err := s.Unset("vless-in", "a", xrpc.SourceMaster); err == nil {
		t.Fatal("写不出文件时撤销也应当报错")
	}
	if bps, _ := tr.Effective("vless-in", "a"); bps != 5*mbps {
		t.Fatalf("写失败时 tracker 不应当变：%d", bps)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("写失败时原来的文件不应当变")
	}
	s.path = path
	if st := ok(s.Set("vless-in", "a", xrpc.SourceStatic, 2*mbps, nil)); len(st.Sources) != 2 || st.EffectiveBPS != 2*mbps {
		t.Fatalf("内存里的状态也不应当被写失败的那次改掉：%+v", st)
	}
}

// 坏的状态文件：报错，但仍给出一个空的、能用的状态。
func TestCorruptFile(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	os.WriteFile(path, []byte("{"), 0o600)
	s, err := Open(path, tracker.New(), time.Now)
	if err == nil || s == nil {
		t.Fatalf("坏文件应当报错并给出空状态：%v %v", s, err)
	}
	if st := ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, nil)); st.EffectiveBPS != 5*mbps {
		t.Fatalf("空状态应当能接着用：%+v", st)
	}
}

// 截止时间在拿到锁之后再看一次：已经过了就回 ErrExpired，文件、tracker 与内存里的状态都不变。
func TestExpiredDeadlineRejectedUnderLock(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	start := time.Now()
	s, tr := open(t, path, func() time.Time { return start })
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, nil))
	before, _ := os.ReadFile(path)
	past := start.Add(-time.Second)
	if _, err := s.Set("vless-in", "a", xrpc.SourceMaster, 1*mbps, &past); !errors.Is(err, ErrExpired) {
		t.Fatalf("截止时间已过应当回 ErrExpired：%v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("被拒时文件不应当变")
	}
	if bps, _ := tr.Effective("vless-in", "a"); bps != 5*mbps {
		t.Fatalf("被拒时 tracker 不应当变：%d", bps)
	}
}

// 回复里的来源与生效值一致：主控临时在存储的时钟上已经过期、tracker 的计时器还没到时，改另一份来源，回复里既没有主控临时，
// 生效值也不受它影响。
func TestStateConsistentWhenSourceExpires(t *testing.T) {
	ok := mustOK(t)
	start := time.Now()
	now := start
	s, tr := open(t, filepath.Join(t.TempDir(), FileName), func() time.Time { return now })
	deadline := start.Add(time.Minute)
	ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, &deadline))
	now = start.Add(2 * time.Minute) // 存储看来主控临时已经过期；tracker 按真实时间，一分钟内不会撤
	st := ok(s.Set("vless-in", "a", xrpc.SourceStatic, 10*mbps, nil))
	if len(st.Sources) != 1 || st.Sources[0].Source != xrpc.SourceStatic || st.EffectiveBPS != 10*mbps {
		t.Fatalf("回复里不应当有已过期的主控临时，生效值应当是静态的 10 Mbps：%+v", st)
	}
	if bps, _ := tr.Effective("vless-in", "a"); bps != 5*mbps {
		t.Fatalf("这个测试要的正是 tracker 还没撤的那一刻：%d", bps)
	}
}

// 一次设值里的「现在」固定成拿到锁那一刻：存储的时钟每被问一次就往前走 10 毫秒，截止时间设在第一次与第二次之间。
// 拿到锁时还没过期，所以接受；写文件与回复用的也是那一刻，文件与回复里都有这份来源。
func TestOneInstantPerChange(t *testing.T) {
	ok := mustOK(t)
	path := filepath.Join(t.TempDir(), FileName)
	start := time.Now()
	calls := 0
	tick := func() time.Time { calls++; return start.Add(time.Duration(calls-1) * 10 * time.Millisecond) }
	s, _ := open(t, path, tick)
	calls = 0
	deadline := start.Add(5 * time.Millisecond) // 第一次被问时（start）还没到，第二次（start+10ms）已过
	st := ok(s.Set("vless-in", "a", xrpc.SourceMaster, 5*mbps, &deadline))
	if len(st.Sources) != 1 || st.Sources[0].Source != xrpc.SourceMaster || !st.Limited {
		t.Fatalf("拿到锁那一刻还没过期，回复里应当有这份来源：%+v", st)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), `"source": "master"`) {
		t.Fatalf("文件里也应当有它：%s", data)
	}
}

// Package limits 管节点上每份「入站 × 凭据」的三份限速来源（静态、主控临时、节点规则临时）：存在 limiter-state.json 里，
// 启动时重放进 tracker（m2-03 design 第 3 条，node-limiter「节点上的限速来源与持久化」）。
//
// 每次改动先写文件、写成功了再改 tracker，写失败什么都不改，文件与 tracker 不会一个改了一个没改。一次改动里用到的「现在」
// 固定成拿到锁那一刻：判断截止时间过没过、写文件时滤掉过期的、回复里列来源都用它，三者一致。到期由 tracker 自己撤；
// 文件里过期的那一条不急着删，下次写文件时不写进去；启动读回时丢掉，并当场重写一次文件。与 mmwx 的不同：三份来源分开存、按入站隔离、各自到期，
// 不共用一个覆盖槽（技术方案第 10 章）。
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/tracker"
)

// FileName 是状态文件的名字，与 config.yaml 放在同一个目录。
const FileName = "limiter-state.json"

const fileVersion = 1

// ErrExpired 是设值时截止时间已经过了：入口校验时还有效、等锁或写文件期间过期的，也在这里拒绝。
var ErrExpired = errors.New("截止时间已经过了")

// sources 把通道上的来源名对到 tracker 的来源。
var sources = map[string]tracker.Source{
	xrpc.SourceStatic:   tracker.SourceStatic,
	xrpc.SourceMaster:   tracker.SourceMaster,
	xrpc.SourceNodeRule: tracker.SourceNodeRule,
}

type key struct{ inbound, credential string }

type value struct {
	bps      int64
	deadline *time.Time
}

// entry 是状态文件里的一条。
type entry struct {
	Inbound    string     `json:"inbound"`
	Credential string     `json:"credential"`
	Source     string     `json:"source"`
	BPS        int64      `json:"bps"`
	Deadline   *time.Time `json:"deadline,omitempty"`
}

type file struct {
	Version int     `json:"version"`
	Entries []entry `json:"entries"`
}

// Store 是三份来源的状态。方法可以并发调用。
type Store struct {
	path    string
	tracker *tracker.Tracker
	now     func() time.Time

	mu      sync.Mutex
	entries map[key]map[string]value
}

// Open 读回 path 里的状态并重放进 t：过期的丢掉（丢了就当场重写文件），没过期的按原截止时间到期。文件不存在时从空开始。
// 出错时仍返回能用的状态：文件读不了或解不开时是空的，重写失败时是已经重放的那些。
func Open(path string, t *tracker.Tracker, now func() time.Time) (*Store, error) {
	s := &Store{path: path, tracker: t, now: now, entries: map[key]map[string]value{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("读限速状态 %s 失败：%w", path, err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return s, fmt.Errorf("限速状态 %s 解不开：%w", path, err)
	}
	at := now()
	dropped := 0
	for _, e := range f.Entries {
		src, ok := sources[e.Source]
		if !ok || e.Credential == "" || e.BPS < 0 || (e.Deadline != nil && !e.Deadline.After(at)) {
			dropped++
			continue
		}
		var deadline time.Time
		if e.Deadline != nil {
			deadline = *e.Deadline
		}
		if err := t.Set(e.Inbound, e.Credential, src, e.BPS, deadline); err != nil {
			dropped++
			continue
		}
		s.put(key{e.Inbound, e.Credential}, e.Source, value{e.BPS, e.Deadline})
	}
	if dropped > 0 {
		if err := s.save(s.entries, at); err != nil {
			return s, fmt.Errorf("丢掉过期的限速来源之后重写 %s 失败：%w", path, err)
		}
	}
	return s, nil
}

func (s *Store) put(k key, source string, v value) {
	m := s.entries[k]
	if m == nil {
		m = map[string]value{}
		s.entries[k] = m
	}
	m[source] = v
}

// Set 给一份凭据的某一份来源设值（比特每秒，0 表示这一份显式不限速）；deadline 为空表示不带截止时间。调用方先校验来源、
// 值与凭据名；截止时间按拿到锁那一刻再看一次：已经过了就回 ErrExpired、什么都不改（tracker 把零值时间当成不带截止时间）；
// 那一刻还没过就接受，之后才到的按正常到期撤掉（后一次设值连同截止时间覆盖前一次，到期后不会回到前一次的值）。
func (s *Store) Set(inbound, credential, source string, bps int64, deadline *time.Time) (xrpc.LimiterState, error) {
	src, ok := sources[source]
	if !ok {
		return xrpc.LimiterState{}, fmt.Errorf("不认识的限速来源 %q", source)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	if deadline != nil && !deadline.After(at) {
		return xrpc.LimiterState{}, ErrExpired
	}
	k := key{inbound, credential}
	next := s.snapshot()
	m := next[k]
	if m == nil {
		m = map[string]value{}
		next[k] = m
	}
	m[source] = value{bps, deadline}
	if err := s.save(next, at); err != nil {
		return xrpc.LimiterState{}, err
	}
	var d time.Time
	if deadline != nil {
		d = *deadline
	}
	if err := s.tracker.Set(inbound, credential, src, bps, d); err != nil {
		return xrpc.LimiterState{}, err
	}
	s.entries = next
	return s.stateLocked(k, at), nil
}

// Unset 撤掉一份凭据的某一份来源；本来没设也算成功。
func (s *Store) Unset(inbound, credential, source string) (xrpc.LimiterState, error) {
	src, ok := sources[source]
	if !ok {
		return xrpc.LimiterState{}, fmt.Errorf("不认识的限速来源 %q", source)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.now()
	k := key{inbound, credential}
	next := s.snapshot()
	delete(next[k], source)
	if len(next[k]) == 0 {
		delete(next, k)
	}
	if err := s.save(next, at); err != nil {
		return xrpc.LimiterState{}, err
	}
	if err := s.tracker.Unset(inbound, credential, src); err != nil {
		return xrpc.LimiterState{}, err
	}
	s.entries = next
	return s.stateLocked(k, at), nil
}

// snapshot 复制一份当前状态（调用方持锁）。
func (s *Store) snapshot() map[key]map[string]value {
	out := make(map[key]map[string]value, len(s.entries))
	for k, m := range s.entries {
		c := make(map[string]value, len(m))
		for src, v := range m {
			c[src] = v
		}
		out[k] = c
	}
	return out
}

// stateLocked 是一份凭据的回复：没过期的来源按 xrpc.Sources 的顺序；生效值也按这份状态、用与 tracker 相同的规则算
// （已设且大于 0 的来源里取最小），不去问 tracker——截止时间恰好在这中间到期时，tracker 要等自己的计时器才撤，回复里的
// 来源与生效值会对不上（调用方持锁）。at 是这次改动拿到锁那一刻。
func (s *Store) stateLocked(k key, at time.Time) xrpc.LimiterState {
	st := xrpc.LimiterState{Inbound: k.inbound, Credential: k.credential, Sources: []xrpc.LimitSource{}}
	for _, src := range xrpc.Sources {
		v, ok := s.entries[k][src]
		if !ok || (v.deadline != nil && !v.deadline.After(at)) {
			continue
		}
		st.Sources = append(st.Sources, xrpc.LimitSource{Source: src, BPS: v.bps, Deadline: v.deadline})
		if v.bps > 0 && (!st.Limited || v.bps < st.EffectiveBPS) {
			st.Limited, st.EffectiveBPS = true, v.bps
		}
	}
	return st
}

// save 把 entries 里没过期的来源写进状态文件：先写临时文件、改 0600、再改名，与 config.yaml 的写法相同。
func (s *Store) save(entries map[key]map[string]value, at time.Time) error {
	f := file{Version: fileVersion, Entries: []entry{}}
	for k, m := range entries {
		for src, v := range m {
			if v.deadline != nil && !v.deadline.After(at) {
				continue
			}
			f.Entries = append(f.Entries, entry{Inbound: k.inbound, Credential: k.credential, Source: src, BPS: v.bps, Deadline: v.deadline})
		}
	}
	sort.Slice(f.Entries, func(i, j int) bool {
		a, b := f.Entries[i], f.Entries[j]
		if a.Inbound != b.Inbound {
			return a.Inbound < b.Inbound
		}
		if a.Credential != b.Credential {
			return a.Credential < b.Credential
		}
		return a.Source < b.Source
	})
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".limiter-state-*.json")
	if err != nil {
		return fmt.Errorf("写限速状态失败：%w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("写限速状态失败：%w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写限速状态失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("写限速状态失败：%w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("写限速状态失败：%w", err)
	}
	return nil
}

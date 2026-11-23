package execctl

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/updater"
)

func TestExecDisabledRejected(t *testing.T) {
	mgr := New(Options{AllowExec: false, DataDir: t.TempDir()})
	if mgr.AllowExec() {
		t.Fatal("默认 AllowExec 必须为 false")
	}
	_, err := mgr.Start(context.Background(), xrpc.ExecStartParams{JobID: "job-1", Command: "echo hi"})
	if err == nil {
		t.Fatal("AllowExec=false 必须拒绝执行")
	}
}

func TestExecStreamOutputTruncateNonZeroAndPersist(t *testing.T) {
	dir := t.TempDir()
	counter := &updater.ExecCounter{}
	var mu sync.Mutex
	var events []xrpc.ExecEvent

	mgr := New(Options{
		AllowExec: true,
		DataDir:   dir,
		Execs:     counter,
		OnEvent: func(ev xrpc.ExecEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})

	// 1. 正常流式输出与本地审计记录。
	res, err := mgr.Start(context.Background(), xrpc.ExecStartParams{
		JobID:     "job-ok-1",
		Command:   "echo hello-1; echo hello-2 >&2",
		TimeoutMS: 5000,
	})
	if err != nil || !res.Accepted {
		t.Fatalf("Start 失败：%+v err=%v", res, err)
	}
	st := waitDone(t, mgr, "job-ok-1")
	if st.State != xrpc.ExecStateDone || st.ExitCode != 0 || !strings.Contains(st.Output, "hello-1") || !strings.Contains(st.Output, "hello-2") {
		t.Fatalf("正常执行终态不对：%+v", st)
	}
	if counter.Running() {
		t.Fatal("执行结束后 ExecCounter 应归零")
	}
	mu.Lock()
	evCount := len(events)
	mu.Unlock()
	if evCount == 0 {
		t.Fatal("应收到至少 1 条流式/终态事件")
	}
	auditRaw, err := os.ReadFile(filepath.Join(dir, "logs", "exec-audit.log"))
	if err != nil || !strings.Contains(string(auditRaw), "job_id=job-ok-1") {
		t.Fatalf("本地审计日志未写入：err=%v raw=%s", err, string(auditRaw))
	}

	// 2. 重建新 Manager 模拟节点重启，验证持久化终态可按 job_id 补报。
	mgr2 := New(Options{AllowExec: true, DataDir: dir, Execs: counter})
	replayed, err := mgr2.Status(xrpc.ExecStatusParams{JobID: "job-ok-1"})
	if err != nil || !replayed.Found || !replayed.Done || !strings.Contains(replayed.Output, "hello-1") {
		t.Fatalf("重启后无法按 job_id 查回终态：%+v err=%v", replayed, err)
	}

	// 3. 非零退出码保留真实值与输出截断。
	if _, err := mgr2.Start(context.Background(), xrpc.ExecStartParams{
		JobID:     "job-nz-2",
		Command:   "printf '0123456789ABCDEF'; exit 42",
		TimeoutMS: 5000,
		MaxBytes:  8,
	}); err != nil {
		t.Fatal(err)
	}
	st2 := waitDone(t, mgr2, "job-nz-2")
	if st2.State != xrpc.ExecStateFailed || st2.ExitCode != 42 || !st2.Truncated || st2.Output != "01234567" {
		t.Fatalf("非零退出码或截断不对：%+v", st2)
	}
}

func TestExecTimeoutKillsProcessGroupAndCounterBlocksUpdate(t *testing.T) {
	dir := t.TempDir()
	counter := &updater.ExecCounter{}
	mgr := New(Options{AllowExec: true, DataDir: dir, Execs: counter})

	start := time.Now()
	if _, err := mgr.Start(context.Background(), xrpc.ExecStartParams{
		JobID:     "job-timeout-1",
		Command:   "sleep 30 & wait",
		TimeoutMS: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if !counter.Running() {
		t.Fatal("执行中 ExecCounter 应为 true 以阻塞自升级")
	}
	st := waitDone(t, mgr, "job-timeout-1")
	if st.State != xrpc.ExecStateTimedOut || st.ExitCode != 124 {
		t.Fatalf("超时终态不对：%+v", st)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("超时杀进程组耗时过长：%v", time.Since(start))
	}
	if counter.Running() {
		t.Fatal("超时查杀后 ExecCounter 应归零")
	}
}

func TestExecReapOrphansOnStartup(t *testing.T) {
	dir := t.TempDir()
	// 启动一个独立进程组的睡眠进程模拟上次 agent 异常退出残留的孤儿。
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	orphanPGID := cmd.Process.Pid
	doneWait := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(doneWait)
	}()

	entries := []activeEntry{{JobID: "job-orphan", PGID: orphanPGID, PID: orphanPGID, StartedAt: time.Now().UTC()}}
	raw, _ := json.Marshal(entries)
	if err := os.WriteFile(filepath.Join(dir, activeFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_ = New(Options{AllowExec: true, DataDir: dir})
	select {
	case <-doneWait:
	case <-time.After(3 * time.Second):
		killProcessGroup(orphanPGID)
		t.Fatal("启动清扫未能终止遗留孤儿进程组")
	}
	if _, err := os.Stat(filepath.Join(dir, activeFileName)); !os.IsNotExist(err) {
		t.Fatalf("清扫后应移除 exec-active.json：%v", err)
	}
}

func waitDone(t *testing.T, mgr *Manager, jobID string) *xrpc.ExecStatusResult {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		st, err := mgr.Status(xrpc.ExecStatusParams{JobID: jobID})
		if err != nil {
			t.Fatal(err)
		}
		if st.Found && st.Done {
			return st
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("等待 job %s 结束超时", jobID)
	return nil
}

// Package execctl 实现节点侧受控任意命令执行（server exec）：
// 本地 allow_exec 强开关、独立进程组（Setpgid）无 stdin 执行、超时/取消整组查杀、64 KiB 输出上限、
// WS 增量事件流与 exec.status 轮询缓存、重启孤儿进程组清扫、与自升级 ExecCounter 互斥以及本地单行审计记录。
package execctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/updater"
)

const (
	activeFileName  = "exec-active.json"
	resultsFileName = "exec-results.json"
	maxCachedJobs   = 64
	resultTTL       = 24 * time.Hour
)

// Options 配置节点受控执行器。
type Options struct {
	AllowExec    bool
	DataDir      string
	AuditLogPath string
	Execs        *updater.ExecCounter
	OnEvent      func(ev xrpc.ExecEvent)
	Logger       *slog.Logger
	Now          func() time.Time
}

type activeEntry struct {
	JobID     string    `json:"job_id"`
	PGID      int       `json:"pgid"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

type storedResult struct {
	JobID      string    `json:"job_id"`
	State      string    `json:"state"`
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Truncated  bool      `json:"truncated,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type runningJob struct {
	jobID     string
	command   string
	pgid      int
	maxBytes  int
	startedAt time.Time
	cancelCh  chan struct{}
	cancelOne sync.Once

	mu         sync.Mutex
	buf        bytes.Buffer
	truncated  bool
	seq        uint64
	done       bool
	state      string
	exitCode   int
	durationMS int64
	errMsg     string
	finishedAt *time.Time
}

func (r *runningJob) requestCancel() {
	r.cancelOne.Do(func() { close(r.cancelCh) })
}

// Manager 管理节点侧所有受控命令执行任务。
type Manager struct {
	opts Options

	mu      sync.Mutex
	running map[string]*runningJob
	results map[string]*storedResult
	onEvent func(ev xrpc.ExecEvent)
}

// New 构造受控执行器，并在启动时自动清扫上次进程遗留的孤儿执行进程组。
func New(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.AuditLogPath == "" && opts.DataDir != "" {
		opts.AuditLogPath = filepath.Join(opts.DataDir, "logs", "exec-audit.log")
	}
	m := &Manager{
		opts:    opts,
		running: make(map[string]*runningJob),
		results: make(map[string]*storedResult),
		onEvent: opts.OnEvent,
	}
	m.loadResults()
	m.ReapOrphans()
	return m
}

// AllowExec 返回节点本地配置的只读 exec 开关状态。
func (m *Manager) AllowExec() bool {
	return m != nil && m.opts.AllowExec
}

// SetOnEvent 设置（或替换）WS 上行 exec_event 推送回调。
func (m *Manager) SetOnEvent(fn func(ev xrpc.ExecEvent)) {
	m.mu.Lock()
	m.onEvent = fn
	m.mu.Unlock()
}

// ReapOrphans 清扫 <DataDir>/exec-active.json 中记录的历史遗留执行进程组，不留 root 孤儿进程。
func (m *Manager) ReapOrphans() int {
	if m.opts.DataDir == "" {
		return 0
	}
	path := filepath.Join(m.opts.DataDir, activeFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var entries []activeEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		_ = os.Remove(path)
		return 0
	}
	reaped := 0
	for _, ent := range entries {
		if ent.PGID > 1 && pgidAlive(ent.PGID) {
			m.opts.Logger.Warn("清理上次遗留的 exec 进程组", "job_id", ent.JobID, "pgid", ent.PGID)
			killProcessGroup(ent.PGID)
			reaped++
		}
	}
	_ = os.Remove(path)
	return reaped
}

// Start 按本地 allow_exec 开关以独立进程组、无 stdin 启动 /bin/sh -c 命令。
func (m *Manager) Start(_ context.Context, p xrpc.ExecStartParams) (*xrpc.ExecStartResult, error) {
	if !m.opts.AllowExec {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: "节点本机未开启 allow_exec（仅允许在节点本地 config.yaml 或 join --allow-exec 修改），拒绝执行远程命令"}
	}
	jobID := strings.TrimSpace(p.JobID)
	if jobID == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "job_id 不能为空"}
	}
	if strings.TrimSpace(p.Command) == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "command 不能为空"}
	}
	if len(p.Command) > xrpc.ExecMaxCommandBytes {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("command 长度超出上限 %d 字节", xrpc.ExecMaxCommandBytes)}
	}
	timeoutMS := p.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = xrpc.ExecDefaultTimeoutMS
	}
	if timeoutMS < xrpc.ExecMinTimeoutMS || timeoutMS > xrpc.ExecMaxTimeoutMS {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("timeout_ms 必须在 %d..%d 之间", xrpc.ExecMinTimeoutMS, xrpc.ExecMaxTimeoutMS)}
	}
	maxBytes := p.MaxBytes
	if maxBytes <= 0 || maxBytes > xrpc.ExecMaxOutputBytes {
		maxBytes = xrpc.ExecMaxOutputBytes
	}

	m.mu.Lock()
	if _, dup := m.running[jobID]; dup {
		m.mu.Unlock()
		return nil, &xrpc.Error{Code: xrpc.CodeConflict, Message: fmt.Sprintf("job %s 已在执行中", jobID)}
	}
	if _, dup := m.results[jobID]; dup {
		m.mu.Unlock()
		return nil, &xrpc.Error{Code: xrpc.CodeConflict, Message: fmt.Sprintf("job %s 已有终态记录", jobID)}
	}

	cmd := exec.Command("/bin/sh", "-c", p.Command)
	cmd.Stdin = nil // 禁止 stdin，标准库绑定 /dev/null
	setProcessGroup(cmd)

	pr, pw, err := os.Pipe()
	if err != nil {
		m.mu.Unlock()
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("创建输出管道失败：%v", err)}
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		m.mu.Unlock()
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("启动执行进程失败：%v", err)}
	}
	// 父进程立即关闭写端，确保子进程组全部退出后读端收到 EOF。
	_ = pw.Close()

	started := m.opts.Now().UTC()
	pgid := cmd.Process.Pid
	rj := &runningJob{
		jobID:     jobID,
		command:   p.Command,
		pgid:      pgid,
		maxBytes:  maxBytes,
		startedAt: started,
		cancelCh:  make(chan struct{}),
		state:     xrpc.ExecStateRunning,
	}
	m.running[jobID] = rj
	m.opts.Execs.Begin()
	m.persistActiveLocked()
	m.mu.Unlock()

	go m.supervise(rj, cmd, pr, time.Duration(timeoutMS)*time.Millisecond)

	return &xrpc.ExecStartResult{
		JobID:     jobID,
		Accepted:  true,
		PGID:      pgid,
		StartedAt: started,
	}, nil
}

func (m *Manager) supervise(rj *runningJob, cmd *exec.Cmd, pr *os.File, timeout time.Duration) {
	defer m.opts.Execs.End()
	defer pr.Close()

	// 并发读输出流并推送增量事件。
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				m.appendChunk(rj, buf[:n])
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					_ = err
				}
				return
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var waitErr error
	timedOut := false
	canceled := false

	select {
	case waitErr = <-waitCh:
	case <-timer.C:
		timedOut = true
		killProcessGroup(rj.pgid)
		waitErr = <-waitCh
	case <-rj.cancelCh:
		canceled = true
		killProcessGroup(rj.pgid)
		waitErr = <-waitCh
	}

	// 确保管道读端刷完再收集终态（若孙子进程异常未退出，上面已 SIGKILL 整组）。
	<-readDone

	finished := m.opts.Now().UTC()
	durMS := finished.Sub(rj.startedAt).Milliseconds()
	if durMS < 0 {
		durMS = 0
	}

	state := xrpc.ExecStateDone
	exitCode := 0
	errMsg := ""
	switch {
	case timedOut:
		state = xrpc.ExecStateTimedOut
		exitCode = 124
		errMsg = fmt.Sprintf("命令执行超过 %s 超时，已终止整个进程组", timeout)
	case canceled:
		state = xrpc.ExecStateCanceled
		exitCode = 130
		errMsg = "命令执行已被取消，已终止整个进程组"
	case waitErr != nil:
		state = xrpc.ExecStateFailed
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
			if exitCode == 0 {
				exitCode = 1
			}
		} else {
			exitCode = 1
			errMsg = waitErr.Error()
		}
	}

	rj.mu.Lock()
	rj.done = true
	rj.state = state
	rj.exitCode = exitCode
	rj.durationMS = durMS
	rj.errMsg = errMsg
	rj.finishedAt = &finished
	rj.seq++
	finalSeq := rj.seq
	finalOutput := rj.buf.String()
	finalOffset := rj.buf.Len()
	finalTrunc := rj.truncated
	rj.mu.Unlock()

	rec := &storedResult{
		JobID:      rj.jobID,
		State:      state,
		ExitCode:   exitCode,
		Output:     finalOutput,
		Truncated:  finalTrunc,
		DurationMS: durMS,
		Error:      errMsg,
		StartedAt:  rj.startedAt,
		FinishedAt: finished,
	}

	m.mu.Lock()
	delete(m.running, rj.jobID)
	m.results[rj.jobID] = rec
	m.pruneResultsLocked()
	m.persistActiveLocked()
	m.persistResultsLocked()
	emit := m.onEvent
	m.mu.Unlock()

	m.writeLocalAudit(rj.jobID, rj.command, state, exitCode, durMS, finalTrunc)

	if emit != nil {
		emit(xrpc.ExecEvent{
			JobID:      rj.jobID,
			Seq:        finalSeq,
			Offset:     finalOffset,
			Done:       true,
			State:      state,
			ExitCode:   exitCode,
			Truncated:  finalTrunc,
			DurationMS: durMS,
			Error:      errMsg,
			At:         finished,
		})
	}
}

func (m *Manager) appendChunk(rj *runningJob, data []byte) {
	rj.mu.Lock()
	rem := rj.maxBytes - rj.buf.Len()
	var written string
	if rem > 0 {
		if len(data) > rem {
			_, _ = rj.buf.Write(data[:rem])
			written = string(data[:rem])
			rj.truncated = true
		} else {
			_, _ = rj.buf.Write(data)
			written = string(data)
		}
	} else {
		rj.truncated = true
	}
	offset := rj.buf.Len()
	truncated := rj.truncated
	var seq uint64
	if written != "" {
		rj.seq++
		seq = rj.seq
	}
	rj.mu.Unlock()

	if written == "" {
		return
	}
	m.mu.Lock()
	emit := m.onEvent
	m.mu.Unlock()
	if emit != nil {
		emit(xrpc.ExecEvent{
			JobID:     rj.jobID,
			Seq:       seq,
			Chunk:     written,
			Offset:    offset,
			Truncated: truncated,
			At:        m.opts.Now().UTC(),
		})
	}
}

// Status 查询运行中或已持久化缓存的 exec 任务增量输出与终态。
func (m *Manager) Status(p xrpc.ExecStatusParams) (*xrpc.ExecStatusResult, error) {
	jobID := strings.TrimSpace(p.JobID)
	if jobID == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "job_id 不能为空"}
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}

	m.mu.Lock()
	rj := m.running[jobID]
	sr := m.results[jobID]
	m.mu.Unlock()

	if rj != nil {
		rj.mu.Lock()
		full := rj.buf.String()
		trunc := rj.truncated
		done := rj.done
		state := rj.state
		exitCode := rj.exitCode
		durMS := rj.durationMS
		errMsg := rj.errMsg
		st := rj.startedAt
		ft := rj.finishedAt
		rj.mu.Unlock()

		chunk := ""
		if offset < len(full) {
			chunk = full[offset:]
		}
		res := &xrpc.ExecStatusResult{
			JobID:      jobID,
			Found:      true,
			State:      state,
			Done:       done,
			ExitCode:   exitCode,
			Chunk:      chunk,
			NextOffset: len(full),
			Truncated:  trunc,
			DurationMS: durMS,
			Error:      errMsg,
			StartedAt:  &st,
			FinishedAt: ft,
		}
		if offset == 0 || done {
			res.Output = full
		}
		return res, nil
	}

	if sr != nil {
		chunk := ""
		if offset < len(sr.Output) {
			chunk = sr.Output[offset:]
		}
		st := sr.StartedAt
		ft := sr.FinishedAt
		return &xrpc.ExecStatusResult{
			JobID:      jobID,
			Found:      true,
			State:      sr.State,
			Done:       true,
			ExitCode:   sr.ExitCode,
			Chunk:      chunk,
			NextOffset: len(sr.Output),
			Output:     sr.Output,
			Truncated:  sr.Truncated,
			DurationMS: sr.DurationMS,
			Error:      sr.Error,
			StartedAt:  &st,
			FinishedAt: &ft,
		}, nil
	}

	return &xrpc.ExecStatusResult{JobID: jobID, Found: false}, nil
}

// Cancel 取消正在执行中的任务并终止其整个进程组。
func (m *Manager) Cancel(p xrpc.ExecCancelParams) (*xrpc.ExecCancelResult, error) {
	jobID := strings.TrimSpace(p.JobID)
	if jobID == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "job_id 不能为空"}
	}
	m.mu.Lock()
	rj := m.running[jobID]
	m.mu.Unlock()
	if rj == nil {
		return &xrpc.ExecCancelResult{JobID: jobID, Canceled: false}, nil
	}
	rj.requestCancel()
	return &xrpc.ExecCancelResult{JobID: jobID, Canceled: true}, nil
}

// Shutdown 在节点退出时终止所有在途 exec 进程组。
func (m *Manager) Shutdown() {
	m.mu.Lock()
	list := make([]*runningJob, 0, len(m.running))
	for _, rj := range m.running {
		list = append(list, rj)
	}
	m.mu.Unlock()
	for _, rj := range list {
		rj.requestCancel()
	}
}

func (m *Manager) writeLocalAudit(jobID, command, state string, exitCode int, durMS int64, truncated bool) {
	summary := strings.ReplaceAll(strings.TrimSpace(command), "\n", " ")
	if len(summary) > 160 {
		summary = summary[:160] + "..."
	}
	m.opts.Logger.Info("本地记录远程受控执行",
		"job_id", jobID, "state", state, "exit_code", exitCode, "duration_ms", durMS, "truncated", truncated, "command_summary", summary)
	if m.opts.AuditLogPath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.opts.AuditLogPath), 0o700)
	f, err := os.OpenFile(m.opts.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%s job_id=%s state=%s exit_code=%d duration_ms=%d truncated=%t cmd=%q\n",
		m.opts.Now().UTC().Format(time.RFC3339), jobID, state, exitCode, durMS, truncated, summary)
	_, _ = f.WriteString(line)
}

func (m *Manager) persistActiveLocked() {
	if m.opts.DataDir == "" {
		return
	}
	path := filepath.Join(m.opts.DataDir, activeFileName)
	if len(m.running) == 0 {
		_ = os.Remove(path)
		return
	}
	entries := make([]activeEntry, 0, len(m.running))
	for _, rj := range m.running {
		entries = append(entries, activeEntry{
			JobID:     rj.jobID,
			PGID:      rj.pgid,
			PID:       rj.pgid,
			StartedAt: rj.startedAt,
		})
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWrite0600(path, raw)
}

func (m *Manager) loadResults() {
	if m.opts.DataDir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(m.opts.DataDir, resultsFileName))
	if err != nil {
		return
	}
	var list []*storedResult
	if err := json.Unmarshal(raw, &list); err != nil {
		return
	}
	cutoff := m.opts.Now().UTC().Add(-resultTTL)
	for _, r := range list {
		if r != nil && r.JobID != "" && !r.FinishedAt.Before(cutoff) {
			m.results[r.JobID] = r
		}
	}
}

func (m *Manager) pruneResultsLocked() {
	cutoff := m.opts.Now().UTC().Add(-resultTTL)
	for id, r := range m.results {
		if r.FinishedAt.Before(cutoff) {
			delete(m.results, id)
		}
	}
	if len(m.results) <= maxCachedJobs {
		return
	}
	list := make([]*storedResult, 0, len(m.results))
	for _, r := range m.results {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].FinishedAt.Before(list[j].FinishedAt) })
	for i := 0; i < len(list)-maxCachedJobs; i++ {
		delete(m.results, list[i].JobID)
	}
}

func (m *Manager) persistResultsLocked() {
	if m.opts.DataDir == "" {
		return
	}
	list := make([]*storedResult, 0, len(m.results))
	for _, r := range m.results {
		list = append(list, r)
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWrite0600(filepath.Join(m.opts.DataDir, resultsFileName), raw)
}

func atomicWrite0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

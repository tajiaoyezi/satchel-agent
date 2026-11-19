// Package logging 管理 satchel-agent 自身及内嵌 sing-box 内核的轮转文件日志（node-telemetry）：
// 使用 lumberjack.v2 按 50 MiB × 3 备份轮转，目录 0700、文件 0600，复用敏感属性脱敏，
// 并以原子 slog.LevelVar 支持主控 agent_log_enabled 实时热切换 INFO/DEBUG 而无需重启。
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	singlog "github.com/sagernet/sing-box/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// DefaultAgentLogFile 与 CoreLogFile 是节点日志目录内的两个活跃主日志文件。
	DefaultAgentLogFile = "satchel-agent.log"
	CoreLogFile         = "core.log"

	maxSizeMB  = 50
	maxBackups = 3
)

// LoggerSet 持有节点自身日志、原子级别开关与内嵌内核日志写出器。
type LoggerSet struct {
	Logger       *slog.Logger
	Level        *slog.LevelVar
	CoreLogger   *slog.Logger
	LogDir       string
	AgentLogPath string
	CoreLogPath  string

	agentRot *lumberjack.Logger
	coreRot  *lumberjack.Logger
}

// Setup 初始化节点轮转文件日志与内嵌内核轮转日志；同时向 stderr 与轮转文件写入。
func Setup(agentLogPath string, stderr io.Writer) (*LoggerSet, error) {
	return setupWith(agentLogPath, stderr, maxSizeMB)
}

func setupWith(agentLogPath string, stderr io.Writer, sizeMB int) (*LoggerSet, error) {
	if strings.TrimSpace(agentLogPath) == "" {
		return nil, fmt.Errorf("agent 日志路径不能为空")
	}
	if stderr == nil {
		stderr = io.Discard
	}
	dir := filepath.Dir(agentLogPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("建日志目录 %s 失败：%w", dir, err)
	}
	// lumberjack 延迟建文件；预先按 0600 创建确保权限严格受控并提早暴露只读路径问题。
	if err := ensureFile0600(agentLogPath); err != nil {
		return nil, err
	}
	coreLogPath := filepath.Join(dir, CoreLogFile)
	if err := ensureFile0600(coreLogPath); err != nil {
		return nil, err
	}

	agentRot := &lumberjack.Logger{Filename: agentLogPath, MaxSize: sizeMB, MaxBackups: maxBackups}
	coreRot := &lumberjack.Logger{Filename: coreLogPath, MaxSize: sizeMB, MaxBackups: maxBackups}

	lv := &slog.LevelVar{}
	lv.Set(slog.LevelInfo)
	agentHandler := slog.NewTextHandler(io.MultiWriter(stderr, agentRot), &slog.HandlerOptions{
		Level:       lv,
		ReplaceAttr: redact,
	})
	coreHandler := slog.NewTextHandler(coreRot, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: redact,
	})

	return &LoggerSet{
		Logger:       slog.New(agentHandler),
		Level:        lv,
		CoreLogger:   slog.New(coreHandler),
		LogDir:       dir,
		AgentLogPath: agentLogPath,
		CoreLogPath:  coreLogPath,
		agentRot:     agentRot,
		coreRot:      coreRot,
	}, nil
}

func ensureFile0600(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打开日志文件 %s 失败：%w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("设置日志文件权限 %s 失败：%w", path, err)
	}
	return f.Close()
}

// SetDebugEnabled 原子切换节点运行期日志级别：true → DEBUG，false → INFO。
func (s *LoggerSet) SetDebugEnabled(enabled bool) {
	if s == nil || s.Level == nil {
		return
	}
	if enabled {
		s.Level.Set(slog.LevelDebug)
	} else {
		s.Level.Set(slog.LevelInfo)
	}
}

// DebugEnabled 返回当前是否处于 DEBUG 级别。
func (s *LoggerSet) DebugEnabled() bool {
	if s == nil || s.Level == nil {
		return false
	}
	return s.Level.Level() <= slog.LevelDebug
}

// CorePlatformWriter 返回适配 sing-box 的 PlatformLogWriter，将内嵌内核日志按 slog 格式写入 core.log。
func (s *LoggerSet) CorePlatformWriter() singlog.PlatformWriter {
	if s == nil || s.CoreLogger == nil {
		return nil
	}
	return corePlatformWriter{logger: s.CoreLogger}
}

// Close 关闭底层轮转日志文件句柄。
func (s *LoggerSet) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.agentRot != nil {
		if err := s.agentRot.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.coreRot != nil {
		if err := s.coreRot.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type corePlatformWriter struct {
	logger *slog.Logger
}

func (w corePlatformWriter) WriteMessage(level singlog.Level, message string) {
	if w.logger == nil {
		return
	}
	msg := strings.TrimSpace(message)
	switch level {
	case singlog.LevelPanic, singlog.LevelFatal, singlog.LevelError:
		w.logger.Error(msg)
	case singlog.LevelWarn:
		w.logger.Warn(msg)
	case singlog.LevelInfo:
		w.logger.Info(msg)
	default:
		w.logger.Debug(msg)
	}
}

// redact 与主控保持完全一致的日志兜底脱敏：键名或任一层属性组名含 password/secret 或以 token 结尾写成 ***。
func redact(groups []string, a slog.Attr) slog.Attr {
	if sensitive(a.Key) {
		return slog.String(a.Key, "***")
	}
	for _, g := range groups {
		if sensitive(g) {
			return slog.String(a.Key, "***")
		}
	}
	return a
}

func sensitive(name string) bool {
	k := strings.ToLower(name)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.HasSuffix(k, "token")
}

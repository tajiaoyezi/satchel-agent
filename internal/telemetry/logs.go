package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/logging"
)

var logLevelRanks = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

// LogInspector 提供节点侧只读日志与日志文件清单检查（不提供任何删除或清空操作）。
type LogInspector struct {
	LogDir            string
	AgentLogFile      string
	CoreLogFile       string
	NginxFallbackPath string
	RunJournalctl     func(ctx context.Context, lines int) ([]byte, error)
}

// NewLogInspector 建节点只读日志检查器。
func NewLogInspector(logDir, agentLogFile, coreLogFile string) *LogInspector {
	if agentLogFile == "" {
		agentLogFile = logging.DefaultAgentLogFile
	}
	if coreLogFile == "" {
		coreLogFile = logging.CoreLogFile
	}
	return &LogInspector{
		LogDir:            filepath.Clean(logDir),
		AgentLogFile:      filepath.Base(agentLogFile),
		CoreLogFile:       filepath.Base(coreLogFile),
		NginxFallbackPath: "/var/log/nginx/error.log",
		RunJournalctl:     defaultNginxJournalctl,
	}
}

// defaultNginxJournalctl 使用写死白名单参数调用 journalctl，绝不把用户输入拼进命令行。
func defaultNginxJournalctl(ctx context.Context, lines int) ([]byte, error) {
	if lines <= 0 {
		lines = 200
	}
	if lines > xrpc.AgentLogsMaxScanLines {
		lines = xrpc.AgentLogsMaxScanLines
	}
	return exec.CommandContext(ctx, "journalctl", "-u", "nginx", "-n", strconv.Itoa(lines), "--no-pager", "-o", "cat").CombinedOutput()
}

// Files 列出节点日志目录下白名单内的 agent/core 日志文件。
func (l *LogInspector) Files() (xrpc.AgentLogFilesResult, error) {
	if l == nil || l.LogDir == "" {
		return xrpc.AgentLogFilesResult{Files: []xrpc.AgentLogFileInfo{}}, nil
	}
	files, total, err := logging.Files(l.LogDir, l.AgentLogFile, l.CoreLogFile)
	if err != nil {
		return xrpc.AgentLogFilesResult{}, err
	}
	if files == nil {
		files = []xrpc.AgentLogFileInfo{}
	}
	return xrpc.AgentLogFilesResult{
		Dir:       l.LogDir,
		TotalSize: total,
		Files:     files,
	}, nil
}

// List 只读过滤、分页并按 512 KiB 载荷上限截断返回节点日志行（从新到旧）。
func (l *LogInspector) List(ctx context.Context, p xrpc.AgentLogsParams) (xrpc.AgentLogsResult, error) {
	service := strings.TrimSpace(p.Service)
	if service == "" {
		service = "agent"
	}
	switch service {
	case "agent", "core", "nginx":
	default:
		return xrpc.AgentLogsResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("不支持的 service %q（仅支持 agent、core、nginx）", service)}
	}
	minRank := -1
	if lv := strings.ToLower(strings.TrimSpace(p.Level)); lv != "" {
		r, ok := logLevelRanks[lv]
		if !ok {
			return xrpc.AgentLogsResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("不支持的 level %q（仅支持 debug、info、warn、error）", lv)}
		}
		minRank = r
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}

	if service == "nginx" {
		if strings.TrimSpace(p.File) != "" {
			return xrpc.AgentLogsResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "nginx 日志不支持 --file 参数"}
		}
		return l.listNginx(ctx, p.Grep, limit, offset)
	}

	fileName, err := l.resolveLogFile(service, strings.TrimSpace(p.File))
	if err != nil {
		return xrpc.AgentLogsResult{}, err
	}
	fullPath := filepath.Join(l.LogDir, fileName)
	lines, err := logging.Tail(fullPath, xrpc.AgentLogsMaxScanLines)
	if errors.Is(err, os.ErrNotExist) {
		return xrpc.AgentLogsResult{Service: service, File: fileName, Items: []xrpc.AgentLogEntry{}, Total: 0}, nil
	}
	if err != nil {
		return xrpc.AgentLogsResult{}, fmt.Errorf("读日志文件 %s 失败：%w", fileName, err)
	}

	matched := make([]xrpc.AgentLogEntry, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if line == "" || (p.Grep != "" && !strings.Contains(line, p.Grep)) {
			continue
		}
		e := logging.Parse(line)
		if minRank >= 0 {
			r, ok := logLevelRanks[strings.ToLower(e.Level)]
			if !ok || r < minRank {
				continue
			}
		}
		matched = append(matched, e)
	}
	return paginateCapped(service, fileName, matched, limit, offset, ""), nil
}

func (l *LogInspector) resolveLogFile(service, requested string) (string, error) {
	if l == nil || l.LogDir == "" {
		return "", &xrpc.Error{Code: xrpc.CodeFailed, Message: "节点日志目录未配置"}
	}
	if requested == "" {
		if service == "core" {
			return l.CoreLogFile, nil
		}
		return l.AgentLogFile, nil
	}
	ok, _ := logging.AllowedLogFile(requested, l.AgentLogFile, l.CoreLogFile)
	if !ok {
		return "", &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("没有日志文件 %q", requested)}
	}
	clean := filepath.Clean(filepath.Join(l.LogDir, filepath.Base(requested)))
	if filepath.Dir(clean) != filepath.Clean(l.LogDir) {
		return "", &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("没有日志文件 %q", requested)}
	}
	if _, err := os.Stat(clean); err != nil {
		return "", &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("没有日志文件 %q", requested)}
	}
	return filepath.Base(clean), nil
}

func (l *LogInspector) listNginx(ctx context.Context, grep string, limit, offset int) (xrpc.AgentLogsResult, error) {
	runFn := l.RunJournalctl
	if runFn == nil {
		runFn = defaultNginxJournalctl
	}
	var lines []string
	var msg string
	out, err := runFn(ctx, xrpc.AgentLogsMaxScanLines)
	if err == nil {
		raw := strings.TrimSpace(string(out))
		if raw != "" {
			lines = strings.Split(raw, "\n")
		}
	} else if l.NginxFallbackPath != "" {
		if fbLines, ferr := logging.Tail(l.NginxFallbackPath, xrpc.AgentLogsMaxScanLines); ferr == nil {
			lines = fbLines
		} else {
			msg = fmt.Sprintf("journalctl 不可用且无法读取 %s（可能运行在无 systemd 的容器中）", l.NginxFallbackPath)
		}
	} else {
		msg = "journalctl 不可用（可能运行在无 systemd 的容器中）"
	}

	matched := make([]xrpc.AgentLogEntry, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || (grep != "" && !strings.Contains(line, grep)) {
			continue
		}
		matched = append(matched, xrpc.AgentLogEntry{Raw: line})
	}
	return paginateCapped("nginx", "", matched, limit, offset, msg), nil
}

// paginateCapped 按页切片并强制序列化载荷不超过 xrpc.AgentLogsMaxReplyBytes（512 KiB）。
func paginateCapped(service, file string, matched []xrpc.AgentLogEntry, limit, offset int, msg string) xrpc.AgentLogsResult {
	res := xrpc.AgentLogsResult{
		Service: service,
		File:    file,
		Items:   []xrpc.AgentLogEntry{},
		Total:   len(matched),
		Message: msg,
	}
	if offset >= len(matched) {
		return res
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	// 预留固定信封开销，逐条累加不超过 512 KiB 上限。
	const envelopeMargin = 4096
	budget := xrpc.AgentLogsMaxReplyBytes - envelopeMargin
	used := 0
	for _, item := range matched[offset:end] {
		b, err := json.Marshal(item)
		if err != nil {
			continue
		}
		if used+len(b)+1 > budget {
			if len(res.Items) == 0 && len(b)+1 > budget {
				// 单行超大时截断 Raw/Msg，保证整包严格不超过 512 KiB。
				maxStr := budget / 2
				if len(item.Raw) > maxStr {
					item.Raw = item.Raw[:maxStr] + "...(truncated)"
				}
				if len(item.Msg) > maxStr {
					item.Msg = item.Msg[:maxStr] + "...(truncated)"
				}
				item.Attrs = nil
				res.Items = append(res.Items, item)
			}
			res.Truncated = true
			break
		}
		res.Items = append(res.Items, item)
		used += len(b) + 1
	}
	return res
}

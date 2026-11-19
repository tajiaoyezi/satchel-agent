package logging

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"
)

const tailChunk = 64 << 10

// Tail 从文件末尾往前读出最多 n 行，按文件先后顺序返回；末尾未换行的半行不计。
func Tail(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var chunks [][]byte
	newlines := 0
	pos := info.Size()
	for pos > 0 && newlines <= n {
		step := int64(tailChunk)
		if pos < step {
			step = pos
		}
		pos -= step
		b := make([]byte, step)
		if _, err := f.ReadAt(b, pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		chunks = append(chunks, b)
		newlines += bytes.Count(b, []byte{'\n'})
	}
	var buf bytes.Buffer
	for i := len(chunks) - 1; i >= 0; i-- {
		buf.Write(chunks[i])
	}
	data := buf.Bytes()
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		if len(data) == 0 {
			return nil, nil
		}
		return []string{string(data)}, nil
	}
	lines := strings.Split(string(data[:end]), "\n")
	if pos > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// Parse 把一行 slog 文本格式拆成结构化条目；拆不开时保留 Raw 原文。
func Parse(line string) xrpc.AgentLogEntry {
	raw := xrpc.AgentLogEntry{Raw: line}
	attrs := map[string]string{}
	s := line
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || strings.ContainsAny(s[:eq], " \"") {
			return raw
		}
		key := s[:eq]
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			q, err := strconv.QuotedPrefix(s)
			if err != nil {
				return raw
			}
			if val, err = strconv.Unquote(q); err != nil {
				return raw
			}
			s = s[len(q):]
		} else if sp := strings.IndexByte(s, ' '); sp >= 0 {
			val, s = s[:sp], s[sp:]
		} else {
			val, s = s, ""
		}
		attrs[key] = val
	}
	e := xrpc.AgentLogEntry{Time: attrs["time"], Level: attrs["level"], Msg: attrs["msg"]}
	for _, k := range []string{"time", "level", "msg"} {
		if _, ok := attrs[k]; !ok {
			return raw
		}
		delete(attrs, k)
	}
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	return e
}

// AllowedLogFile 报告 name 是否属于给定 agent/core 日志文件名或其 lumberjack 轮转文件。
func AllowedLogFile(name, agentFile, coreFile string) (allowed, active bool) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false, false
	}
	if agentFile == "" {
		agentFile = DefaultAgentLogFile
	}
	if coreFile == "" {
		coreFile = CoreLogFile
	}
	agentBase := filepath.Base(agentFile)
	coreBase := filepath.Base(coreFile)
	if name == agentBase || name == coreBase {
		return true, true
	}
	for _, base := range []string{agentBase, coreBase} {
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		if ext != "" && strings.HasPrefix(name, stem+"-") && strings.HasSuffix(name, ext) {
			return true, false
		}
	}
	return false, false
}

// Files 列出 dir 下所有合法白名单 agent/core 日志文件（活跃文件排最前，其余按修改时间倒序）。
func Files(dir, agentFile, coreFile string) ([]xrpc.AgentLogFileInfo, int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []xrpc.AgentLogFileInfo{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	out := make([]xrpc.AgentLogFileInfo, 0, len(entries))
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		ok, active := AllowedLogFile(e.Name(), agentFile, coreFile)
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		total += info.Size()
		out = append(out, xrpc.AgentLogFileInfo{
			Name:     e.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().UTC(),
			Active:   active,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if !out[i].Modified.Equal(out[j].Modified) {
			return out[i].Modified.After(out[j].Modified)
		}
		return out[i].Name < out[j].Name
	})
	return out, total, nil
}

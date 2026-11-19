package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	singlog "github.com/sagernet/sing-box/log"
)

func TestSetupPermsLevelSwitchRedactionAndFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	agentLog := filepath.Join(dir, DefaultAgentLogFile)
	var stderr bytes.Buffer
	ls, err := Setup(agentLog, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer ls.Close()

	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("日志目录权限应为 0700，得到 %v %v", dirInfo.Mode().Perm(), err)
	}
	for _, p := range []string{ls.AgentLogPath, ls.CoreLogPath} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("日志文件 %s 权限应为 0600，得到 %v %v", p, fi.Mode().Perm(), err)
		}
	}

	// 默认 INFO 级别不落 DEBUG；脱敏覆盖 password/secret/*token 但保留 token_id。
	ls.Logger.Debug("hidden-debug-line")
	ls.Logger.Info("hello", "password", "p1", "client_secret", "s1", "agent_token", "t1", "token_id", 7,
		slog.Group("secret_box", slog.String("nested", "boom")))
	ls.SetDebugEnabled(true)
	ls.Logger.Debug("visible-debug-line", "k", "v")
	ls.SetDebugEnabled(false)
	ls.Logger.Debug("hidden-again")

	ls.CorePlatformWriter().WriteMessage(singlog.LevelWarn, "sing-box warning msg")

	agentBytes, err := os.ReadFile(ls.AgentLogPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(agentBytes)
	if strings.Contains(text, "hidden-debug-line") || strings.Contains(text, "hidden-again") {
		t.Fatalf("INFO 级别下不应当写入 DEBUG 日志：%s", text)
	}
	if !strings.Contains(text, "visible-debug-line") {
		t.Fatalf("SetDebugEnabled(true) 后应当立即写入 DEBUG 日志：%s", text)
	}
	for _, leaked := range []string{"p1", "s1", "t1", "boom"} {
		if strings.Contains(text, leaked) || strings.Contains(stderr.String(), leaked) {
			t.Fatalf("敏感值 %q 应当被脱敏：%s", leaked, text)
		}
	}
	if !strings.Contains(text, "token_id=7") {
		t.Fatalf("token_id 不应误脱敏：%s", text)
	}

	coreLines, err := Tail(ls.CoreLogPath, 10)
	if err != nil || len(coreLines) != 1 {
		t.Fatalf("core.log 应当写入 1 行：%v %v", coreLines, err)
	}
	entry := Parse(coreLines[0])
	if entry.Level != "WARN" || entry.Msg != "sing-box warning msg" {
		t.Fatalf("Parse(core) 不对：%+v", entry)
	}

	// 放置一个无关文件与一个轮转备份文件，验证 Files 白名单过滤。
	if err := os.WriteFile(filepath.Join(dir, "satchel-agent-2026-11-19.log"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.txt"), []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, _, err := Files(dir, DefaultAgentLogFile, CoreLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("应当只列出 3 个白名单日志文件，得到 %+v", files)
	}
	if !files[0].Active || !files[1].Active || files[2].Active {
		t.Fatalf("活跃文件应当排在最前：%#v", files)
	}
	for _, f := range files {
		if f.Name == "evil.txt" {
			t.Fatal("无关文件不应出现在白名单文件列表中")
		}
	}
}

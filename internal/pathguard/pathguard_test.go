package pathguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectControlChars(t *testing.T) {
	if err := RejectControlChars("token", "abc_123-XYZ=="); err != nil {
		t.Fatalf("正常凭据应当通过：%v", err)
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\tb", "abc\x7f"} {
		if err := RejectControlChars("token", bad); err == nil {
			t.Fatalf("含控制字符 %q 应当被拒", bad)
		}
	}
}

func TestPathWithinDirs(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "etc", "satchel-agent")
	sibling := filepath.Join(root, "etc", "satchel-agent-evil")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := PathWithinDirs(filepath.Join(allowed, "sub", "config.yaml"), allowed)
	if err != nil || !strings.HasSuffix(got, filepath.Join("sub", "config.yaml")) {
		t.Fatalf("允许目录内的新建子路径应当通过：%q %v", got, err)
	}

	// 同前缀兄弟目录绕过与 .. 越界必须拒绝。
	if _, err := PathWithinDirs(filepath.Join(sibling, "config.yaml"), allowed); err == nil {
		t.Fatal("同前缀兄弟目录不应通过")
	}
	if _, err := PathWithinDirs(filepath.Join(allowed, "..", "outside.yaml"), allowed); err == nil {
		t.Fatal("相对穿越路径不应通过")
	}
	if _, err := PathWithinDirs("a\nb", allowed); err == nil {
		t.Fatal("含换行路径不应通过")
	}
	for _, sys := range []string{"/proc/self/environ", "/sys/kernel", "/dev/null"} {
		if _, err := PathWithinDirs(sys, "/"); err == nil {
			t.Fatalf("敏感系统路径 %s 即使基准是 / 也必须被拒", sys)
		}
	}

	// 符号链接逃逸必须拒绝。
	escape := filepath.Join(allowed, "link")
	if err := os.Symlink(sibling, escape); err == nil {
		if _, err := PathWithinDirs(filepath.Join(escape, "config.yaml"), allowed); err == nil {
			t.Fatal("指到允许目录外的软链接必须被拒")
		}
	}
}

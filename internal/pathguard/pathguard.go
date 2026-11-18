// Package pathguard 为 satchel-agent 提供配置字段控制字符拦截与路径逃逸/敏感目录校验，
// 避免 YAML 注入与路径穿越写出系统敏感路径。
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var sensitivePrefixes = []string{"/proc", "/sys", "/dev"}

// RejectControlChars 拒绝包含 ASCII 控制字符（< 0x20 或 0x7f，如 \r、\n、\x00、\t）的值，防止配置注入。
func RejectControlChars(field, val string) error {
	for i := 0; i < len(val); i++ {
		b := val[i]
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("%s 不能包含控制字符（位置 %d，字节 0x%02x）", field, i, b)
		}
	}
	return nil
}

// resolveRealPath 对可能尚未创建末端文件的路径做真实路径归一化：找到最深已存在父目录并 EvalSymlinks，再拼回剩余相对段。
func resolveRealPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	var suffix []string
	cur := abs
	for {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			out := real
			for i := len(suffix) - 1; i >= 0; i-- {
				out = filepath.Join(out, suffix[i])
			}
			return out, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
}

func isWithin(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// PathWithinDirs 校验目标路径不含控制字符、指向敏感系统路径（/proc、/sys、/dev），且在符号链接解析后仍严格落在任一允许目录内。
func PathWithinDirs(path string, allowedDirs ...string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("路径不能为空")
	}
	if err := RejectControlChars("path", path); err != nil {
		return "", err
	}
	if len(allowedDirs) == 0 {
		return "", errors.New("未提供允许的基准目录")
	}
	realTarget, err := resolveRealPath(path)
	if err != nil {
		return "", fmt.Errorf("解析目标路径 %q 失败：%w", path, err)
	}
	for _, sys := range sensitivePrefixes {
		if isWithin(realTarget, sys) {
			return "", fmt.Errorf("拒绝访问敏感系统路径 %q", realTarget)
		}
	}
	for _, dir := range allowedDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		realBase, err := resolveRealPath(dir)
		if err != nil {
			continue
		}
		if isWithin(realTarget, realBase) {
			return realTarget, nil
		}
	}
	return "", fmt.Errorf("路径 %q 超出允许目录范围", path)
}

package updater

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/satchel/satchel/pkg/release"

	"github.com/satchel/satchel-agent/internal/pathguard"
)

const (
	DefaultBinaryPath      = "/usr/local/bin/satchel-agent"
	DefaultConfigDir       = "/etc/satchel-agent"
	DefaultStateDir        = "/var/lib/satchel-agent"
	DefaultSystemdUnitPath = "/etc/systemd/system/satchel-agent.service"
	DefaultOpenRCInitPath  = "/etc/init.d/satchel-agent"
)

// DetachOptions 控制脱离服务 cgroup 派生异步卸载子进程的参数。
type DetachOptions struct {
	Root        string
	Executable  string
	Delay       time.Duration
	Execs       *ExecCounter
	SystemdRun  func(ctx context.Context, unit string, exe string, args ...string) error
	SpawnSetsid func(exe string, args ...string) error
}

// UninstallOptions 控制纯 Go 卸载器清理哪些白名单资源（绝不触碰白名单外路径）。
type UninstallOptions struct {
	Root         string
	Delay        time.Duration
	BinaryPath   string
	ConfigDir    string
	StateDir     string
	SystemdUnit  string
	OpenRCInit   string
	AllowedRoots []string // 测试注入临时根目录代替系统白名单；空时采用生产固定白名单
	RunCmd       func(ctx context.Context, name string, args ...string) error
}

// SpawnDetachedUninstall 从受控进程（如 systemd 服务）派生完全脱离其 cgroup / 进程组的卸载子进程，
// 保证先完成对主控的 RPC 确认回复并关机，子进程才执行 stop/disable 与删除文件，避免自杀导致残留。
func SpawnDetachedUninstall(ctx context.Context, opts DetachOptions) (string, error) {
	if opts.Execs != nil && opts.Execs.Running() {
		return "", ErrExecInFlight
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}
	if release.InDocker(root) {
		return "", ErrDockerRestricted
	}
	exe := strings.TrimSpace(opts.Executable)
	if exe == "" {
		var err error
		exe, err = resolveExecutable()
		if err != nil {
			return "", fmt.Errorf("解析当前可执行文件路径失败：%w", err)
		}
	}
	delay := opts.Delay
	if delay <= 0 {
		delay = time.Second
	}
	args := []string{"uninstall", "--yes", "--detach-delay", delay.String()}

	if runtime.GOOS == "linux" {
		if opts.SystemdRun != nil {
			unit := "satchel-agent-uninstall-" + strconv.Itoa(os.Getpid())
			if err := opts.SystemdRun(ctx, unit, exe, args...); err == nil {
				return "systemd-run", nil
			}
		} else if sdBin, err := exec.LookPath("systemd-run"); err == nil {
			if _, statErr := os.Stat(filepath.Join(root, "run", "systemd", "system")); statErr == nil {
				unit := "satchel-agent-uninstall-" + strconv.Itoa(os.Getpid())
				sdArgs := append([]string{"--unit=" + unit, "--quiet", "--collect", exe}, args...)
				cmd := exec.CommandContext(ctx, sdBin, sdArgs...)
				if err := cmd.Run(); err == nil {
					return "systemd-run", nil
				}
			}
		}
	}

	if opts.SpawnSetsid != nil {
		if err := opts.SpawnSetsid(exe, args...); err != nil {
			return "", err
		}
		return "setsid", nil
	}

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin = devNull
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer devNull.Close()
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("派生脱离进程组卸载器失败：%w", err)
	}
	_ = cmd.Process.Release()
	return "setsid", nil
}

// ValidateUninstallPath 强制检验 p 经符号链接归一后严格属于白名单目录，绝不删除白名单以外的系统或用户文件。
func ValidateUninstallPath(p string, allowedRoots []string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("卸载目标路径不能为空")
	}
	cleaned := filepath.Clean(p)
	if cleaned == "/" || cleaned == "." {
		return "", fmt.Errorf("拒绝删除根目录或当前目录 %q", p)
	}
	roots := allowedRoots
	if len(roots) == 0 {
		roots = []string{
			DefaultBinaryPath,
			release.PreviousPath(DefaultBinaryPath),
			DefaultConfigDir,
			DefaultStateDir,
			DefaultSystemdUnitPath,
			DefaultOpenRCInitPath,
		}
	}
	return pathguard.PathWithinDirs(cleaned, roots...)
}

// RunUninstall 纯 Go 停止并停用服务后清理二进制、.bak、服务文件及配置/状态目录。
func RunUninstall(ctx context.Context, opts UninstallOptions) error {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	if release.InDocker(root) {
		return ErrDockerRestricted
	}

	binPath := firstNonEmpty(opts.BinaryPath, DefaultBinaryPath)
	bakPath := release.PreviousPath(binPath)
	cfgDir := firstNonEmpty(opts.ConfigDir, DefaultConfigDir)
	stateDir := firstNonEmpty(opts.StateDir, DefaultStateDir)
	sdUnit := firstNonEmpty(opts.SystemdUnit, DefaultSystemdUnitPath)
	rcInit := firstNonEmpty(opts.OpenRCInit, DefaultOpenRCInitPath)

	targets := []struct {
		path      string
		recursive bool
	}{
		{sdUnit, false},
		{rcInit, false},
		{binPath, false},
		{bakPath, false},
		{cfgDir, true},
		{stateDir, true},
	}
	validated := make([]struct {
		realPath  string
		recursive bool
	}, 0, len(targets))
	for _, tg := range targets {
		realPath, err := ValidateUninstallPath(tg.path, opts.AllowedRoots)
		if err != nil {
			return fmt.Errorf("卸载白名单拦截路径 %q：%w", tg.path, err)
		}
		validated = append(validated, struct {
			realPath  string
			recursive bool
		}{realPath: realPath, recursive: tg.recursive})
	}

	if opts.Delay > 0 {
		t := time.NewTimer(opts.Delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}

	runCmd := opts.RunCmd
	if runCmd == nil {
		runCmd = func(cctx context.Context, name string, args ...string) error {
			cmd := exec.CommandContext(cctx, name, args...)
			return cmd.Run()
		}
	}

	if _, err := os.Stat(sdUnit); err == nil {
		if opts.RunCmd != nil || hasExe("systemctl") {
			_ = runCmd(ctx, "systemctl", "disable", "--now", "satchel-agent")
		}
	}
	if _, err := os.Stat(rcInit); err == nil {
		if opts.RunCmd != nil || hasExe("rc-service") {
			_ = runCmd(ctx, "rc-service", "satchel-agent", "stop")
			_ = runCmd(ctx, "rc-update", "del", "satchel-agent", "default")
		}
	}

	var errs []error
	for _, item := range validated {
		if item.recursive {
			if err := os.RemoveAll(item.realPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
			continue
		}
		if err := os.Remove(item.realPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if _, err := os.Stat(sdUnit); os.IsNotExist(err) && (opts.RunCmd != nil || hasExe("systemctl")) {
		_ = runCmd(ctx, "systemctl", "daemon-reload")
	}
	if len(errs) > 0 {
		return fmt.Errorf("卸载清理存在失败项：%v", errs)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if s := strings.TrimSpace(a); s != "" {
		return s
	}
	return b
}

func hasExe(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

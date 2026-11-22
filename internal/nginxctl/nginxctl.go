// Package nginxctl 为 satchel-agent 提供纯 Go 的 nginx 生命周期管理、服务状态与启停、
// server/stream 配置解析以及带路径守卫、未纳管标记守卫、同机 443 防抢占守卫与失败自动回滚的原子配置事务。
package nginxctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/satchel/satchel/pkg/release"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/pathguard"
)

const (
	DefaultRootDir     = "/etc/nginx"
	ManagedSitePrefix  = "satchel-site-"
	ManagedStealFile   = "satchel-steal.conf"
	MasterHTTPS443File = "master_https_443.conf"
	initSystemSystemd  = "systemd"
	initSystemOpenRC   = "openrc"
	initSystemDirect   = "direct"
)

// Runner 抽象外部命令执行与二进制探测，便于生产执行系统命令、单测注入伪造执行器。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	LookPath(file string) (string, error)
}

// ExecRunner 使用 os/exec 执行真实系统命令。
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RunDetached 启动可能自行 daemonize 的命令：将 stdout/stderr 重定向到普通临时文件而非管道，
// 避免后台子进程继承管道写端导致 Go cmd.CombinedOutput() 永久阻塞。
func (ExecRunner) RunDetached(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	tmp, err := os.CreateTemp("", "satchel-nginx-cmd-*.log")
	if err != nil {
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		return "", cmd.Run()
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	cmd.Stdin = nil
	cmd.Stdout = tmp
	cmd.Stderr = tmp
	runErr := cmd.Run()
	_ = tmp.Close()
	raw, _ := os.ReadFile(tmpPath)
	return string(raw), runErr
}

func (ExecRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

type detachedRunner interface {
	RunDetached(ctx context.Context, name string, args ...string) (string, error)
}

// Options 配置 nginx 控制器。
type Options struct {
	RootDir      string
	InDocker     func() bool
	Runner       Runner
	NginxMu      *sync.Mutex
	PIDFiles     []string
	CheckRunning func(ctx context.Context, initSys string) bool
}

// Controller 管理节点上的 nginx 服务与受管配置目录。
type Controller struct {
	rootDir      string
	inDockerFn   func() bool
	runner       Runner
	mu           *sync.Mutex
	pidFiles     []string
	checkRunning func(ctx context.Context, initSys string) bool
}

// New 构造 nginx 控制器。
func New(opts Options) *Controller {
	root := strings.TrimSpace(opts.RootDir)
	if root == "" {
		root = DefaultRootDir
	}
	inDocker := opts.InDocker
	if inDocker == nil {
		inDocker = func() bool { return release.InDocker("/") }
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	mu := opts.NginxMu
	if mu == nil {
		mu = &sync.Mutex{}
	}
	pidFiles := opts.PIDFiles
	if len(pidFiles) == 0 {
		pidFiles = []string{"/run/nginx.pid", "/var/run/nginx.pid", "/var/run/nginx/nginx.pid", "/tmp/nginx.pid"}
	}
	return &Controller{
		rootDir:      filepath.Clean(root),
		inDockerFn:   inDocker,
		runner:       runner,
		mu:           mu,
		pidFiles:     pidFiles,
		checkRunning: opts.CheckRunning,
	}
}

func (c *Controller) serversDir() string       { return filepath.Join(c.rootDir, "servers") }
func (c *Controller) streamServersDir() string { return filepath.Join(c.rootDir, "stream_servers") }
func (c *Controller) htmlDir() string          { return filepath.Join(c.rootDir, "html") }
func (c *Controller) certDir() string          { return filepath.Join(c.rootDir, "cert") }
func (c *Controller) mainConfPath() string     { return filepath.Join(c.rootDir, "nginx.conf") }

func (c *Controller) nginxArgs(extra ...string) []string {
	if c.rootDir != DefaultRootDir {
		if fi, err := os.Stat(c.mainConfPath()); err == nil && fi.Mode().IsRegular() {
			return append([]string{"-c", c.mainConfPath()}, extra...)
		}
	}
	return extra
}

func (c *Controller) inDocker() bool {
	return c.inDockerFn != nil && c.inDockerFn()
}

func (c *Controller) isInstalled() bool {
	p, err := c.runner.LookPath("nginx")
	return err == nil && strings.TrimSpace(p) != ""
}

func (c *Controller) detectInitSystem(installed bool) string {
	if !installed {
		return ""
	}
	if !c.inDocker() {
		if _, err := c.runner.LookPath("systemctl"); err == nil {
			if fi, serr := os.Stat("/run/systemd/system"); serr == nil && fi.IsDir() {
				return initSystemSystemd
			}
		}
		if _, err := c.runner.LookPath("rc-service"); err == nil {
			return initSystemOpenRC
		}
	}
	return initSystemDirect
}

var nginxVersionRe = regexp.MustCompile(`nginx/([0-9A-Za-z._-]+)`)

func (c *Controller) nginxVersion(ctx context.Context) string {
	out, _ := c.runner.Run(ctx, "nginx", "-v")
	if m := nginxVersionRe.FindStringSubmatch(out); len(m) == 2 {
		return m[1]
	}
	return ""
}

func (c *Controller) isRunning(ctx context.Context, initSys string) bool {
	if c.checkRunning != nil {
		return c.checkRunning(ctx, initSys)
	}
	switch initSys {
	case initSystemSystemd:
		out, err := c.runner.Run(ctx, "systemctl", "is-active", "nginx")
		return err == nil && strings.TrimSpace(out) == "active"
	case initSystemOpenRC:
		_, err := c.runner.Run(ctx, "rc-service", "nginx", "status")
		return err == nil
	case initSystemDirect:
		if c.hasLiveNginxPID() {
			return true
		}
		if runtime.GOOS == "linux" {
			return hasLinuxProcNamed("nginx")
		}
		return false
	default:
		return false
	}
}

func (c *Controller) hasLiveNginxPID() bool {
	candidates := append([]string{}, c.pidFiles...)
	if raw, err := os.ReadFile(c.mainConfPath()); err == nil {
		if m := pidDirectiveRe.FindStringSubmatch(string(raw)); len(m) == 2 {
			candidates = append([]string{strings.TrimSpace(m[1])}, candidates...)
		}
	}
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid <= 0 {
			continue
		}
		if err := syscall.Kill(pid, 0); err == nil && !isLinuxZombie(pid) {
			return true
		}
	}
	return false
}

var pidDirectiveRe = regexp.MustCompile(`(?m)^\s*pid\s+([^;\s]+)\s*;`)

func isLinuxZombie(pid int) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// /proc/<pid>/stat 格式: "<pid> (<comm>) <state> ..."；取最后一个 ')' 防止 comm 含括号或空格。
	s := string(raw)
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 || idx+2 >= len(s) {
		return false
	}
	return s[idx+2] == 'Z'
}

func hasLinuxProcNamed(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if isLinuxZombie(pid) {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == name {
			return true
		}
	}
	return false
}

// Status 查询节点上 nginx 的安装状态、运行状态、版本、容器标记、init 方式与配置校验结果。
func (c *Controller) Status(ctx context.Context) xrpc.NginxServiceStatus {
	installed := c.isInstalled()
	inDocker := c.inDocker()
	initSys := c.detectInitSystem(installed)
	st := xrpc.NginxServiceStatus{
		Installed:  installed,
		InDocker:   inDocker,
		InitSystem: initSys,
	}
	if !installed {
		return st
	}
	st.Version = c.nginxVersion(ctx)
	st.Running = c.isRunning(ctx, initSys)
	if out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...); err != nil {
		st.ConfigOK = false
		st.Error = strings.TrimSpace(out)
		if st.Error == "" {
			st.Error = err.Error()
		}
	} else {
		st.ConfigOK = true
	}
	return st
}

// Control 对节点上的 nginx 执行 start、stop、restart 或 reload。
func (c *Controller) Control(ctx context.Context, action string) (xrpc.NginxServiceStatus, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isInstalled() {
		return c.Status(ctx), "", &xrpc.Error{Code: xrpc.CodeConflict, Message: "节点尚未安装 nginx（请先执行 server nginx install）"}
	}
	initSys := c.detectInitSystem(true)
	act := strings.ToLower(strings.TrimSpace(action))

	runTest := func() error {
		out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...)
		if err != nil {
			msg := strings.TrimSpace(out)
			if msg == "" {
				msg = err.Error()
			}
			return fmt.Errorf("nginx -t 校验失败：%s", msg)
		}
		return nil
	}

	switch act {
	case "start":
		if err := runTest(); err != nil {
			return c.Status(ctx), "", err
		}
		if c.isRunning(ctx, initSys) {
			return c.Status(ctx), "nginx 已在运行中", nil
		}
		if err := c.execStart(ctx, initSys); err != nil {
			return c.Status(ctx), "", err
		}
		return c.Status(ctx), "nginx 已启动", nil

	case "stop":
		if !c.isRunning(ctx, initSys) {
			return c.Status(ctx), "nginx 已处于停止状态", nil
		}
		if err := c.execStop(ctx, initSys); err != nil {
			return c.Status(ctx), "", err
		}
		return c.Status(ctx), "nginx 已停止", nil

	case "restart":
		if err := runTest(); err != nil {
			return c.Status(ctx), "", err
		}
		if err := c.execRestart(ctx, initSys); err != nil {
			return c.Status(ctx), "", err
		}
		return c.Status(ctx), "nginx 已重启", nil

	case "reload":
		if err := runTest(); err != nil {
			return c.Status(ctx), "", err
		}
		if !c.isRunning(ctx, initSys) {
			return c.Status(ctx), "", &xrpc.Error{Code: xrpc.CodeConflict, Message: "nginx 当前未运行，无法 reload（请先执行 start）"}
		}
		if err := c.execReload(ctx, initSys); err != nil {
			return c.Status(ctx), "", err
		}
		return c.Status(ctx), "nginx 配置已重载", nil

	default:
		return c.Status(ctx), "", &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("不支持的 nginx 动作 %q（仅支持 start/stop/restart/reload）", action)}
	}
}

func (c *Controller) execStart(ctx context.Context, initSys string) error {
	switch initSys {
	case initSystemSystemd:
		if out, err := c.runner.Run(ctx, "systemctl", "start", "nginx"); err != nil {
			return fmt.Errorf("启动 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case initSystemOpenRC:
		if out, err := c.runner.Run(ctx, "rc-service", "nginx", "start"); err != nil {
			return fmt.Errorf("启动 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	default:
		var out string
		var err error
		if dr, ok := c.runner.(detachedRunner); ok {
			out, err = dr.RunDetached(ctx, "nginx", c.nginxArgs()...)
		} else {
			out, err = c.runner.Run(ctx, "nginx", c.nginxArgs()...)
		}
		if err != nil {
			return fmt.Errorf("启动 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	}
	return nil
}

func (c *Controller) execStop(ctx context.Context, initSys string) error {
	switch initSys {
	case initSystemSystemd:
		if out, err := c.runner.Run(ctx, "systemctl", "stop", "nginx"); err != nil {
			return fmt.Errorf("停止 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case initSystemOpenRC:
		if out, err := c.runner.Run(ctx, "rc-service", "nginx", "stop"); err != nil {
			return fmt.Errorf("停止 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	default:
		if out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-s", "quit")...); err != nil {
			return fmt.Errorf("停止 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if !c.isRunning(ctx, initSys) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

func (c *Controller) execRestart(ctx context.Context, initSys string) error {
	switch initSys {
	case initSystemSystemd:
		if out, err := c.runner.Run(ctx, "systemctl", "restart", "nginx"); err != nil {
			return fmt.Errorf("重启 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case initSystemOpenRC:
		if out, err := c.runner.Run(ctx, "rc-service", "nginx", "restart"); err != nil {
			return fmt.Errorf("重启 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	default:
		if c.isRunning(ctx, initSys) {
			if err := c.execStop(ctx, initSys); err != nil {
				return err
			}
		}
		if err := c.execStart(ctx, initSys); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) execReload(ctx context.Context, initSys string) error {
	switch initSys {
	case initSystemSystemd:
		if out, err := c.runner.Run(ctx, "systemctl", "reload", "nginx"); err != nil {
			return fmt.Errorf("重载 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case initSystemOpenRC:
		if out, err := c.runner.Run(ctx, "rc-service", "nginx", "reload"); err != nil {
			return fmt.Errorf("重载 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	default:
		if out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-s", "reload")...); err != nil {
			return fmt.Errorf("重载 nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	}
	return nil
}

// Install 安装并初始化节点上的 nginx（Docker 镜像预装直接返回 already_installed=true）。
func (c *Controller) Install(ctx context.Context) (xrpc.NginxInstallResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	inDocker := c.inDocker()
	if c.isInstalled() {
		if err := c.ensureDirs(); err != nil {
			return xrpc.NginxInstallResult{}, err
		}
		_ = c.ensureMainConfIncludes(ctx)
		ver := c.nginxVersion(ctx)
		msg := "nginx 已安装，目录与配置已就绪"
		if inDocker {
			msg = "Docker 镜像已预装 nginx，跳过包管理器安装并已确认配置目录就绪"
		}
		return xrpc.NginxInstallResult{
			Installed:        true,
			AlreadyInstalled: true,
			InDocker:         inDocker,
			Version:          ver,
			Message:          msg,
		}, nil
	}
	if inDocker {
		return xrpc.NginxInstallResult{}, &xrpc.Error{
			Code:    xrpc.CodeConflict,
			Message: "当前 Docker 镜像未预装 nginx，不支持在容器内动态安装（请改用预装 nginx 的官方镜像）",
		}
	}

	pm, err := c.installViaPackageManager(ctx)
	if err != nil {
		return xrpc.NginxInstallResult{}, err
	}
	if err := c.ensureDirs(); err != nil {
		return xrpc.NginxInstallResult{}, err
	}
	_ = c.ensureMainConfIncludes(ctx)

	if out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...); err != nil {
		return xrpc.NginxInstallResult{}, fmt.Errorf("安装后 nginx -t 校验失败：%s (%w)", strings.TrimSpace(out), err)
	}
	initSys := c.detectInitSystem(true)
	if !c.isRunning(ctx, initSys) {
		if err := c.execStart(ctx, initSys); err != nil {
			return xrpc.NginxInstallResult{}, err
		}
	}
	return xrpc.NginxInstallResult{
		Installed:        true,
		AlreadyInstalled: false,
		InDocker:         false,
		Version:          c.nginxVersion(ctx),
		PackageManager:   pm,
		Message:          "已通过 " + pm + " 安装并启动 nginx",
	}, nil
}

func (c *Controller) installViaPackageManager(ctx context.Context) (string, error) {
	switch {
	case c.hasCmd("apt-get"):
		if out, err := c.runner.Run(ctx, "apt-get", "update"); err != nil {
			return "", fmt.Errorf("apt-get update 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		if out, err := c.runner.Run(ctx, "apt-get", "install", "-y", "nginx"); err != nil {
			return "", fmt.Errorf("apt-get install nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		return "apt-get", nil
	case c.hasCmd("dnf"):
		if out, err := c.runner.Run(ctx, "dnf", "install", "-y", "nginx"); err != nil {
			return "", fmt.Errorf("dnf install nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		return "dnf", nil
	case c.hasCmd("yum"):
		if out, err := c.runner.Run(ctx, "yum", "install", "-y", "nginx"); err != nil {
			return "", fmt.Errorf("yum install nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		return "yum", nil
	case c.hasCmd("apk"):
		if out, err := c.runner.Run(ctx, "apk", "add", "--no-cache", "nginx"); err != nil {
			return "", fmt.Errorf("apk add nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
		return "apk", nil
	default:
		return "", &xrpc.Error{Code: xrpc.CodeConflict, Message: "未检测到支持的包管理器（apt-get / dnf / yum / apk），无法自动安装 nginx"}
	}
}

func (c *Controller) hasCmd(name string) bool {
	p, err := c.runner.LookPath(name)
	return err == nil && strings.TrimSpace(p) != ""
}

// Uninstall 卸载节点上的 nginx（Docker 容器内直接拒绝）。
func (c *Controller) Uninstall(ctx context.Context) (xrpc.NginxUninstallResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.inDocker() {
		return xrpc.NginxUninstallResult{}, &xrpc.Error{
			Code:    xrpc.CodeConflict,
			Message: "Docker 容器镜像内置 nginx，不支持远程卸载（请停止移除容器或更换镜像）",
		}
	}
	if !c.isInstalled() {
		return xrpc.NginxUninstallResult{
			Uninstalled: true,
			InDocker:    false,
			Message:     "节点未安装 nginx",
		}, nil
	}
	initSys := c.detectInitSystem(true)
	if c.isRunning(ctx, initSys) {
		_ = c.execStop(ctx, initSys)
	}
	switch {
	case c.hasCmd("apt-get"):
		if out, err := c.runner.Run(ctx, "apt-get", "remove", "-y", "nginx", "nginx-common"); err != nil {
			return xrpc.NginxUninstallResult{}, fmt.Errorf("apt-get remove nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case c.hasCmd("dnf"):
		if out, err := c.runner.Run(ctx, "dnf", "remove", "-y", "nginx"); err != nil {
			return xrpc.NginxUninstallResult{}, fmt.Errorf("dnf remove nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case c.hasCmd("yum"):
		if out, err := c.runner.Run(ctx, "yum", "remove", "-y", "nginx"); err != nil {
			return xrpc.NginxUninstallResult{}, fmt.Errorf("yum remove nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	case c.hasCmd("apk"):
		if out, err := c.runner.Run(ctx, "apk", "del", "nginx"); err != nil {
			return xrpc.NginxUninstallResult{}, fmt.Errorf("apk del nginx 失败：%s (%w)", strings.TrimSpace(out), err)
		}
	default:
		return xrpc.NginxUninstallResult{}, &xrpc.Error{Code: xrpc.CodeConflict, Message: "未检测到支持的包管理器，无法自动卸载 nginx"}
	}
	return xrpc.NginxUninstallResult{
		Uninstalled: true,
		InDocker:    false,
		Message:     "nginx 已停止并卸载",
	}, nil
}

func (c *Controller) ensureDirs() error {
	for _, dir := range []string{c.serversDir(), c.streamServersDir(), c.htmlDir(), c.certDir()} {
		if _, err := pathguard.PathWithinDirs(dir, c.rootDir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建目录 %s 失败：%w", dir, err)
		}
	}
	return nil
}

func (c *Controller) ensureMainConfIncludes(ctx context.Context) error {
	mainPath := c.mainConfPath()
	rawBytes, err := os.ReadFile(mainPath)
	if err != nil {
		return err
	}
	orig := string(rawBytes)
	updated := orig

	httpInc := fmt.Sprintf("include %s/*.conf;", filepath.ToSlash(c.serversDir()))
	if !strings.Contains(updated, "servers/*.conf") {
		if idx := findHTTPBlockClose(updated); idx > 0 {
			updated = updated[:idx] + "\n    " + httpInc + "\n" + updated[idx:]
			if err := atomicWriteFile(mainPath, []byte(updated), 0o644); err == nil {
				if _, terr := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...); terr != nil {
					_ = atomicWriteFile(mainPath, rawBytes, 0o644)
					updated = orig
				}
			}
		}
	}

	if !strings.Contains(updated, "stream_servers/*.conf") {
		beforeStream := []byte(updated)
		streamBlock := fmt.Sprintf("\nstream {\n    include %s/*.conf;\n}\n", filepath.ToSlash(c.streamServersDir()))
		cand := updated + streamBlock
		if err := atomicWriteFile(mainPath, []byte(cand), 0o644); err == nil {
			if _, terr := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...); terr != nil {
				// 若当前 nginx 未启用 stream 模块，回滚 stream 块但保留已验证通过的 HTTP include。
				_ = atomicWriteFile(mainPath, beforeStream, 0o644)
			} else {
				updated = cand
			}
		}
	}
	if updated != orig {
		initSys := c.detectInitSystem(true)
		if c.isRunning(ctx, initSys) {
			_ = c.execReload(ctx, initSys)
		}
	}
	return nil
}

// hasMaster443OnDisk 检测 /etc/nginx/stream_servers 下是否存在主控 443 stream 保护文件或标记。
func (c *Controller) hasMaster443OnDisk() bool {
	dir := c.streamServersDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if e.Name() == MasterHTTPS443File {
			return true
		}
		full := filepath.Join(dir, e.Name())
		if _, err := pathguard.PathWithinDirs(full, dir); err != nil {
			continue
		}
		if raw, err := os.ReadFile(full); err == nil && strings.Contains(string(raw), xrpc.SatchelMaster443Marker) {
			return true
		}
	}
	return false
}

// ClearStream 清理 /etc/nginx/stream_servers 下监听指定端口且带 # satchel-managed: 标记的配置，
// 严格保护主控同机 443 与未纳管文件，失败时原子恢复。
func (c *Controller) ClearStream(ctx context.Context, params xrpc.NginxClearStreamParams) (xrpc.NginxClearStreamResult, error) {
	if params.Port < 1 || params.Port > 65535 {
		return xrpc.NginxClearStreamResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("端口必须在 1..65535 之间，得到 %d", params.Port)}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	protect443 := params.ProtectMaster443 || c.hasMaster443OnDisk()
	if params.Port == 443 && protect443 {
		return xrpc.NginxClearStreamResult{}, &xrpc.Error{
			Code:    xrpc.CodeConflict,
			Message: "主控同机 443 防抢占守卫生效，禁止清理 443 端口的 stream 配置",
		}
	}

	dir := c.streamServersDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return xrpc.NginxClearStreamResult{
				Port:         params.Port,
				RemovedFiles: []string{},
				Reloaded:     false,
				Message:      "stream_servers 目录不存在，无可清理配置",
			}, nil
		}
		return xrpc.NginxClearStreamResult{}, fmt.Errorf("读取 stream_servers 目录失败：%w", err)
	}

	portStr := strconv.Itoa(params.Port)
	var toRemove []fileSnapshot
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		realPath, err := pathguard.PathWithinDirs(full, dir)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(realPath)
		if err != nil {
			continue
		}
		content := string(raw)
		// 永远保护主控 443 文件
		if e.Name() == MasterHTTPS443File || strings.Contains(content, xrpc.SatchelMaster443Marker) {
			if streamListensOnPort(content, portStr) {
				return xrpc.NginxClearStreamResult{}, &xrpc.Error{
					Code:    xrpc.CodeConflict,
					Message: fmt.Sprintf("文件 %s 受主控 443 守卫保护，禁止清理", full),
				}
			}
			continue
		}
		if !streamListensOnPort(content, portStr) {
			continue
		}
		// 未带 # satchel-managed: 的手工文件绝不删除
		if !HasManagedHeader(content) {
			continue
		}
		fi, statErr := os.Stat(realPath)
		perm := os.FileMode(0o644)
		if statErr == nil {
			perm = fi.Mode().Perm()
		}
		toRemove = append(toRemove, fileSnapshot{path: full, existed: true, data: raw, perm: perm})
	}

	if len(toRemove) == 0 {
		return xrpc.NginxClearStreamResult{
			Port:         params.Port,
			RemovedFiles: []string{},
			Reloaded:     false,
			Message:      fmt.Sprintf("未发现监听端口 %d 的 Satchel 纳管 stream 配置", params.Port),
		}, nil
	}

	removed := make([]string, 0, len(toRemove))
	for _, snap := range toRemove {
		if err := os.Remove(snap.path); err != nil {
			rbErr := restoreSnapshots(toRemove)
			return xrpc.NginxClearStreamResult{
				Port:          params.Port,
				RemovedFiles:  []string{},
				RolledBack:    rbErr == "",
				RollbackError: rbErr,
				Message:       "删除 stream 配置失败：" + err.Error(),
			}, fmt.Errorf("删除 %s 失败：%w", snap.path, err)
		}
		removed = append(removed, snap.path)
	}
	sort.Strings(removed)

	reloaded, txErr := c.testAndReload(ctx)
	if txErr != nil {
		rbErr := restoreSnapshots(toRemove)
		return xrpc.NginxClearStreamResult{
			Port:          params.Port,
			RemovedFiles:  []string{},
			Reloaded:      false,
			RolledBack:    rbErr == "",
			RollbackError: rbErr,
			Message:       txErr.Error(),
		}, nil
	}

	return xrpc.NginxClearStreamResult{
		Port:         params.Port,
		RemovedFiles: removed,
		Reloaded:     reloaded,
		Message:      fmt.Sprintf("已清理 %d 份端口 %d 的 Satchel stream 配置", len(removed), params.Port),
	}, nil
}

// ApplyWebsites 原子落盘主控下发的受管站点配置、移除列表以及可选的偷自己配置，执行三重守卫、nginx -t 校验与重载，失败自动回滚。
func (c *Controller) ApplyWebsites(ctx context.Context, params xrpc.NginxWebsitesApplyParams) (xrpc.NginxWebsitesApplyResult, error) {
	if params.StealSite != nil && params.RemoveSteal {
		return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
			Code:    xrpc.CodeBadParams,
			Message: "steal_site 与 remove_steal 互斥，不能同时设置",
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isInstalled() {
		return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeConflict, Message: "节点尚未安装 nginx，无法应用站点配置"}
	}
	if err := c.ensureDirs(); err != nil {
		return xrpc.NginxWebsitesApplyResult{}, err
	}

	protect443 := params.ProtectMaster443 || c.hasMaster443OnDisk()
	serversDir := c.serversDir()
	htmlDir := c.htmlDir()

	type writeOp struct {
		domain   string
		confPath string
		conf     []byte
		htmlPath string
		html     []byte
	}
	ops := make([]writeOp, 0, len(params.Sites))
	keepConfPaths := map[string]bool{}
	snapshots := make([]fileSnapshot, 0, len(params.Sites)*2+len(params.RemoveDomains)+2)
	snapSeen := map[string]bool{}

	recordSnap := func(target string) error {
		if snapSeen[target] {
			return nil
		}
		snapSeen[target] = true
		raw, err := os.ReadFile(target)
		if errors.Is(err, os.ErrNotExist) {
			snapshots = append(snapshots, fileSnapshot{path: target, existed: false, perm: 0o644})
			return nil
		}
		if err != nil {
			return fmt.Errorf("快照旧文件 %s 失败：%w", target, err)
		}
		perm := os.FileMode(0o644)
		if fi, serr := os.Stat(target); serr == nil {
			perm = fi.Mode().Perm()
		}
		snapshots = append(snapshots, fileSnapshot{path: target, existed: true, data: raw, perm: perm})
		return nil
	}

	// 1. 预检全部待写入站点（路径守卫、标记守卫、未纳管防覆盖守卫、同机 443 守卫）。
	for _, s := range params.Sites {
		dom, err := sanitizeDomain(s.Domain)
		if err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
		}
		if !HasManagedHeader(s.Conf) {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeBadParams,
				Message: fmt.Sprintf("站点 %s 配置缺少 %s 标记", dom, xrpc.SatchelManagedHeader),
			}
		}
		if protect443 && HasPort443Listen(s.Conf) {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeConflict,
				Message: fmt.Sprintf("同机 443 防抢占守卫生效，拒绝写入监听 443 端口的站点 %s", dom),
			}
		}
		confPath := filepath.Join(serversDir, ManagedSitePrefix+dom+".conf")
		if _, err := pathguard.PathWithinDirs(confPath, serversDir); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "站点配置路径越界：" + err.Error()}
		}
		// 若磁盘上已存在同名文件，必须带 # satchel-managed: 才允许覆盖。
		if existing, err := os.ReadFile(confPath); err == nil {
			if !HasManagedHeader(string(existing)) {
				return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
					Code:    xrpc.CodeConflict,
					Message: fmt.Sprintf("拒绝覆盖未纳管的 nginx 配置文件 %s（缺少 %s 标记）", confPath, xrpc.SatchelManagedHeader),
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return xrpc.NginxWebsitesApplyResult{}, fmt.Errorf("读取 %s 失败：%w", confPath, err)
		}
		if err := recordSnap(confPath); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, err
		}

		var mappedHTML string
		var htmlData []byte
		if strings.TrimSpace(s.HTMLPath) != "" && s.HTMLContent != "" {
			mappedHTML = c.remapHTMLPath(s.HTMLPath)
			if _, err := pathguard.PathWithinDirs(mappedHTML, htmlDir); err != nil {
				return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "静态页路径越界：" + err.Error()}
			}
			// 静态页仅在不存在或原本为 Satchel 生成的默认页时写入，避免覆盖用户手工上传页面。
			if existingHTML, err := os.ReadFile(mappedHTML); errors.Is(err, os.ErrNotExist) ||
				(err == nil && strings.HasPrefix(string(existingHTML), "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>")) {
				if err := recordSnap(mappedHTML); err != nil {
					return xrpc.NginxWebsitesApplyResult{}, err
				}
				htmlData = []byte(s.HTMLContent)
			} else {
				mappedHTML = ""
			}
		}
		confBytes := []byte(c.remapConfRootDir(s.Conf))
		keepConfPaths[confPath] = true
		ops = append(ops, writeOp{
			domain:   dom,
			confPath: confPath,
			conf:     confBytes,
			htmlPath: mappedHTML,
			html:     htmlData,
		})
	}

	// 2. 预检全部待移除站点（路径守卫 + 未纳管保护守卫）。
	type removeOp struct {
		domain   string
		confPath string
	}
	var removals []removeOp
	for _, rawDom := range params.RemoveDomains {
		dom, err := sanitizeDomain(rawDom)
		if err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
		}
		confPath := filepath.Join(serversDir, ManagedSitePrefix+dom+".conf")
		if keepConfPaths[confPath] {
			continue
		}
		if _, err := pathguard.PathWithinDirs(confPath, serversDir); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "待删除站点路径越界：" + err.Error()}
		}
		existing, err := os.ReadFile(confPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return xrpc.NginxWebsitesApplyResult{}, fmt.Errorf("检查待删除文件 %s 失败：%w", confPath, err)
		}
		if !HasManagedHeader(string(existing)) {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeConflict,
				Message: fmt.Sprintf("拒绝删除未纳管的 nginx 配置文件 %s（缺少 %s 标记）", confPath, xrpc.SatchelManagedHeader),
			}
		}
		if err := recordSnap(confPath); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, err
		}
		removals = append(removals, removeOp{domain: dom, confPath: confPath})
	}

	// 2.5 预检偷自己配置文件（固定 satchel-steal.conf，与常规站点共享同一快照与回滚事务）。
	var stealWrite *writeOp
	var stealRemovePath string
	if params.StealSite != nil {
		if !HasManagedHeader(params.StealSite.Conf) {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeBadParams,
				Message: fmt.Sprintf("偷自己配置缺少 %s 标记", xrpc.SatchelManagedHeader),
			}
		}
		if protect443 && HasPort443Listen(params.StealSite.Conf) {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeConflict,
				Message: "同机 443 防抢占守卫生效，拒绝写入监听 443 端口的偷自己配置",
			}
		}
		stealPath := filepath.Join(serversDir, ManagedStealFile)
		if _, err := pathguard.PathWithinDirs(stealPath, serversDir); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "偷自己配置路径越界：" + err.Error()}
		}
		if existing, err := os.ReadFile(stealPath); err == nil {
			if !HasManagedHeader(string(existing)) {
				return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
					Code:    xrpc.CodeConflict,
					Message: fmt.Sprintf("拒绝覆盖未纳管的 nginx 配置文件 %s（缺少 %s 标记）", stealPath, xrpc.SatchelManagedHeader),
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return xrpc.NginxWebsitesApplyResult{}, fmt.Errorf("读取 %s 失败：%w", stealPath, err)
		}
		if err := recordSnap(stealPath); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, err
		}
		var mappedHTML string
		var htmlData []byte
		if strings.TrimSpace(params.StealSite.HTMLPath) != "" && params.StealSite.HTMLContent != "" {
			mappedHTML = c.remapHTMLPath(params.StealSite.HTMLPath)
			if _, err := pathguard.PathWithinDirs(mappedHTML, htmlDir); err != nil {
				return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "偷自己伪装页路径越界：" + err.Error()}
			}
			if existingHTML, err := os.ReadFile(mappedHTML); errors.Is(err, os.ErrNotExist) ||
				(err == nil && strings.HasPrefix(string(existingHTML), "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>")) {
				if err := recordSnap(mappedHTML); err != nil {
					return xrpc.NginxWebsitesApplyResult{}, err
				}
				htmlData = []byte(params.StealSite.HTMLContent)
			} else {
				mappedHTML = ""
			}
		}
		stealWrite = &writeOp{
			domain:   strings.ToLower(strings.TrimSpace(params.StealSite.Domain)),
			confPath: stealPath,
			conf:     []byte(c.remapConfRootDir(params.StealSite.Conf)),
			htmlPath: mappedHTML,
			html:     htmlData,
		}
	} else if params.RemoveSteal {
		stealPath := filepath.Join(serversDir, ManagedStealFile)
		if _, err := pathguard.PathWithinDirs(stealPath, serversDir); err != nil {
			return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "待删除偷自己配置路径越界：" + err.Error()}
		}
		existing, err := os.ReadFile(stealPath)
		if err == nil {
			if !HasManagedHeader(string(existing)) {
				return xrpc.NginxWebsitesApplyResult{}, &xrpc.Error{
					Code:    xrpc.CodeConflict,
					Message: fmt.Sprintf("拒绝删除未纳管的 nginx 配置文件 %s（缺少 %s 标记）", stealPath, xrpc.SatchelManagedHeader),
				}
			}
			if err := recordSnap(stealPath); err != nil {
				return xrpc.NginxWebsitesApplyResult{}, err
			}
			stealRemovePath = stealPath
		} else if !errors.Is(err, os.ErrNotExist) {
			return xrpc.NginxWebsitesApplyResult{}, fmt.Errorf("检查待删除偷自己配置 %s 失败：%w", stealPath, err)
		}
	}

	// 3. 原子落盘全部文件与删除。
	appliedFiles := make([]xrpc.AppliedWebsiteFile, 0, len(ops))
	for _, op := range ops {
		if op.htmlPath != "" && len(op.html) > 0 {
			if err := atomicWriteFile(op.htmlPath, op.html, 0o644); err != nil {
				rbErr := restoreSnapshots(snapshots)
				return xrpc.NginxWebsitesApplyResult{
					Applied:       []xrpc.AppliedWebsiteFile{},
					Removed:       []string{},
					RolledBack:    rbErr == "",
					RollbackError: rbErr,
					Error:         "写入站点静态页失败：" + err.Error(),
				}, nil
			}
		}
		if err := atomicWriteFile(op.confPath, op.conf, 0o644); err != nil {
			rbErr := restoreSnapshots(snapshots)
			return xrpc.NginxWebsitesApplyResult{
				Applied:       []xrpc.AppliedWebsiteFile{},
				Removed:       []string{},
				RolledBack:    rbErr == "",
				RollbackError: rbErr,
				Error:         "写入站点配置失败：" + err.Error(),
			}, nil
		}
		appliedFiles = append(appliedFiles, xrpc.AppliedWebsiteFile{
			Domain:   op.domain,
			ConfPath: op.confPath,
		})
	}
	removedDomains := make([]string, 0, len(removals))
	for _, rem := range removals {
		if err := os.Remove(rem.confPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			rbErr := restoreSnapshots(snapshots)
			return xrpc.NginxWebsitesApplyResult{
				Applied:       []xrpc.AppliedWebsiteFile{},
				Removed:       []string{},
				RolledBack:    rbErr == "",
				RollbackError: rbErr,
				Error:         "删除旧站点配置失败：" + err.Error(),
			}, nil
		}
		removedDomains = append(removedDomains, rem.domain)
	}
	if stealWrite != nil {
		if stealWrite.htmlPath != "" && len(stealWrite.html) > 0 {
			if err := atomicWriteFile(stealWrite.htmlPath, stealWrite.html, 0o644); err != nil {
				rbErr := restoreSnapshots(snapshots)
				return xrpc.NginxWebsitesApplyResult{
					Applied:       []xrpc.AppliedWebsiteFile{},
					Removed:       []string{},
					RolledBack:    rbErr == "",
					RollbackError: rbErr,
					Error:         "写入偷自己伪装页失败：" + err.Error(),
				}, nil
			}
		}
		if err := atomicWriteFile(stealWrite.confPath, stealWrite.conf, 0o644); err != nil {
			rbErr := restoreSnapshots(snapshots)
			return xrpc.NginxWebsitesApplyResult{
				Applied:       []xrpc.AppliedWebsiteFile{},
				Removed:       []string{},
				RolledBack:    rbErr == "",
				RollbackError: rbErr,
				Error:         "写入偷自己配置失败：" + err.Error(),
			}, nil
		}
	}
	if stealRemovePath != "" {
		if err := os.Remove(stealRemovePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			rbErr := restoreSnapshots(snapshots)
			return xrpc.NginxWebsitesApplyResult{
				Applied:       []xrpc.AppliedWebsiteFile{},
				Removed:       []string{},
				RolledBack:    rbErr == "",
				RollbackError: rbErr,
				Error:         "删除偷自己配置失败：" + err.Error(),
			}, nil
		}
	}

	// 4. nginx -t 校验并在运行中时平滑重载；任一步失败全量回滚。
	reloaded, txErr := c.testAndReload(ctx)
	if txErr != nil {
		rbErr := restoreSnapshots(snapshots)
		return xrpc.NginxWebsitesApplyResult{
			Applied:       []xrpc.AppliedWebsiteFile{},
			Removed:       []string{},
			Reloaded:      false,
			RolledBack:    rbErr == "",
			RollbackError: rbErr,
			Error:         txErr.Error(),
		}, nil
	}

	sort.Slice(appliedFiles, func(i, j int) bool { return appliedFiles[i].Domain < appliedFiles[j].Domain })
	sort.Strings(removedDomains)
	res := xrpc.NginxWebsitesApplyResult{
		Applied:  appliedFiles,
		Removed:  removedDomains,
		Reloaded: reloaded,
	}
	if stealWrite != nil {
		res.StealApplied = true
		res.StealConfPath = stealWrite.confPath
	} else if stealRemovePath != "" {
		res.StealRemoved = true
		res.StealConfPath = stealRemovePath
	}
	return res, nil
}

func (c *Controller) remapHTMLPath(raw string) string {
	if c.rootDir == DefaultRootDir {
		return filepath.Clean(raw)
	}
	const prefix = DefaultRootDir + "/html/"
	if strings.HasPrefix(raw, prefix) {
		rel := strings.TrimPrefix(raw, prefix)
		return filepath.Join(c.htmlDir(), filepath.FromSlash(rel))
	}
	return filepath.Clean(raw)
}

func (c *Controller) remapConfRootDir(conf string) string {
	if c.rootDir == DefaultRootDir {
		return conf
	}
	return strings.ReplaceAll(conf, DefaultRootDir+"/", filepath.ToSlash(c.rootDir)+"/")
}

func (c *Controller) testAndReload(ctx context.Context) (bool, error) {
	if out, err := c.runner.Run(ctx, "nginx", c.nginxArgs("-t")...); err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		return false, fmt.Errorf("nginx -t 校验失败：%s", msg)
	}
	initSys := c.detectInitSystem(true)
	if !c.isRunning(ctx, initSys) {
		return false, nil
	}
	if err := c.execReload(ctx, initSys); err != nil {
		return false, err
	}
	return true, nil
}

type fileSnapshot struct {
	path    string
	existed bool
	data    []byte
	perm    os.FileMode
}

func restoreSnapshots(snaps []fileSnapshot) string {
	var errs []string
	for i := len(snaps) - 1; i >= 0; i-- {
		s := snaps[i]
		if s.existed {
			if err := atomicWriteFile(s.path, s.data, s.perm); err != nil {
				errs = append(errs, fmt.Sprintf("恢复 %s 失败: %v", s.path, err))
			}
		} else {
			if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("清理新建 %s 失败: %v", s.path, err))
			}
		}
	}
	return strings.Join(errs, "; ")
}

func atomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

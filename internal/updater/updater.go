// Package updater 实现 satchel-agent 的纯 Go 自更新与脱离服务进程组的纯 Go 卸载器（m2-09 node-lifecycle）。
// 全流程禁止拼接或调用任何 shell 脚本，严格核对 Docker 禁令、128 MiB 磁盘空间、同源成对下载验签与试跑后替换四硬条件。
package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/satchel/satchel/pkg/release"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/buildinfo"
)

const defaultStateUpdateDir = "/var/lib/satchel-agent/update"

// 发布源地址：测试构建二进制时可通过 -ldflags -X 注入测试地址，严禁环境变量覆盖。
var (
	CDNBase    = release.DefaultCDNBase
	GitHubRepo = "tajiaoyezi/satchel-agent"
	GitHubAPI  = release.DefaultGitHubAPI
	GitHubWeb  = release.DefaultGitHubWeb
	GHProxy    = release.DefaultGHProxy
)

// DefaultSources 返回 satchel-agent 使用的三层发布源配置。
func DefaultSources() release.Sources {
	return release.Sources{
		CDN:     CDNBase,
		Project: "satchel-agent",
		Repo:    GitHubRepo,
		API:     GitHubAPI,
		Web:     GitHubWeb,
		Proxy:   GHProxy,
	}
}

var (
	ErrDockerRestricted = errors.New("节点运行在 Docker 容器内，禁止自更新或远程卸载；请直接更换容器镜像标签重建")
	ErrDevBuild         = errors.New("当前节点为开发版构建，不支持自更新")
	ErrExecInFlight     = errors.New("节点当前正在执行远程命令（exec），暂不能更新或卸载")
	ErrAlreadyLatest    = errors.New("节点当前已是最新版本")
	ErrIncompatible     = errors.New("目标版本超出控制协议兼容范围")
)

// ExecCounter 记录当前进行中的远程命令数，给自更新与卸载做互斥守卫，并暴露给 agent.info。
type ExecCounter struct {
	n atomic.Int64
}

func (c *ExecCounter) Begin() {
	if c != nil {
		c.n.Add(1)
	}
}

func (c *ExecCounter) End() {
	if c != nil {
		c.n.Add(-1)
	}
}

func (c *ExecCounter) Running() bool {
	return c != nil && c.n.Load() > 0
}

// Options 描述一次纯 Go 自更新事务的可注入参数。
type Options struct {
	CurrentVersion          string
	TargetVersion           string // 为空时自动取 channel 最新版（CLI 兜底用）
	Channel                 string // stable | prerelease
	UseCDN                  bool
	ExpectedControlProtocol int
	Sources                 release.Sources
	Root                    string
	GOARCH                  string
	StagingDir              string
	Executable              func() (string, error)
	Verify                  func(bin, sig string) error
	FreeSpaceProbe          func(dir string) (uint64, error)
	RunVersion              func(ctx context.Context, bin string) (string, error)
	Execs                   *ExecCounter
	Install                 func(staged, target string) (bool, error)
}

// Result 记录一次已验签、试跑并替换到目标路径的自更新成果。
type Result struct {
	PreviousVersion string `json:"previous_version"`
	TargetVersion   string `json:"target_version"`
	Source          string `json:"source"`
	Executable      string `json:"executable"`
	DiskState       string `json:"disk_state,omitempty"`
}

var applyMu sync.Mutex

// Apply 执行纯 Go 自更新的四硬条件检查、同源成对下载验签、试跑 --version、备份 .bak 并原子覆写现网可执行文件。
// 任一前置/下载/验签/试跑失败都会清理临时文件，现网二进制与 .bak 零改动。
func Apply(ctx context.Context, opts Options) (*Result, error) {
	if !applyMu.TryLock() {
		return nil, errors.New("已有自更新事务正在进行")
	}
	defer applyMu.Unlock()

	if opts.Execs != nil && opts.Execs.Running() {
		return nil, ErrExecInFlight
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}
	if release.InDocker(root) {
		return nil, ErrDockerRestricted
	}

	curVer := strings.TrimSpace(opts.CurrentVersion)
	if curVer == "" {
		curVer = buildinfo.Get().Version
	}
	if release.IsDev(curVer) {
		return nil, fmt.Errorf("%w（%s）", ErrDevBuild, curVer)
	}
	curNorm := release.Normalize(curVer)

	ch := strings.TrimSpace(opts.Channel)
	if ch == "" {
		ch = release.ChannelStable
	}
	if ch != release.ChannelStable && ch != release.ChannelPrerelease {
		return nil, fmt.Errorf("未知更新渠道 %q", ch)
	}

	src := opts.Sources
	if src.Repo == "" && src.CDN == "" && src.API == "" && src.Web == "" && src.Proxy == "" {
		src = DefaultSources()
	}

	exeFn := opts.Executable
	if exeFn == nil {
		exeFn = resolveExecutable
	}
	exePath, err := exeFn()
	if err != nil {
		return nil, fmt.Errorf("解析当前可执行文件路径失败：%w", err)
	}
	targetDir := filepath.Dir(exePath)

	rel, _, err := release.Latest(ctx, src, ch, opts.UseCDN)
	if err != nil {
		return nil, fmt.Errorf("查询最新节点版本失败：%w", err)
	}
	if rel.ControlProtocol > xrpc.ControlProtocol {
		return nil, fmt.Errorf("%w：目标版本控制协议 %d 高于当前支持上限 %d", ErrIncompatible, rel.ControlProtocol, xrpc.ControlProtocol)
	}
	if opts.ExpectedControlProtocol > 0 && rel.ControlProtocol > opts.ExpectedControlProtocol {
		return nil, fmt.Errorf("%w：发布源控制协议 %d 超出主控预期 %d", ErrIncompatible, rel.ControlProtocol, opts.ExpectedControlProtocol)
	}
	if want := strings.TrimSpace(opts.TargetVersion); want != "" {
		if !release.Valid(want) {
			return nil, fmt.Errorf("目标版本号 %q 不是合法语义化版本", want)
		}
		wantNorm := release.Normalize(want)
		if rel.Version != wantNorm {
			return nil, fmt.Errorf("渠道 %s 最新版为 %s，与目标 %s 不一致", ch, rel.Version, wantNorm)
		}
	}
	if release.Compare(rel.Version, curNorm) <= 0 {
		return nil, fmt.Errorf("%w（当前 %s，最新 %s）", ErrAlreadyLatest, curNorm, rel.Version)
	}

	stagingDir := pickStagingDir(opts.StagingDir, targetDir)
	if err := release.CheckFreeSpace(stagingDir, release.MinStagingFreeBytes, opts.FreeSpaceProbe); err != nil {
		return nil, err
	}
	if targetDir != stagingDir {
		if err := release.CheckFreeSpace(targetDir, release.MinStagingFreeBytes, opts.FreeSpaceProbe); err != nil {
			return nil, err
		}
	}

	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	verifyFn := opts.Verify
	if verifyFn == nil {
		verifyFn = release.VerifyFile
	}
	art, err := release.DownloadPair(ctx, src, rel, opts.UseCDN, goarch, stagingDir, verifyFn, nil)
	if err != nil {
		return nil, fmt.Errorf("成对下载或验签失败：%w", err)
	}
	defer art.Remove()

	if err := os.Chmod(art.Binary, 0o755); err != nil {
		return nil, fmt.Errorf("设置试跑权限失败：%w", err)
	}
	runVerFn := opts.RunVersion
	if runVerFn == nil {
		runVerFn = defaultRunVersion
	}
	tctx, cancelTrial := context.WithTimeout(ctx, 15*time.Second)
	trialVer, err := runVerFn(tctx, art.Binary)
	cancelTrial()
	if err != nil {
		return nil, fmt.Errorf("新二进制 --version 试跑失败（现网未改动）：%w", err)
	}
	if !release.Valid(trialVer) || release.Normalize(trialVer) != rel.Version {
		return nil, fmt.Errorf("新二进制 --version 返回 %q，与目标版本 %s 不一致（现网未改动）", trialVer, rel.Version)
	}

	// 将验证通过的新二进制写入目标二进制同目录临时文件，保证随后 os.Rename 严格同文件系统原子切换。
	newBytes, err := os.ReadFile(art.Binary)
	if err != nil {
		return nil, fmt.Errorf("读取已验签新二进制失败：%w", err)
	}
	stagedTarget, err := writeTempBinary(targetDir, newBytes)
	if err != nil {
		return nil, fmt.Errorf("写入目标目录暂存文件失败：%w", err)
	}
	defer os.Remove(stagedTarget)

	if err := release.SavePrevious(exePath); err != nil {
		return nil, fmt.Errorf("备份现有二进制到 .bak 失败（现网未改动）：%w", err)
	}

	installFn := opts.Install
	if installFn == nil {
		installFn = release.Install
	}
	replaced, err := installFn(stagedTarget, exePath)
	if err != nil {
		if replaced {
			if rerr := release.RestorePrevious(exePath); rerr == nil {
				return &Result{
					PreviousVersion: curNorm,
					TargetVersion:   rel.Version,
					Source:          art.Source,
					Executable:      exePath,
					DiskState:       xrpc.DiskStateOldAfterSwap,
				}, fmt.Errorf("替换后目录落盘失败且已从 .bak 恢复旧版本：%w", err)
			}
			return &Result{
				PreviousVersion: curNorm,
				TargetVersion:   rel.Version,
				Source:          art.Source,
				Executable:      exePath,
				DiskState:       xrpc.DiskStateNewUnconfirmed,
			}, fmt.Errorf("替换已完成但目录落盘失败且回退失败：%w", err)
		}
		return &Result{
			PreviousVersion: curNorm,
			TargetVersion:   rel.Version,
			Source:          art.Source,
			Executable:      exePath,
			DiskState:       xrpc.DiskStateOld,
		}, fmt.Errorf("原子替换可执行文件失败：%w", err)
	}

	return &Result{
		PreviousVersion: curNorm,
		TargetVersion:   rel.Version,
		Source:          art.Source,
		Executable:      exePath,
	}, nil
}

func resolveExecutable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func pickStagingDir(configured, fallback string) string {
	candidates := []string{configured, defaultStateUpdateDir, fallback}
	for _, dir := range candidates {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		probe, err := os.CreateTemp(dir, ".write-probe-*")
		if err != nil {
			continue
		}
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		return dir
	}
	return fallback
}

func writeTempBinary(dir string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, ".satchel-agent.new.*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func defaultRunVersion(ctx context.Context, bin string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseVersionOutput(string(out))
}

func parseVersionOutput(out string) (string, error) {
	fields := strings.Fields(out)
	for _, f := range fields {
		cand := strings.TrimSuffix(f, ",")
		if release.Valid(cand) {
			return release.Normalize(cand), nil
		}
	}
	return "", fmt.Errorf("未能在 --version 输出 %q 中识别语义化版本", strings.TrimSpace(out))
}

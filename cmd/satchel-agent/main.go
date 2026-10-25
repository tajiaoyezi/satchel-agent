// satchel-agent 是节点守护进程的入口，只做装配：join 写配置（m2-02 node-pairing），run 按本地配置起内核、连主控
// （m2-02 node-channel，m2-03 agent-kernel「run 按本地配置起内核」）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/satchel/satchel-agent/internal/buildinfo"
	"github.com/satchel/satchel-agent/internal/channel"
	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// kernelConfig 是内核配置（一份 sing-box 配置）的文件名，与 config.yaml 放在同一个目录；改了要重启 satchel-agent 才生效。
const kernelConfig = "kernel.json"

const usage = `用法：
  satchel-agent join --master-url <url> --token <token> --master-key <key> --mode <mode> [--config <path>]
  satchel-agent run [--config <path>]
  satchel-agent --version

  join   把主控地址、token、主控公钥与连接模式写进配置文件（默认 ` + config.DefaultPath + `，权限 0600）
  run    按配置连主控并保持连接（装成服务时由 systemd 或 OpenRC 运行）；配置目录里有 kernel.json 就照它起内核

安装命令从主控的 satchel server install-command 取，安装脚本会替你执行 join 并装好服务。`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "join":
			return join(args[1:], stdout, stderr)
		case "run":
			return serve(args[1:], stderr)
		}
	}
	fs := flag.NewFlagSet("satchel-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {} // 用法由下面按情形打印：--help 打到 stdout，敲错时 flag 已把错误写到 stderr
	version := fs.Bool("version", false, "打印版本、commit 与构建时间后退出")
	if err := fs.Parse(args); err != nil {
		// 人主动要帮助不是用法错误：用法打到 stdout、退出码 0，与主控 satchel --help 一致；敲错了才是 2。
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *version {
		info := buildinfo.Get()
		fmt.Fprintf(stdout, "satchel-agent %s (commit %s, built %s)\n", info.Version, info.Commit, info.Date)
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "不认识的子命令 %q\n%s\n", fs.Arg(0), usage)
		return 2
	}
	fmt.Fprintln(stderr, usage)
	return 2
}

// join 校验参数后写配置文件；任何一项不合法都不写。
func join(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("satchel-agent join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config.Config
	fs.StringVar(&c.MasterURL, "master-url", "", "主控地址（https）")
	fs.StringVar(&c.Token, "token", "", "这台服务器的 token")
	fs.StringVar(&c.MasterPublicKey, "master-key", "", "主控公钥（标准 base64）")
	fs.StringVar(&c.ConnectionMode, "mode", "", "连接模式（这一版只支持 websocket）")
	path := fs.String("config", config.DefaultPath, "配置文件的位置")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "join 不接受多余的参数：%v\n", fs.Args())
		return 2
	}
	if err := config.Save(*path, c); err != nil {
		fmt.Fprintln(stderr, "写配置失败：", err)
		return 1
	}
	fmt.Fprintf(stdout, "已写配置 %s（权限 0600）；用 satchel-agent run 连主控\n", *path)
	return 0
}

// serve 读配置并连主控，直到收到 SIGTERM / SIGINT（退出码 0）。配置缺主控公钥或不合法时不连、退出码 1。
func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("satchel-agent run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", config.DefaultPath, "配置文件的位置")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	logger.Info("satchel-agent 启动", "version", buildinfo.Get().Version, "master", c.MasterURL)
	return runAgent(ctx, filepath.Dir(*path), channel.Config{MasterURL: c.MasterURL, Token: c.Token, MasterKey: c.MasterKey(),
		AgentVersion: buildinfo.Get().Version, Logger: logger}, logger)
}

// runAgent 按配置目录起内核、给通道装上连接管控的方法、连主控，直到 ctx 结束；结束时先断通道（Run 返回时已断开）、
// 再停内核。返回退出码。serve 只负责读配置与接信号。
func runAgent(ctx context.Context, dir string, cfg channel.Config, logger *slog.Logger) int {
	deps, k := startKernel(ctx, dir, logger)
	cfg.Methods = control.Methods(deps)
	err := channel.New(cfg).Run(ctx)
	logger.Info("已断开主控，停内核")
	if serr := k.Stop(); serr != nil {
		logger.Warn("停内核出错", "err", serr)
	}
	if err != nil {
		logger.Error("satchel-agent 异常退出", "err", err)
		return 1
	}
	logger.Info("satchel-agent 已停止")
	return 0
}

// startKernel 按配置目录准备连接管控（agent-kernel「run 按本地配置起内核」，m2-03 design 第 2 条）：先把 limiter-state.json
// 里的限速来源重放进 tracker，再按 kernel.json 起内核。状态文件坏了、内核配置解析不了或内核起不来都只记日志，不影响连主控。
// ctx 只管内核启动这一段：启动期间收到退出信号就放弃启动。
func startKernel(ctx context.Context, dir string, logger *slog.Logger) (control.Deps, *kernel.Kernel) {
	tr := tracker.New()
	store, err := limits.Open(filepath.Join(dir, limits.FileName), tr, time.Now)
	if err != nil {
		logger.Error("限速状态没能完整读回或重写（读回了的已经生效，下次改动时会重写这个文件）", "err", err)
	}
	k := kernel.New(tr)
	deps := control.Deps{Limits: store, Tracker: tr, Kernel: k}
	config, err := os.ReadFile(filepath.Join(dir, kernelConfig))
	switch {
	case errors.Is(err, os.ErrNotExist):
		logger.Info("配置目录里没有 " + kernelConfig + "，不起内核")
		return deps, k
	case err != nil:
		logger.Error("读内核配置失败，不起内核", "err", err)
		return deps, k
	}
	tags, err := kernel.InboundTags(config)
	if err != nil {
		logger.Error(kernelConfig+" 解析不了，不起内核", "err", err)
		return deps, k
	}
	deps.Inbounds = tags
	if err := k.Start(ctx, config); err != nil {
		logger.Error("内核起不来，只连主控", "err", err)
		return deps, k
	}
	logger.Info("内核已启动", "version", kernel.Version, "inbounds", tags)
	return deps, k
}

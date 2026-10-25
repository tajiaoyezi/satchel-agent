// satchel-agent 是节点守护进程的入口，只做装配：join 写配置，run 连主控（m2-02 node-pairing、node-channel）。
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
	"syscall"

	"github.com/satchel/satchel-agent/internal/buildinfo"
	"github.com/satchel/satchel-agent/internal/channel"
	"github.com/satchel/satchel-agent/internal/config"
)

const usage = `用法：
  satchel-agent join --master-url <url> --token <token> --master-key <key> --mode <mode> [--config <path>]
  satchel-agent run [--config <path>]
  satchel-agent --version

  join   把主控地址、token、主控公钥与连接模式写进配置文件（默认 ` + config.DefaultPath + `，权限 0600）
  run    按配置连主控并保持连接（装成服务时由 systemd 或 OpenRC 运行）

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
	client := channel.New(channel.Config{MasterURL: c.MasterURL, Token: c.Token, MasterKey: c.MasterKey(),
		AgentVersion: buildinfo.Get().Version, Logger: logger})
	if err := client.Run(ctx); err != nil {
		logger.Error("satchel-agent 异常退出", "err", err)
		return 1
	}
	logger.Info("satchel-agent 已停止")
	return 0
}

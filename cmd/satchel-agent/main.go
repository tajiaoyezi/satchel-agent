// satchel-agent 是节点守护进程的入口，只做装配：join 写配置（m2-02 node-pairing），run 按本地配置起内核、连主控
// （m2-02 node-channel，m2-03 agent-kernel「run 按本地配置起内核」）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	singlog "github.com/sagernet/sing-box/log"

	"github.com/satchel/satchel/pkg/release"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/buildinfo"
	"github.com/satchel/satchel-agent/internal/channel"
	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/control"
	"github.com/satchel/satchel-agent/internal/diag"
	"github.com/satchel/satchel-agent/internal/execctl"
	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/logging"
	"github.com/satchel/satchel-agent/internal/nginxctl"
	"github.com/satchel/satchel-agent/internal/telemetry"
	"github.com/satchel/satchel-agent/internal/tracker"
	"github.com/satchel/satchel-agent/internal/updater"
	"github.com/satchel/satchel-agent/internal/warpctl"
)

// kernelConfig 是内核配置（一份 sing-box 配置）的文件名，与 config.yaml 放在同一个目录；改了执行 server restart-kernel 或重启 satchel-agent 生效。
const kernelConfig = control.KernelConfig

const usage = `用法：
  satchel-agent join --master-url <url> --token <token> --master-key <key> --mode <mode>
                     [--agent-token <token>] [--pull-token <token>] [--listen-port <port>] [--pull-port <port>] [--log-path <path>] [--allow-exec] [--config <path>]
  satchel-agent run [--config <path>] [--log-path <path>]
  satchel-agent diag [item] [--config <path>] [--json]
  satchel-agent update [<version>] [--channel stable|prerelease] [--yes]
  satchel-agent uninstall [--yes] [--detach-delay <duration>]
  satchel-agent --version

  join       把主控地址、通信凭据、主控公钥、连接模式与入站端口写进配置文件（默认 ` + config.DefaultPath + `，权限 0600）
  run        按配置连主控并按模式开放受保护端口；配置目录里有 kernel.json 就照它起内核
  diag       在本机直接执行固定只读诊断集（支持单项如 ports/services/logs/config/connectivity/firewall/clock/resources/certs/speedtest）
  update     纯 Go 下载验签、试跑并替换自身二进制（容器内禁用）
  uninstall  纯 Go 停止服务并清理二进制与白名单目录（容器内禁用）

安装命令从主控的 satchel server install-command 取，安装脚本会替你执行 join 并装好服务。`

var execSelf = syscall.Exec

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
		case "diag":
			return cmdDiag(args[1:], stdout, stderr)
		case "update":
			return cmdUpdate(args[1:], stdout, stderr)
		case "uninstall":
			return cmdUninstall(args[1:], stdout, stderr)
		case "__verify":
			return cmdVerify(args[1:], stdout, stderr)
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
	fs.StringVar(&c.Token, "token", "", "这台服务器上行认证的 token")
	fs.StringVar(&c.AgentToken, "agent-token", "", "主控访问节点管理口（--mode 非 websocket 时必填）")
	fs.StringVar(&c.PullToken, "pull-token", "", "主控拉取节点只读轮询口（--mode 为 auto 或 pull 时必填）")
	fs.StringVar(&c.MasterPublicKey, "master-key", "", "主控公钥（标准 base64）")
	fs.StringVar(&c.ConnectionMode, "mode", "", "连接模式（auto、websocket、http 或 pull）")
	fs.IntVar(&c.ListenPort, "listen-port", 0, "节点管理监听端口（0 表示按默认 23889）")
	fs.IntVar(&c.PullPort, "pull-port", 0, "节点只读轮询端口（0 表示按默认 23890）")
	fs.StringVar(&c.LogPath, "log-path", "", "节点轮转日志文件路径（可选，默认 <state-dir>/logs/satchel-agent.log）")
	fs.BoolVar(&c.AllowExec, "allow-exec", false, "在节点本机显式允许主控经 server exec 执行命令（默认关闭，仅可本机修改）")
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
	logPathFlag := fs.String("log-path", "", "节点轮转日志文件路径覆盖")
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
	logCfg := strings.TrimSpace(*logPathFlag)
	if logCfg == "" {
		logCfg = c.LogPath
	}
	logPath := config.EffectiveLogPath(*path, logCfg)
	logSet, err := logging.Setup(logPath, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "初始化日志文件失败：", err)
		return 1
	}
	defer logSet.Close()
	logger := logSet.Logger
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	logger.Info("satchel-agent 启动", "version", buildinfo.Get().Version, "master", c.MasterURL, "mode", c.ConnectionMode, "log_path", logPath)
	return runAgentWithLogs(ctx, filepath.Dir(*path), channel.Config{
		MasterURL:       c.MasterURL,
		Token:           c.Token,
		AgentToken:      c.AgentToken,
		PullToken:       c.PullToken,
		MasterKey:       c.MasterKey(),
		Mode:            c.ConnectionMode,
		ListenPort:      c.EffectiveListenPort(),
		PullPort:        c.EffectivePullPort(),
		ConfigPath:      *path,
		AllowExec:       c.AllowExec,
		IPProbeInterval: channel.DefaultIPProbeInterval,
		IPProber:        channel.DefaultIPProber,
		AgentVersion:    buildinfo.Get().Version,
		Logger:          logger,
		OnAgentConfig: func(ac xrpc.AgentConfig) {
			logSet.SetDebugEnabled(ac.AgentLogEnabled)
		},
	}, logger, logSet)
}

// runAgent 按配置目录起内核、给通道装上连接管控与遥测日志方法、连主控，直到 ctx 结束或收到升级原地重启/卸载退出请求；
// 结束时先断通道、先取消内核启动用的 ctx、再停内核，最后如收到 RequestExec 则原地 syscall.Exec 新二进制。
func runAgent(ctx context.Context, dir string, cfg channel.Config, logger *slog.Logger) int {
	return runAgentWithLogs(ctx, dir, cfg, logger, nil)
}

func runAgentWithLogs(ctx context.Context, dir string, cfg channel.Config, logger *slog.Logger, logSet *logging.LoggerSet) int {
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()

	var (
		execMu   sync.Mutex
		execPath string
	)
	if cfg.Execs == nil {
		cfg.Execs = &updater.ExecCounter{}
	}
	if cfg.RequestExec == nil {
		cfg.RequestExec = func(path string) {
			execMu.Lock()
			execPath = path
			execMu.Unlock()
			stopRun()
		}
	}
	if cfg.RequestStop == nil {
		cfg.RequestStop = stopRun
	}

	var coreLogWriter singlog.PlatformWriter
	logDir := filepath.Join(dir, "logs")
	agentLogFile := logging.DefaultAgentLogFile
	coreLogFile := logging.CoreLogFile
	if logSet != nil {
		coreLogWriter = logSet.CorePlatformWriter()
		logDir = logSet.LogDir
		agentLogFile = filepath.Base(logSet.AgentLogPath)
		coreLogFile = filepath.Base(logSet.CoreLogPath)
	}

	sysCol := telemetry.NewSysCollector(telemetry.SysReader{
		InDocker:      func() bool { return release.InDocker("/") },
		AgentVersion:  cfg.AgentVersion,
		CPUProbeDelay: 100 * time.Millisecond,
	})
	sysCol.SampleCPU()
	speedCol := telemetry.NewSpeedCollector(nil, nil)
	speedCol.Sample()
	logInsp := telemetry.NewLogInspector(logDir, agentLogFile, coreLogFile)

	kernelCtx, cancelKernel := context.WithCancel(runCtx)
	defer cancelKernel()
	deps, k := startKernelWithLogWriter(kernelCtx, dir, logger, coreLogWriter)
	deps.Sys = sysCol
	deps.Speed = speedCol
	deps.Logs = logInsp
	deps.ListNICs = telemetry.ListNICs
	deps.AgentVersion = cfg.AgentVersion
	deps.StartedAt = time.Now().UTC()
	deps.InDocker = func() bool { return release.InDocker("/") }
	deps.Nginx = nginxctl.New(nginxctl.Options{InDocker: deps.InDocker})
	deps.Warp = warpctl.New(dir)
	deps.Diag = diag.New(diag.Options{
		ConfigDir:    dir,
		MasterURL:    cfg.MasterURL,
		AgentVersion: cfg.AgentVersion,
		StartedAt:    deps.StartedAt,
		InDocker:     deps.InDocker,
		KernelInfo: func() diag.KernelInfo {
			ki := diag.KernelInfo{
				Running:  k.Running(),
				Inbounds: deps.Inbounds.Get(),
			}
			if ki.Running {
				ki.Version = kernel.Version
			}
			if at := k.StartedAt(); !at.IsZero() {
				ki.StartedAt = &at
			}
			return ki
		},
		Nginx: deps.Nginx,
		Sys:   sysCol,
		Logs:  logInsp,
	})
	execMgr := execctl.New(execctl.Options{
		AllowExec:    cfg.AllowExec,
		DataDir:      dir,
		AuditLogPath: filepath.Join(logDir, "exec-audit.log"),
		Execs:        cfg.Execs,
		Logger:       logger,
	})
	defer execMgr.Shutdown()
	deps.Exec = execMgr
	cfg.Methods = control.Methods(deps)
	if cfg.SpeedCollector == nil {
		cfg.SpeedCollector = speedCol
	}
	if cfg.SysCollector == nil {
		cfg.SysCollector = sysCol
	}
	ch := channel.New(cfg)
	execMgr.SetOnEvent(func(ev xrpc.ExecEvent) {
		ch.SendExecEvent(ev)
	})
	err := ch.Run(runCtx)
	cancelKernel()
	logger.Info("已断开主控，停内核")
	if serr := k.Stop(); serr != nil {
		logger.Warn("停内核出错", "err", serr)
	}
	if err != nil {
		logger.Error("satchel-agent 异常退出", "err", err)
		return 1
	}

	execMu.Lock()
	targetExec := execPath
	execMu.Unlock()
	if targetExec != "" {
		logger.Info("正在原地 exec 切换到新版本", "executable", targetExec)
		if exErr := execSelf(targetExec, os.Args, os.Environ()); exErr != nil {
			logger.Error("原地 exec 新版本失败，退出等待服务管理器重启", "executable", targetExec, "err", exErr)
			return 1
		}
		return 0
	}

	logger.Info("satchel-agent 已停止")
	return 0
}

var (
	updaterApplyFn = updater.Apply
	uninstallFn    = updater.RunUninstall
)

func reorderUpdateFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		if !strings.Contains(a, "=") && (a == "--channel" || a == "-channel") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, pos...)
}

func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("satchel-agent update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ch := fs.String("channel", release.ChannelStable, "更新渠道（stable 或 prerelease）")
	yes := fs.Bool("yes", false, "确认执行自更新")
	noCDN := fs.Bool("no-cdn", false, "禁用更新 CDN，直连 GitHub / gh-proxy")
	if err := fs.Parse(reorderUpdateFlags(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "update 最多只收 1 个版本号参数：%v\n", fs.Args())
		return 2
	}
	if !*yes {
		fmt.Fprintln(stderr, "执行自更新需显式传递 --yes")
		return 2
	}
	targetVer := ""
	if fs.NArg() == 1 {
		targetVer = strings.TrimSpace(fs.Arg(0))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := updaterApplyFn(ctx, updater.Options{
		CurrentVersion: buildinfo.Get().Version,
		TargetVersion:  targetVer,
		Channel:        *ch,
		UseCDN:         !*noCDN,
	})
	if err != nil {
		fmt.Fprintln(stderr, "更新失败：", err)
		return 1
	}
	fmt.Fprintf(stdout, "已从 %s 升级到 %s（来源 %s）；如以系统服务运行，请重启服务或由远程控制面原地接管\n",
		res.PreviousVersion, res.TargetVersion, res.Source)
	return 0
}

func cmdUninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("satchel-agent uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "确认卸载并清理白名单文件与目录")
	delay := fs.Duration("detach-delay", 0, "开始清理前的等待时间（脱离父进程组时用）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "uninstall 不接受位置参数：%v\n", fs.Args())
		return 2
	}
	if !*yes {
		fmt.Fprintln(stderr, "执行卸载需显式传递 --yes")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := uninstallFn(ctx, updater.UninstallOptions{Delay: *delay}); err != nil {
		fmt.Fprintln(stderr, "卸载失败：", err)
		return 1
	}
	fmt.Fprintln(stdout, "satchel-agent 已卸载清理完成")
	return 0
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "用法：satchel-agent __verify <file> <sig>")
		return 2
	}
	if err := release.VerifyFile(args[0], args[1]); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}

func cmdDiag(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("satchel-agent diag", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "配置文件位置（用于定位配置与日志目录，文件不存在时仍可诊断）")
	asJSON := fs.Bool("json", false, "以 JSON 格式输出诊断结果")
	// 支持把位置参数写在 flag 前（如 satchel-agent diag ports --json），Go 标准 flag 遇位置参数即停，需先分离。
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if (a == "--config" || a == "-config") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		posArgs = append(posArgs, a)
	}
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	posArgs = append(posArgs, fs.Args()...)
	if len(posArgs) > 1 {
		fmt.Fprintf(stderr, "diag 最多接受 1 个诊断项名，得到 %v\n", posArgs)
		return 2
	}

	var items []string
	if len(posArgs) == 1 {
		name := xrpc.NormalizeDiagItem(posArgs[0])
		if !xrpc.ValidDiagItem(name) {
			fmt.Fprintf(stderr, "未知诊断项 %q，可选：%s\n", posArgs[0], strings.Join(xrpc.DiagItems, ", "))
			return 2
		}
		items = []string{name}
	}

	cfgDir := filepath.Dir(*cfgPath)
	masterURL := ""
	logCfg := ""
	if loaded, err := config.Load(*cfgPath); err == nil {
		masterURL = loaded.MasterURL
		logCfg = loaded.LogPath
	}
	logPath := config.EffectiveLogPath(*cfgPath, logCfg)
	logDir := filepath.Dir(logPath)
	coreLog := filepath.Join(logDir, "sing-box.log")

	eng := diag.New(diag.Options{
		ConfigDir:    cfgDir,
		MasterURL:    masterURL,
		AgentVersion: buildinfo.Get().Version,
		InDocker:     func() bool { return release.InDocker("/") },
		Nginx:        nginxctl.New(nginxctl.Options{InDocker: func() bool { return release.InDocker("/") }}),
		Sys:          telemetry.NewSysCollector(telemetry.SysReader{AgentVersion: buildinfo.Get().Version, InDocker: func() bool { return release.InDocker("/") }}),
		Logs:         telemetry.NewLogInspector(logDir, logPath, coreLog),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := eng.Run(ctx, xrpc.DiagRunParams{Items: items, MasterURL: masterURL, IncludeSecrets: false})
	if err != nil {
		fmt.Fprintln(stderr, "执行诊断失败：", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}
	for _, it := range res.Items {
		line := fmt.Sprintf("%-13s %-13s %4dms", it.Name, it.Status, it.DurationMS)
		if it.Error != "" {
			line += "  error=" + it.Error
		}
		fmt.Fprintln(stdout, line)
	}
	return 0
}

// startKernel 按配置目录准备连接管控（agent-kernel「run 按本地配置起内核」，m2-03 design 第 2 条）：先把 limiter-state.json
// 里的限速来源重放进 tracker，再按 kernel.json 起内核。状态文件坏了、内核配置解析不了或内核起不来都只记日志，不影响连主控。
// ctx 只管内核启动（含随后 kernel.restart 的启动）：启动期间收到退出信号就放弃启动。
func startKernel(ctx context.Context, dir string, logger *slog.Logger) (control.Deps, *kernel.Kernel) {
	return startKernelWithLogWriter(ctx, dir, logger, nil)
}

func startKernelWithLogWriter(ctx context.Context, dir string, logger *slog.Logger, coreLogWriter singlog.PlatformWriter) (control.Deps, *kernel.Kernel) {
	tr := tracker.New()
	store, err := limits.Open(filepath.Join(dir, limits.FileName), tr, time.Now)
	if err != nil {
		logger.Error("限速状态没能完整读回或重写（读回了的已经生效，下次改动时会重写这个文件）", "err", err)
	}
	k := kernel.New(tr)
	if coreLogWriter != nil {
		k.SetLogWriter(coreLogWriter)
	}
	inbounds := control.NewInbounds(nil)
	deps := control.Deps{Limits: store, Tracker: tr, Kernel: k, Inbounds: inbounds, KernelCtx: ctx, ConfigDir: dir}
	if dir != "" {
		if modified, backupPath, removedTags, perr := control.ProtectMasterHTTPSPort443(filepath.Join(dir, kernelConfig), nil); perr != nil {
			logger.Warn("主控同机 443 启动自愈检查出错", "err", perr)
		} else if modified {
			logger.Warn("检测到主控 443 保护标记，已自动剥离 kernel.json 中的 443 入站并留存备份",
				"backup", backupPath, "removed_inbounds", removedTags)
		}
	}
	config, tags, err := control.ReadKernelConfig(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info("配置目录里没有 " + kernelConfig + "，不起内核")
		} else {
			logger.Error("内核配置不可用，不起内核", "err", err)
		}
		return deps, k
	}
	inbounds.Set(tags)
	if err := k.Start(ctx, config); err != nil {
		logger.Error("内核起不来，只连主控", "err", err)
		return deps, k
	}
	logger.Info("内核已启动", "version", kernel.Version, "inbounds", tags)
	return deps, k
}

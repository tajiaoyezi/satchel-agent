// Package channel 是节点连主控的通道（m2-02 / m2-06）：支持 auto / websocket / http / pull 四种连接模式、
// 双端口独立 SilentAuth + 强制双向 securechan 入站控制与只读轮询、auto 端口隐身 listenGate 以及公网 IP 漂移唤醒重连。
package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/release"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/config"
	"github.com/satchel/satchel-agent/internal/pathguard"
	"github.com/satchel/satchel-agent/internal/updater"
)

// MinMasterVersion 是这个 agent 要求的最低主控版本：线格式第一次出现不兼容的变化时填上；空表示不要求。
const MinMasterVersion = ""

const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	// defaultHeartbeat 是主控没给心跳间隔时用的间隔。
	defaultHeartbeat = 30 * time.Second

	defaultWSProbeInterval = 60 * time.Second
	defaultHTTPFailLimit   = 5
	defaultPullWindowBase  = 30 * time.Second
	defaultPullWindowMax   = 5 * time.Minute
)

// Backoff 是重连等待的几个常数（测试里换小）。
type Backoff struct {
	Base         time.Duration // 普通失败的第一次等待，之后翻倍
	Max          time.Duration // 普通失败的封顶
	AuthStep     time.Duration // 认证失败第 n 次连续等 n×AuthStep
	AuthMax      time.Duration // 认证失败的封顶
	Penalty      time.Duration // token 无效连续 PenaltyAfter 次后的长等待
	PenaltyAfter int
}

// DefaultBackoff 照抄 mmwx 的常数。
var DefaultBackoff = Backoff{Base: 5 * time.Second, Max: 5 * time.Minute, AuthStep: 30 * time.Second, AuthMax: 10 * time.Minute,
	Penalty: 30 * time.Minute, PenaltyAfter: 10}

// Config 是通道的依赖。
type Config struct {
	MasterURL    string
	Token        string
	AgentToken   string
	PullToken    string
	MasterKey    ed25519.PublicKey
	Mode         string // auto / websocket / http / pull；空串向后兼容按 websocket
	ListenHost   string
	ListenPort   int
	PullPort     int
	ConfigPath   string
	AgentVersion string
	// Methods 是 agent.info / agent.health / token.rotate 之外节点回应的方法（连接管控与流量，见 internal/control）。
	Methods xrpc.Methods
	Logger  *slog.Logger
	Backoff Backoff
	// Sleep 等待 d 或 ctx 结束（测试里换成记录等待时长、立即返回）。
	Sleep func(ctx context.Context, d time.Duration) error

	// 以下为四模式与测试可注入参数，零值取生产默认常数。
	StealthDelay          time.Duration
	WSProbeInterval       time.Duration
	HTTPFailLimit         int
	PullWindowBase        time.Duration
	PullWindowMax         time.Duration
	HTTPHeartbeatInterval time.Duration
	IPProbeInterval       time.Duration
	IPProber              IPProber
	Now                   func() time.Time
	HTTPClient            *http.Client
	SaveConfig            func(config.Config) error
	Execs                 *updater.ExecCounter
	RequestExec           func(exePath string)
	RequestStop           func()
	Root                  string
	MachineID             string
	StagingDir            string
	ReleaseSources        release.Sources
	UpdateApply           func(context.Context, updater.Options) (*updater.Result, error)
	UninstallSpawn        func(context.Context, updater.DetachOptions) (string, error)
}

// AuthError 是主控拒绝了认证（或握手时主控公钥对不上）。
type AuthError struct {
	Reason  string // xrpc.Auth* 之一；主控公钥对不上时为 badMasterKey
	Message string
}

const badMasterKey = "bad_master_key"

func (e *AuthError) Error() string {
	if e.Reason == badMasterKey {
		return "主控的握手签名验不过：配置里的主控公钥与主控对不上，没有发出 token"
	}
	return "主控拒绝了认证：" + e.Message
}

// Client 是节点的通道。
type Client struct {
	cfg        Config
	root       string
	machineID  string
	inDocker   bool
	boot       time.Time
	creds      *credStore
	methods    xrpc.Methods
	managePort *inboundPort
	pullPort   *inboundPort
	gate       *listenGate
	uplink     *httpUplink

	masterMu sync.RWMutex
	master   string

	wsMu     sync.Mutex
	wsCancel context.CancelFunc

	rotateMu     sync.Mutex
	cleanupMu    sync.Mutex
	pendingRoles []string
	postActions  []func()

	wakeupCh chan struct{}
	wsWakeCh chan struct{}
	wakeSeq  atomic.Uint64
}

// New 建通道。
func New(cfg Config) *Client {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Backoff == (Backoff{}) {
		cfg.Backoff = DefaultBackoff
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	if cfg.Mode == "" {
		cfg.Mode = config.ModeWebsocket
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StealthDelay <= 0 {
		cfg.StealthDelay = defaultStealthDelay
	}
	if cfg.WSProbeInterval <= 0 {
		cfg.WSProbeInterval = defaultWSProbeInterval
	}
	if cfg.HTTPFailLimit <= 0 {
		cfg.HTTPFailLimit = defaultHTTPFailLimit
	}
	if cfg.PullWindowBase <= 0 {
		cfg.PullWindowBase = defaultPullWindowBase
	}
	if cfg.PullWindowMax <= 0 {
		cfg.PullWindowMax = defaultPullWindowMax
	}
	if cfg.HTTPHeartbeatInterval <= 0 {
		cfg.HTTPHeartbeatInterval = defaultHeartbeat
	}
	if cfg.IPProber != nil && cfg.IPProbeInterval == 0 {
		cfg.IPProbeInterval = DefaultIPProbeInterval
	}
	root := strings.TrimSpace(cfg.Root)
	if root == "" {
		root = "/"
	}
	machineID := strings.TrimSpace(cfg.MachineID)
	if machineID == "" {
		machineID = readAgentMachineID(root)
	}
	listenPort := cfg.ListenPort
	if listenPort == 0 && cfg.Mode != config.ModeWebsocket {
		listenPort = config.DefaultListenPort
	}
	pullPort := cfg.PullPort
	if pullPort == 0 && (cfg.Mode == config.ModeAuto || cfg.Mode == config.ModePull) {
		pullPort = config.DefaultPullPort
	}

	c := &Client{
		cfg:       cfg,
		root:      root,
		machineID: machineID,
		inDocker:  release.InDocker(root),
		master:    strings.TrimRight(strings.TrimSpace(cfg.MasterURL), "/"),
		boot:      time.Now().UTC(),
		creds:     newCredStore(cfg.Token, cfg.AgentToken, cfg.PullToken),
		wakeupCh:  make(chan struct{}, 1),
		wsWakeCh:  make(chan struct{}, 1),
	}

	baseMethods := xrpc.Methods{
		xrpc.MethodAgentInfo: func(context.Context, json.RawMessage) (any, error) {
			return c.runtimeInfo(), nil
		},
		xrpc.MethodAgentHealth: func(context.Context, json.RawMessage) (any, error) {
			return c.runtimeHealth(), nil
		},
	}
	maps.Copy(baseMethods, cfg.Methods)
	baseMethods[xrpc.MethodTokenRotate] = c.handleTokenRotate
	baseMethods[xrpc.MethodAgentUpdate] = c.handleAgentUpdate
	baseMethods[xrpc.MethodAgentUninstall] = c.handleAgentUninstall
	baseMethods[xrpc.MethodAgentSwitchPorts] = c.handleAgentSwitchPorts
	baseMethods[xrpc.MethodAgentProbeMaster] = c.handleAgentProbeMaster
	baseMethods[xrpc.MethodAgentUpdateMaster] = c.handleAgentUpdateMaster
	c.methods = baseMethods

	// 只读轮询口仅暴露 traffic.snapshot 与 agent.health，绝不挂载任何管理写或生命周期控制动作。
	pullMethods := xrpc.Methods{
		xrpc.MethodAgentHealth: baseMethods[xrpc.MethodAgentHealth],
	}
	if snapFn, ok := baseMethods[xrpc.MethodTrafficSnapshot]; ok {
		pullMethods[xrpc.MethodTrafficSnapshot] = snapFn
	}

	onPostCall := func(_ string, xerr *xrpc.Error) {
		if xerr == nil {
			c.flushPendingCleanup()
		}
	}

	c.managePort = newInboundPort("manage", cfg.Mode, cfg.MasterKey, c.creds.AgentTokens, c.methods, c.runtimeHealth, cfg.Now, onPostCall)
	c.pullPort = newInboundPort("pull", cfg.Mode, cfg.MasterKey, c.creds.PullTokens, pullMethods, c.runtimeHealth, cfg.Now, nil)
	c.gate = newListenGate(
		cfg.Mode,
		cfg.StealthDelay,
		newPortServer("manage", cfg.ListenHost, listenPort, c.managePort.Handler(), cfg.Logger),
		newPortServer("pull", cfg.ListenHost, pullPort, c.pullPort.Handler(), cfg.Logger),
		cfg.Logger,
	)
	c.uplink = newHTTPUplink(c)
	return c
}

func (c *Client) addPendingCleanup(roles ...string) {
	c.cleanupMu.Lock()
	c.pendingRoles = append(c.pendingRoles, roles...)
	c.cleanupMu.Unlock()
}

func (c *Client) addPostAction(fn func()) {
	if fn == nil {
		return
	}
	c.cleanupMu.Lock()
	c.postActions = append(c.postActions, fn)
	c.cleanupMu.Unlock()
}

func (c *Client) flushPendingCleanup() {
	c.cleanupMu.Lock()
	todo := append([]string(nil), c.pendingRoles...)
	c.pendingRoles = nil
	actions := append([]func(){}, c.postActions...)
	c.postActions = nil
	c.cleanupMu.Unlock()
	for _, r := range todo {
		switch r {
		case "manage":
			c.managePort.ClearSessions()
		case "pull":
			c.pullPort.ClearSessions()
		case "uplink":
			c.uplink.ClearSession()
		}
	}
	for _, fn := range actions {
		fn()
	}
}

// InboundAddrs 返回当前正在监听的管理口与只读轮询口地址（隐身关闭或未监听时对应为空串）。
func (c *Client) InboundAddrs() (manageAddr, pullAddr string) {
	return c.gate.Addrs()
}

func (c *Client) triggerWakeup() {
	c.wakeSeq.Add(1)
	select {
	case c.wakeupCh <- struct{}{}:
	default:
	}
	select {
	case c.wsWakeCh <- struct{}{}:
	default:
	}
}

func (c *Client) waitOrWake(ctx context.Context, d time.Duration) (wokenByDrift bool, err error) {
	startSeq := c.wakeSeq.Load()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		select {
		case <-c.wakeupCh:
			cancel()
		case <-done:
		}
	}()
	serr := c.cfg.Sleep(sctx, d)
	close(done)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if c.wakeSeq.Load() != startSeq || serr != nil {
		return true, nil
	}
	return false, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run 按配置模式运行通道与入站监听，直到 ctx 结束（配置合法退出时返回 nil；缺主控公钥直接拒绝启动并返回错误）。
func (c *Client) Run(ctx context.Context) error {
	if len(c.cfg.MasterKey) != ed25519.PublicKeySize {
		return errors.New("缺少或非法的 master_public_key，拒绝启动（不会打开任何监听端口或连接主控）")
	}
	if err := c.gate.Start(); err != nil {
		return err
	}
	defer c.gate.Close()

	var wg sync.WaitGroup
	if c.cfg.IPProber != nil && c.cfg.IPProbeInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runIPProber(ctx)
		}()
	}
	defer wg.Wait()

	switch c.cfg.Mode {
	case config.ModeWebsocket:
		return c.runWebsocketLoop(ctx)
	case config.ModeHTTP:
		return c.runHTTPOnlyLoop(ctx)
	case config.ModePull:
		<-ctx.Done()
		return nil
	case config.ModeAuto:
		return c.runAutoLoop(ctx)
	default:
		return fmt.Errorf("不支持的连接模式 %q", c.cfg.Mode)
	}
}

func (c *Client) computeBackoffWait(err error, failures, authFailures, invalid *int) time.Duration {
	b := c.cfg.Backoff
	var ae *AuthError
	if errors.As(err, &ae) {
		*failures = 0
		*authFailures++
		if ae.Reason == xrpc.AuthInvalidToken {
			*invalid++
		}
		var wait time.Duration
		if *invalid >= b.PenaltyAfter {
			wait = b.Penalty
			*invalid, *authFailures = 0, 0
		} else {
			wait = min(time.Duration(*authFailures)*b.AuthStep, b.AuthMax)
		}
		c.cfg.Logger.Error("认证失败，稍后重试", "err", err, "wait", wait)
		return wait
	}
	*failures++
	wait := b.Base << min(*failures-1, 16)
	if wait > b.Max || wait <= 0 {
		wait = b.Max
	}
	c.cfg.Logger.Warn("与主控的连接断开，稍后重连", "err", err, "wait", wait)
	return wait
}

func (c *Client) runWebsocketLoop(ctx context.Context) error {
	failures, authFailures, invalid := 0, 0, 0
	for {
		authenticated, err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if authenticated {
			failures, authFailures, invalid = 0, 0, 0
		}
		wait := c.computeBackoffWait(err, &failures, &authFailures, &invalid)
		if woken, werr := c.waitOrWake(ctx, wait); werr != nil {
			return nil
		} else if woken {
			failures, authFailures, invalid = 0, 0, 0
		}
	}
}

func (c *Client) runHTTPOnlyLoop(ctx context.Context) error {
	failures, authFailures, invalid := 0, 0, 0
	hbInterval := c.cfg.HTTPHeartbeatInterval
	for {
		interval, err := c.sendHTTPRound(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			failures, authFailures, invalid = 0, 0, 0
			if interval > 0 {
				hbInterval = interval
			}
			if _, werr := c.waitOrWake(ctx, hbInterval); werr != nil {
				return nil
			}
			continue
		}
		wait := c.computeBackoffWait(err, &failures, &authFailures, &invalid)
		if woken, werr := c.waitOrWake(ctx, wait); werr != nil {
			return nil
		} else if woken {
			failures, authFailures, invalid = 0, 0, 0
		}
	}
}

func (c *Client) runAutoLoop(ctx context.Context) error {
	pullStep := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		authenticated, err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if authenticated {
			pullStep = 0
			continue
		}
		var ae *AuthError
		if errors.As(err, &ae) && ae.Reason == badMasterKey {
			if _, werr := c.waitOrWake(ctx, c.cfg.Backoff.AuthStep); werr != nil {
				return nil
			}
			continue
		}

		c.cfg.Logger.Info("auto 模式 WebSocket 暂不可用，降级为加密 HTTP 上报", "err", err)
		wasWS, httpErr := c.runAutoHTTPLoop(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if wasWS {
			pullStep = 0
			continue
		}

		// HTTP 连续失败满阈值，落入 pull 兜底窗口等待后再回外层重探 WS → HTTP。
		pullWait := c.cfg.PullWindowBase << min(pullStep, 8)
		if pullWait > c.cfg.PullWindowMax || pullWait <= 0 {
			pullWait = c.cfg.PullWindowMax
		}
		pullStep++
		c.cfg.Logger.Warn("auto 模式 HTTP 连续失败达到阈值，进入 pull 兜底窗口等待",
			"err", httpErr, "wait", pullWait)
		woken, werr := c.waitOrWake(ctx, pullWait)
		if werr != nil {
			return nil
		}
		if woken {
			pullStep = 0
		}
	}
}

// runAutoHTTPLoop 在 auto 降级期执行加密 HTTP 心跳与流量上报，并周期探测 WS：
// - 若 WS 探测接通，保持在该 WS 会话运行直至断开并返回 wasWS=true；
// - 若 HTTP 连续失败达 cfg.HTTPFailLimit 次，返回 wasWS=false 以落入 pull 兜底窗口。
func (c *Client) runAutoHTTPLoop(ctx context.Context) (wasWS bool, lastErr error) {
	probeTicker := time.NewTicker(c.cfg.WSProbeInterval)
	defer probeTicker.Stop()

	failures := 0
	hbInterval := c.cfg.HTTPHeartbeatInterval

	for {
		interval, err := c.sendHTTPRound(ctx)
		if ctx.Err() != nil {
			return false, nil
		}
		if err == nil {
			failures = 0
			if interval > 0 {
				hbInterval = interval
			}
			t := time.NewTimer(hbInterval)
			select {
			case <-ctx.Done():
				t.Stop()
				return false, nil
			case <-c.wakeupCh:
				t.Stop()
				if authOK, _ := c.session(ctx); authOK {
					return true, nil
				}
			case <-probeTicker.C:
				t.Stop()
				if authOK, _ := c.session(ctx); authOK {
					return true, nil
				}
			case <-t.C:
			}
			continue
		}

		lastErr = err
		failures++
		if failures >= c.cfg.HTTPFailLimit {
			return false, err
		}
		wait := c.cfg.Backoff.Base << min(failures-1, 16)
		if wait > c.cfg.Backoff.Max || wait <= 0 {
			wait = c.cfg.Backoff.Max
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return false, nil
		case <-c.wakeupCh:
			t.Stop()
			failures = 0
			if authOK, _ := c.session(ctx); authOK {
				return true, nil
			}
		case <-probeTicker.C:
			t.Stop()
			if authOK, _ := c.session(ctx); authOK {
				return true, nil
			}
		case <-t.C:
		}
	}
}

func (c *Client) sendHTTPRound(ctx context.Context) (time.Duration, error) {
	rep, err := c.uplink.Call(ctx, xrpc.HTTPRPCMethodHeartbeat, &xrpc.HTTPHeartbeatPayload{BootTime: c.boot}, nil)
	if err != nil {
		return 0, err
	}
	if snapFn, ok := c.methods[xrpc.MethodTrafficSnapshot]; ok {
		if rawSnap, serr := snapFn(ctx, nil); serr == nil {
			if snap, ok := rawSnap.(xrpc.TrafficSnapshot); ok {
				_, _ = c.uplink.Call(ctx, xrpc.HTTPRPCMethodTraffic, nil, &snap)
			}
		}
	}
	if rep.HeartbeatInterval > 0 {
		return time.Duration(rep.HeartbeatInterval) * time.Second, nil
	}
	return 0, nil
}

func wsURL(master string) string {
	u := strings.TrimRight(master, "/")
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	}
	return u + "/api/remote/ws"
}

// session 连一次：握手、认证、心跳与回应请求，直到连接断开。authenticated 表示这一次认证成功过。
func (c *Client) session(ctx context.Context) (authenticated bool, err error) {
	dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	masterAddr := c.getMasterURL()
	// 升级请求只带 User-Agent，不带 Authorization：token 只在加密后的认证消息里出现。
	ws, resp, err := websocket.Dial(dctx, wsURL(masterAddr), &websocket.DialOptions{
		HTTPHeader: http.Header{"User-Agent": {"satchel-agent/" + c.cfg.AgentVersion}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			return false, errors.New("主控暂时拒绝这个来源 IP（最近认证失败太多次）")
		}
		return false, fmt.Errorf("连不上主控：%w", err)
	}
	defer ws.CloseNow()
	conn := xrpc.NewConn(ws)
	if err := xrpc.ClientHandshake(dctx, conn, c.cfg.MasterKey); err != nil {
		if errors.Is(err, xrpc.ErrBadSignature) {
			return false, &AuthError{Reason: badMasterKey}
		}
		return false, fmt.Errorf("握手失败：%w", err)
	}
	info := c.runtimeInfo()
	auth := xrpc.Auth{
		Token:            c.creds.Token(),
		AgentVersion:     info.AgentVersion,
		ControlProtocol:  xrpc.ControlProtocol,
		MinMasterVersion: MinMasterVersion,
		InDocker:         info.InDocker,
		MachineID:        info.MachineID,
		MasterURL:        info.MasterURL,
	}
	if err := conn.Write(dctx, xrpc.TypeAuth, auth); err != nil {
		return false, fmt.Errorf("发认证消息失败：%w", err)
	}
	m, err := conn.Read(dctx)
	if err != nil {
		return false, fmt.Errorf("读认证结果失败：%w", err)
	}
	var res xrpc.AuthResult
	if m.Type != xrpc.TypeAuthResult || xrpc.Decode(m, &res) != nil {
		return false, fmt.Errorf("认证结果不对：%q", m.Type)
	}
	if !res.OK {
		return false, &AuthError{Reason: res.Reason, Message: res.Message}
	}
	cancel()
	interval := time.Duration(res.HeartbeatInterval) * time.Second
	if interval <= 0 {
		interval = defaultHeartbeat
	}
	c.gate.OnWSConnected()
	defer c.gate.OnWSDisconnected()

	c.cfg.Logger.Info("已连上主控", "master", masterAddr, "heartbeat", interval)
	return true, c.serve(ctx, conn, interval)
}

// serve 认证之后的循环：立即发一次心跳，之后按间隔发；读循环回应请求，收到 IP 漂移唤醒时立即短 ping 探活。
func (c *Client) serve(ctx context.Context, conn *xrpc.Conn, interval time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.setActiveWSCancel(cancel)
	defer c.clearActiveWSCancel(cancel)

	readErr := make(chan error, 1)
	go func() { readErr <- c.read(ctx, conn) }()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		info := c.runtimeInfo()
		hb := xrpc.Heartbeat{
			BootTime:     c.boot,
			AgentVersion: info.AgentVersion,
			InDocker:     info.InDocker,
			MachineID:    info.MachineID,
			MasterURL:    info.MasterURL,
		}
		if err := c.write(ctx, conn, xrpc.TypeHeartbeat, hb); err != nil {
			return fmt.Errorf("发心跳失败：%w", err)
		}
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusGoingAway, "agent stopping")
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-c.wsWakeCh:
			pctx, pcancel := context.WithTimeout(ctx, 3*time.Second)
			perr := conn.WS().Ping(pctx)
			pcancel()
			if perr != nil {
				return fmt.Errorf("IP 变化后连接探活失败：%w", perr)
			}
		case <-t.C:
		}
	}
}

func (c *Client) write(ctx context.Context, conn *xrpc.Conn, typ string, payload any) error {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(wctx, typ, payload)
}

func (c *Client) read(ctx context.Context, conn *xrpc.Conn) error {
	for {
		m, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		switch m.Type {
		case xrpc.TypeCall:
			var call xrpc.Call
			if err := xrpc.Decode(m, &call); err != nil {
				return err
			}
			go func() {
				reply := c.methods.Serve(ctx, call)
				err := c.write(ctx, conn, xrpc.TypeReply, reply)
				if err != nil {
					c.cfg.Logger.Warn("回复主控的请求失败", "method", call.Method, "err", err)
				}
				if reply.Error == nil {
					c.flushPendingCleanup()
				}
			}()
		case xrpc.TypeHeartbeatAck:
		default:
			c.cfg.Logger.Debug("忽略不认识的消息类型", "type", m.Type)
		}
	}
}

func (c *Client) handleTokenRotate(_ context.Context, raw json.RawMessage) (any, error) {
	var p xrpc.TokenRotateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("token.rotate 参数解不开：%v", err)}
	}
	if p.Token == "" && p.AgentToken == "" && p.PullToken == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "token.rotate 至少需要提供一把新凭据"}
	}
	for field, v := range map[string]string{
		"token":       p.Token,
		"agent_token": p.AgentToken,
		"pull_token":  p.PullToken,
	} {
		if err := pathguard.RejectControlChars(field, v); err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
		}
	}

	c.rotateMu.Lock()
	defer c.rotateMu.Unlock()

	updated, err := c.loadConfigForEditLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	if p.Token != "" {
		updated.Token = p.Token
	}
	if p.AgentToken != "" {
		updated.AgentToken = p.AgentToken
	}
	if p.PullToken != "" {
		updated.PullToken = p.PullToken
	}
	if err := c.persistConfigLocked(updated); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("保存新凭据配置失败：%v", err)}
	}

	c.creds.Apply(p.Token, p.AgentToken, p.PullToken)
	var roles []string
	if p.AgentToken != "" {
		roles = append(roles, "manage")
	}
	if p.PullToken != "" {
		roles = append(roles, "pull")
	}
	if p.Token != "" {
		roles = append(roles, "uplink")
	}
	c.addPendingCleanup(roles...)

	return xrpc.TokenRotateAck{UpdatedAt: c.cfg.Now().UTC()}, nil
}

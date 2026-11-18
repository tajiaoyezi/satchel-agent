package channel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/satchel/satchel-agent/internal/config"
)

const (
	defaultStealthDelay   = 5 * time.Second
	shutdownServerTimeout = 3 * time.Second
)

type portServer struct {
	name    string
	host    string
	port    int // >0 固定端口；<=0 由系统分派后记住首次绑定端口
	handler http.Handler
	logger  *slog.Logger

	mu       sync.Mutex
	ln       net.Listener
	srv      *http.Server
	bound    int // 记录实际绑定端口（供测试传入 port=0 时开关端口保持同一端口号）
	addr     string
	shutting bool
}

func newPortServer(name, host string, port int, handler http.Handler, logger *slog.Logger) *portServer {
	return &portServer{
		name:    name,
		host:    host,
		port:    port,
		handler: handler,
		logger:  logger,
	}
}

func (ps *portServer) open() error {
	ps.mu.Lock()
	if ps.shutting || ps.ln != nil {
		ps.mu.Unlock()
		return nil
	}
	p := ps.port
	if p == 0 && ps.bound > 0 {
		p = ps.bound
	}
	listenAddr := net.JoinHostPort(ps.host, strconv.Itoa(p))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		ps.mu.Unlock()
		return fmt.Errorf("监听 %s(%s) 失败：%w", ps.name, listenAddr, err)
	}
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok && ps.bound == 0 {
		ps.bound = tcpAddr.Port
	}
	srv := &http.Server{
		Handler:           ps.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ps.ln = ln
	ps.srv = srv
	ps.addr = ln.Addr().String()
	ps.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			ps.logger.Debug("入站 HTTP 监听退出", "port", ps.name, "addr", ps.addr, "err", err)
		}
	}()
	return nil
}

func (ps *portServer) closeListener() {
	ps.mu.Lock()
	ln, srv := ps.ln, ps.srv
	ps.ln, ps.srv, ps.addr = nil, nil, ""
	ps.mu.Unlock()
	if srv != nil {
		// 宽限关闭在途已解密短请求，避免切断正在处理的控制调用；随即确保 listener 关闭。
		ctx, cancel := context.WithTimeout(context.Background(), shutdownServerTimeout)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
}

func (ps *portServer) shutdown() {
	ps.mu.Lock()
	ps.shutting = true
	ps.mu.Unlock()
	ps.closeListener()
}

func (ps *portServer) Addr() string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.addr
}

func (ps *portServer) effectiveTargetPort() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.port > 0 {
		return ps.port
	}
	return ps.bound
}

func (ps *portServer) isOpen() bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.ln != nil && !ps.shutting
}

type preparedPort struct {
	ps      *portServer
	newPort int
	ln      net.Listener
	bound   int
}

func (pp *preparedPort) closeNew() {
	if pp != nil && pp.ln != nil {
		_ = pp.ln.Close()
		pp.ln = nil
	}
}

func (ps *portServer) prepareBind(newPort int) (*preparedPort, error) {
	ps.mu.Lock()
	shutting := ps.shutting
	openNow := ps.ln != nil
	host := ps.host
	curPort := ps.port
	curBound := ps.bound
	ps.mu.Unlock()
	if shutting {
		return nil, errors.New("端口监听已关闭")
	}
	if newPort <= 0 || (curPort == newPort && openNow) || (curPort > 0 && curPort == newPort) || (curBound == newPort && openNow) {
		return &preparedPort{ps: ps, newPort: newPort}, nil
	}
	if !openNow {
		return &preparedPort{ps: ps, newPort: newPort}, nil
	}
	listenAddr := net.JoinHostPort(host, strconv.Itoa(newPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("监听 %s(%s) 失败：%w", ps.name, listenAddr, err)
	}
	bound := newPort
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		bound = tcpAddr.Port
	}
	return &preparedPort{ps: ps, newPort: newPort, ln: ln, bound: bound}, nil
}

func (pp *preparedPort) commit() func() {
	if pp == nil || pp.ps == nil || pp.newPort <= 0 {
		return func() {}
	}
	ps := pp.ps
	ps.mu.Lock()
	ps.port = pp.newPort
	if pp.ln == nil {
		if ps.ln == nil {
			// 未开启时仅更新目标端口（如 auto 隐身态或 websocket 模式）；清空历史 port=0 记录的 bound。
			ps.bound = 0
		}
		ps.mu.Unlock()
		return func() {}
	}
	oldLn, oldSrv := ps.ln, ps.srv
	newSrv := &http.Server{
		Handler:           ps.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ps.bound = pp.bound
	ps.ln = pp.ln
	ps.srv = newSrv
	ps.addr = pp.ln.Addr().String()
	newLn := pp.ln
	ps.mu.Unlock()

	go func() {
		if err := newSrv.Serve(newLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			ps.logger.Debug("入站 HTTP 监听退出", "port", ps.name, "addr", ps.addr, "err", err)
		}
	}()

	return func() {
		if oldSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownServerTimeout)
			_ = oldSrv.Shutdown(ctx)
			cancel()
		}
		if oldLn != nil {
			_ = oldLn.Close()
		}
	}
}

// listenGate 控制节点管理端口与只读轮询端口的按模式启停与 auto 隐身切换：
// - websocket：永不开启任何端口
// - http：常开管理端口
// - pull：常开管理与只读轮询端口
// - auto：默认开双口，WS 认证成功满 stealthDelay 后关闭监听；WS 断开立刻取消延迟定时器并重开监听。
type listenGate struct {
	mode         string
	stealthDelay time.Duration
	manage       *portServer
	pull         *portServer
	logger       *slog.Logger

	mu     sync.Mutex
	closed bool
	timer  *time.Timer
	gen    uint64
}

func newListenGate(mode string, stealthDelay time.Duration, manage, pull *portServer, logger *slog.Logger) *listenGate {
	if stealthDelay <= 0 {
		stealthDelay = defaultStealthDelay
	}
	return &listenGate{
		mode:         mode,
		stealthDelay: stealthDelay,
		manage:       manage,
		pull:         pull,
		logger:       logger,
	}
}

// Start 按模式初始化监听状态。
func (g *listenGate) Start() error {
	switch g.mode {
	case config.ModeWebsocket:
		return nil
	case config.ModeHTTP:
		return g.manage.open()
	case config.ModePull, config.ModeAuto:
		if err := g.manage.open(); err != nil {
			return err
		}
		if err := g.pull.open(); err != nil {
			g.manage.closeListener()
			return err
		}
		return nil
	default:
		return fmt.Errorf("未知连接模式 %q", g.mode)
	}
}

// OnWSConnected 在 auto 模式下 WS 认证通过时启动 5 秒延迟关闭双入站监听。
func (g *listenGate) OnWSConnected() {
	if g.mode != config.ModeAuto {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	g.gen++
	expectedGen := g.gen
	g.timer = time.AfterFunc(g.stealthDelay, func() {
		g.mu.Lock()
		if g.closed || g.gen != expectedGen {
			g.mu.Unlock()
			return
		}
		g.mu.Unlock()
		g.logger.Info("auto 模式 WS 稳定，进入端口隐身并关闭入站监听", "delay", g.stealthDelay)
		g.manage.closeListener()
		g.pull.closeListener()
	})
}

// OnWSDisconnected 在 auto 模式下 WS 断开时立即取消延迟关闭计时并重新开启双口，以便主控降级接管或轮询。
func (g *listenGate) OnWSDisconnected() {
	if g.mode != config.ModeAuto {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	g.gen++
	g.mu.Unlock()

	if err := g.manage.open(); err != nil {
		g.logger.Warn("auto 模式恢复打开管理监听口失败", "err", err)
	}
	if err := g.pull.open(); err != nil {
		g.logger.Warn("auto 模式恢复打开轮询监听口失败", "err", err)
	}
}

func (g *listenGate) Addrs() (manageAddr, pullAddr string) {
	if g.manage != nil {
		manageAddr = g.manage.Addr()
	}
	if g.pull != nil {
		pullAddr = g.pull.Addr()
	}
	return manageAddr, pullAddr
}

// SwitchPorts 无损热切换管理口与只读轮询口：对当前正在监听且发生变化的端口，先在新端口上 listen 成功，
// 再调用 saveFn 落盘 0600 配置，然后原子切入新 http.Server 并返回旧监听器宽限关闭闭包，全程不动内核。
func (g *listenGate) SwitchPorts(listenPort, pullPort int, saveFn func() error) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, errors.New("listenGate 已关闭")
	}

	prepManage, err := g.manage.prepareBind(listenPort)
	if err != nil {
		return nil, err
	}
	prepPull, err := g.pull.prepareBind(pullPort)
	if err != nil {
		prepManage.closeNew()
		return nil, err
	}
	if saveFn != nil {
		if err := saveFn(); err != nil {
			prepManage.closeNew()
			prepPull.closeNew()
			return nil, err
		}
	}

	closeOldManage := prepManage.commit()
	closeOldPull := prepPull.commit()
	return func() {
		closeOldManage()
		closeOldPull()
	}, nil
}

func (g *listenGate) Close() {
	g.mu.Lock()
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	g.gen++
	g.mu.Unlock()
	if g.manage != nil {
		g.manage.shutdown()
	}
	if g.pull != nil {
		g.pull.shutdown()
	}
}

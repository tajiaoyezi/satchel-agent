// Package channel 是节点连主控的通道（m2-02 node-channel，websocket 模式）：按配置连 <主控地址>/api/remote/ws，
// 用主控公钥验握手签名、建立加密会话，凭 token 认证，之后定时发心跳、回应主控的请求；断开后按退避重连。
// 退避照抄 mmwx：普通失败从 5 秒起翻倍、封顶 5 分钟；认证失败第 n 次连续等 n×30 秒、封顶 10 分钟，
// token 无效连续 10 次睡 30 分钟再重新计数（防止孤儿节点骚扰主控）。连上并认证成功后退避清零。
package channel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/satchel/satchel/pkg/xrpc"
)

// MinMasterVersion 是这个 agent 要求的最低主控版本：线格式第一次出现不兼容的变化时填上；空表示不要求。
const MinMasterVersion = ""

const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	// defaultHeartbeat 是主控没给心跳间隔时用的间隔。
	defaultHeartbeat = 30 * time.Second
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
	MasterKey    ed25519.PublicKey
	AgentVersion string
	Logger       *slog.Logger
	Backoff      Backoff
	// Sleep 等待 d 或 ctx 结束（测试里换成记录等待时长、立即返回）。
	Sleep func(ctx context.Context, d time.Duration) error
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
	cfg     Config
	boot    time.Time
	methods xrpc.Methods
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
	c := &Client{cfg: cfg, boot: time.Now().UTC()}
	c.methods = xrpc.Methods{
		xrpc.MethodAgentInfo: func(context.Context, json.RawMessage) (any, error) {
			return xrpc.AgentInfo{AgentVersion: cfg.AgentVersion, ControlProtocol: xrpc.ControlProtocol}, nil
		},
	}
	return c
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

// Run 一直连着主控，直到 ctx 结束（返回 nil）。
func (c *Client) Run(ctx context.Context) error {
	b := c.cfg.Backoff
	failures, authFailures, invalid := 0, 0, 0
	for {
		authenticated, err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if authenticated {
			failures, authFailures, invalid = 0, 0, 0
		}
		var wait time.Duration
		var ae *AuthError
		if errors.As(err, &ae) {
			failures = 0
			authFailures++
			if ae.Reason == xrpc.AuthInvalidToken {
				invalid++
			}
			if invalid >= b.PenaltyAfter {
				wait = b.Penalty
				invalid, authFailures = 0, 0
			} else {
				wait = min(time.Duration(authFailures)*b.AuthStep, b.AuthMax)
			}
			c.cfg.Logger.Error("认证失败，稍后重试", "err", err, "wait", wait)
		} else {
			failures++
			wait = b.Base << min(failures-1, 16)
			if wait > b.Max || wait <= 0 {
				wait = b.Max
			}
			c.cfg.Logger.Warn("与主控的连接断开，稍后重连", "err", err, "wait", wait)
		}
		if err := c.cfg.Sleep(ctx, wait); err != nil {
			return nil
		}
	}
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
	// 升级请求只带 User-Agent，不带 Authorization：token 只在加密后的认证消息里出现。
	ws, resp, err := websocket.Dial(dctx, wsURL(c.cfg.MasterURL), &websocket.DialOptions{
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
	auth := xrpc.Auth{Token: c.cfg.Token, AgentVersion: c.cfg.AgentVersion, ControlProtocol: xrpc.ControlProtocol, MinMasterVersion: MinMasterVersion}
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
	c.cfg.Logger.Info("已连上主控", "master", c.cfg.MasterURL, "heartbeat", interval)
	return true, c.serve(ctx, conn, interval)
}

// serve 认证之后的循环：立即发一次心跳，之后按间隔发；读循环回应请求。任何一边出错就结束。
func (c *Client) serve(ctx context.Context, conn *xrpc.Conn, interval time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	readErr := make(chan error, 1)
	go func() { readErr <- c.read(ctx, conn) }()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := c.write(ctx, conn, xrpc.TypeHeartbeat, xrpc.Heartbeat{BootTime: c.boot}); err != nil {
			return fmt.Errorf("发心跳失败：%w", err)
		}
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusGoingAway, "agent stopping")
			return ctx.Err()
		case err := <-readErr:
			return err
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
				if err := c.write(ctx, conn, xrpc.TypeReply, c.methods.Serve(ctx, call)); err != nil {
					c.cfg.Logger.Warn("回复主控的请求失败", "method", call.Method, "err", err)
				}
			}()
		case xrpc.TypeHeartbeatAck:
		default:
			c.cfg.Logger.Debug("忽略不认识的消息类型", "type", m.Type)
		}
	}
}

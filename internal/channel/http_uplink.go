package channel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"
)

// httpUplink 负责节点经 HTTPS 加密通道上报心跳与流量快照：
// 先调用 POST /api/remote/handshake 交换临时公钥并校验主控双向签名，再经 POST /api/remote/rpc 发送二进制加密信封；
// 严禁携带 HTTP Authorization 请求头，遇到 412 自动清空本地会话重新握手并重试一次。
type httpUplink struct {
	c      *Client
	client *http.Client

	mu   sync.Mutex
	sid  string
	sess *securechan.Session
}

func newHTTPUplink(c *Client) *httpUplink {
	cli := c.cfg.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: handshakeTimeout}
	}
	return &httpUplink{
		c:      c,
		client: cli,
	}
}

func (u *httpUplink) ClearSession() {
	u.mu.Lock()
	u.sid = ""
	u.sess = nil
	u.mu.Unlock()
}

func (u *httpUplink) getSession(ctx context.Context) (string, *securechan.Session, error) {
	u.mu.Lock()
	sid, sess := u.sid, u.sess
	u.mu.Unlock()
	if sid != "" && sess != nil {
		return sid, sess, nil
	}
	return u.handshake(ctx)
}

func (u *httpUplink) handshake(ctx context.Context) (string, *securechan.Session, error) {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	ephPub := ephPriv.PublicKey().Bytes()
	reqBytes, err := json.Marshal(xrpc.HTTPHandshakeReq{AgentEphemeral: ephPub})
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(hctx, http.MethodPost, u.c.getMasterURL()+xrpc.HTTPMasterPathHandshake, bytes.NewReader(reqBytes))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "satchel-agent/"+u.c.cfg.AgentVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("HTTP 握手连接主控失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", nil, errors.New("主控暂时拒绝这个来源 IP（最近认证失败太多次）")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", nil, fmt.Errorf("HTTP 握手失败（%d）：%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var hs xrpc.HTTPHandshakeResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&hs); err != nil {
		return "", nil, fmt.Errorf("HTTP 握手响应解不开：%w", err)
	}
	if hs.SessionID == "" || len(hs.MasterEphemeral) != 32 {
		return "", nil, errors.New("HTTP 握手响应缺少 session_id 或临时公钥")
	}
	if !securechan.VerifyHandshake(u.c.cfg.MasterKey, ephPub, hs.MasterEphemeral, hs.Signature) {
		return "", nil, &AuthError{Reason: badMasterKey}
	}
	masterEph, err := ecdh.X25519().NewPublicKey(hs.MasterEphemeral)
	if err != nil {
		return "", nil, fmt.Errorf("主控临时公钥不合法：%w", err)
	}
	shared, err := ephPriv.ECDH(masterEph)
	if err != nil {
		return "", nil, fmt.Errorf("密钥协商失败：%w", err)
	}
	sess, err := securechan.DeriveSession(shared, ephPub, hs.MasterEphemeral, false)
	if err != nil {
		return "", nil, err
	}
	u.mu.Lock()
	u.sid = hs.SessionID
	u.sess = sess
	u.mu.Unlock()
	return hs.SessionID, sess, nil
}

// Call 向主控 POST /api/remote/rpc 发送一次加密 RPC；若主控返回 412 则清缓存重握手并重试一次。
// 每次成功回复若附带 Config，均立即应用到本地运行配置（包括 agent_log_enabled 与各采集间隔）。
func (u *httpUplink) Call(ctx context.Context, method string, hb *xrpc.HTTPHeartbeatPayload, snap *xrpc.TrafficSnapshot, speed *xrpc.SpeedReport) (*xrpc.AgentHTTPRPCReply, error) {
	for attempt := 0; attempt < 2; attempt++ {
		sid, sess, err := u.getSession(ctx)
		if err != nil {
			return nil, err
		}
		info := u.c.runtimeInfo()
		payload := xrpc.AgentHTTPRPC{
			Method:           method,
			Token:            u.c.creds.Token(),
			AgentVersion:     info.AgentVersion,
			ControlProtocol:  xrpc.ControlProtocol,
			MinMasterVersion: MinMasterVersion,
			InDocker:         info.InDocker,
			MachineID:        info.MachineID,
			MasterURL:        info.MasterURL,
			ExecEnabled:      info.ExecEnabled,
			Heartbeat:        hb,
			Traffic:          snap,
			Speed:            speed,
		}
		plain, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		env, err := sess.Encrypt(plain)
		if err != nil {
			return nil, err
		}
		rctx, cancel := context.WithTimeout(ctx, writeTimeout)
		req, err := http.NewRequestWithContext(rctx, http.MethodPost, u.c.getMasterURL()+xrpc.HTTPMasterPathRPC, bytes.NewReader(env))
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("User-Agent", "satchel-agent/"+u.c.cfg.AgentVersion)
		req.Header.Set(securechan.HeaderSession, sid)
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := u.client.Do(req)
		if err != nil {
			cancel()
			u.ClearSession()
			return nil, fmt.Errorf("HTTP RPC 请求失败：%w", err)
		}
		respBytes, rerr := io.ReadAll(io.LimitReader(resp.Body, xrpc.ReadLimit))
		resp.Body.Close()
		cancel()
		if rerr != nil {
			u.ClearSession()
			return nil, rerr
		}
		if resp.StatusCode == http.StatusPreconditionFailed {
			u.ClearSession()
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, errors.New("主控暂时拒绝这个来源 IP（最近认证失败太多次）")
		}
		if resp.StatusCode != http.StatusOK {
			u.ClearSession()
			return nil, fmt.Errorf("HTTP RPC 返回 %d：%s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
		}
		dec, err := sess.Decrypt(respBytes)
		if err != nil {
			u.ClearSession()
			return nil, fmt.Errorf("解包主控 HTTP 加密响应失败：%w", err)
		}
		var reply xrpc.AgentHTTPRPCReply
		if err := json.Unmarshal(dec, &reply); err != nil {
			return nil, fmt.Errorf("解析主控 HTTP 响应失败：%w", err)
		}
		if !reply.OK {
			switch reply.Reason {
			case xrpc.AuthInvalidToken, xrpc.AuthIncompatible, xrpc.AuthIPConflict:
				return nil, &AuthError{Reason: reply.Reason, Message: reply.Message}
			default:
				return nil, fmt.Errorf("主控拒绝 HTTP %s（%s）：%s", method, reply.Reason, reply.Message)
			}
		}
		if reply.Config != nil {
			u.c.applyRuntimeConfig(*reply.Config)
		}
		return &reply, nil
	}
	return nil, errors.New("主控持续返回 412，加密会话重协商失败")
}

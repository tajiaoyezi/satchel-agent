package channel

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/securechan"
	"github.com/satchel/satchel/pkg/xrpc"
)

const (
	maxPendingHandshakes = 64
	pendingHandshakeTTL  = 30 * time.Second
)

type pendingHandshake struct {
	priv      *ecdh.PrivateKey
	expiresAt time.Time
}

// inboundPort 封装单个节点入站端口（管理口或只读轮询口）的独立认证、会话缓存与方法分派。
// 两端口各自的 NonceWindow、handshake 表、SessionCache、ServeMux 完全隔离，防止会话或路由跨口越权。
type inboundPort struct {
	role       string
	mode       string
	masterKey  ed25519.PublicKey
	tokensFn   func() []string
	methods    xrpc.Methods
	healthFn   func() xrpc.AgentHealth
	nonces     *securechan.NonceWindow
	sessions   *securechan.SessionCache
	now        func() time.Time
	onPostCall func(method string, err *xrpc.Error)

	hsMu       sync.Mutex
	handshakes map[string]pendingHandshake
}

func newInboundPort(role, mode string, masterKey ed25519.PublicKey, tokensFn func() []string, methods xrpc.Methods, healthFn func() xrpc.AgentHealth, now func() time.Time, onPostCall func(string, *xrpc.Error)) *inboundPort {
	if now == nil {
		now = time.Now
	}
	p := &inboundPort{
		role:       role,
		mode:       mode,
		masterKey:  masterKey,
		tokensFn:   tokensFn,
		methods:    methods,
		healthFn:   healthFn,
		nonces:     securechan.NewNonceWindow(securechan.DefaultNonceTTL, 4096, now),
		sessions:   securechan.NewSessionCache(securechan.SessionCacheConfig{TTL: securechan.DefaultSessionTTL, Now: now}),
		now:        now,
		onPostCall: onPostCall,
		handshakes: make(map[string]pendingHandshake),
	}
	return p
}

func (p *inboundPort) ClearSessions() {
	p.sessions.DeleteByServerRole(1, p.role)
}

// Handler 返回套好外层 SilentAuthMiddleware 的独立 http.ServeMux：
// 任何缺少约定 User-Agent、重复 nonce 或未通过 HMAC 校验的请求直接经 Hijack 关闭底层连接、零响应字节。
func (p *inboundPort) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(xrpc.HTTPNodePathHealth, p.handleHealth)
	mux.HandleFunc(xrpc.HTTPNodePathHandshakeInit, p.handleHandshakeInit)
	mux.HandleFunc(xrpc.HTTPNodePathHandshakeFinish, p.handleHandshakeFinish)
	mux.HandleFunc(xrpc.HTTPNodePathRPC, p.handleRPC)
	if p.role == "pull" {
		// 只读轮询口同时暴露精简拉取路径，但仍强制走相同加密 RPC 与方法白名单校验。
		mux.HandleFunc(xrpc.HTTPNodePathPullTraffic, p.handleRPC)
	}
	return p.silentAuthMiddleware(mux)
}

func (p *inboundPort) silentAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(p.masterKey) != ed25519.PublicKeySize {
			closeSilent(w)
			return
		}
		ua := r.UserAgent()
		if !strings.HasPrefix(ua, securechan.UserAgentPrefix) {
			closeSilent(w)
			return
		}
		nonce := r.Header.Get(securechan.HeaderNonce)
		sig := r.Header.Get(securechan.HeaderAuth)
		tokens := p.tokensFn()
		if len(tokens) == 0 {
			closeSilent(w)
			return
		}
		if _, ok := securechan.VerifySilentAuth(tokens, r.Method, r.URL.Path, nonce, sig); !ok || !p.nonces.Allow(nonce) {
			closeSilent(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func closeSilent(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	// 仅在非真实 TCP 连接的纯内存 Recorder 测试分支兜底。
	w.WriteHeader(http.StatusForbidden)
}

func (p *inboundPort) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if p.healthFn != nil {
		_ = json.NewEncoder(w).Encode(p.healthFn())
		return
	}
	_ = json.NewEncoder(w).Encode(xrpc.AgentHealth{Status: "ok", Mode: p.mode})
}

func (p *inboundPort) handleHandshakeInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(p.masterKey) != ed25519.PublicKeySize {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// 消耗限长请求体避免 keep-alive 残留。
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hid, err := securechan.GenerateSessionID()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	now := p.now()
	p.hsMu.Lock()
	for k, h := range p.handshakes {
		if !now.Before(h.expiresAt) {
			delete(p.handshakes, k)
		}
	}
	if len(p.handshakes) >= maxPendingHandshakes {
		var oldestKey string
		var oldestExp time.Time
		for k, h := range p.handshakes {
			if oldestKey == "" || h.expiresAt.Before(oldestExp) {
				oldestKey, oldestExp = k, h.expiresAt
			}
		}
		if oldestKey != "" {
			delete(p.handshakes, oldestKey)
		}
	}
	p.handshakes[hid] = pendingHandshake{priv: priv, expiresAt: now.Add(pendingHandshakeTTL)}
	p.hsMu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(xrpc.NodeHandshakeInitResp{
		HandshakeID:    hid,
		AgentEphemeral: priv.PublicKey().Bytes(),
	})
}

func (p *inboundPort) handleHandshakeFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(p.masterKey) != ed25519.PublicKeySize {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req xrpc.NodeHandshakeFinishReq
	if err := json.Unmarshal(raw, &req); err != nil || req.HandshakeID == "" || len(req.MasterEphemeral) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.hsMu.Lock()
	hs, ok := p.handshakes[req.HandshakeID]
	delete(p.handshakes, req.HandshakeID)
	p.hsMu.Unlock()
	if !ok || !p.now().Before(hs.expiresAt) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	agentEph := hs.priv.PublicKey().Bytes()
	if !securechan.VerifyHandshake(p.masterKey, agentEph, req.MasterEphemeral, req.Signature) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	masterEph, err := ecdh.X25519().NewPublicKey(req.MasterEphemeral)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	shared, err := hs.priv.ECDH(masterEph)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sess, err := securechan.DeriveSession(shared, agentEph, req.MasterEphemeral, false)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sid, err := securechan.GenerateSessionID()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := p.sessions.Put(sid, sess, 1, p.role); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(xrpc.NodeHandshakeFinishResp{SessionID: sid})
}

func (p *inboundPort) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(p.masterKey) != ed25519.PublicKeySize {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	sid := strings.TrimSpace(r.Header.Get(securechan.HeaderSession))
	if sid == "" {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	sess, _, _, ok := p.sessions.Get(sid)
	if !ok {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, xrpc.ReadLimit))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	plain, err := sess.Decrypt(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var call xrpc.Call
	if err := json.Unmarshal(plain, &call); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reply := p.methods.Serve(r.Context(), call)
	replyBytes, err := json.Marshal(reply)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	env, err := sess.Encrypt(replyBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(env)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	if p.onPostCall != nil {
		p.onPostCall(call.Method, reply.Error)
	}
}

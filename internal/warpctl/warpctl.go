// Package warpctl 实现节点侧纯 Go Cloudflare WARP WireGuard 注册、授权、离线导入与 0600 原子凭据存储。
package warpctl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// FileName 是节点数据目录下保存 WARP WireGuard 凭据的文件名（0600）。
const FileName = "warp.json"

// State 是持久化在节点 <dataDir>/warp.json 的内部结构（绝不通过 status RPC 原样暴露）。
type State struct {
	AccountType   string    `json:"account_type"`
	DeviceID      string    `json:"device_id,omitempty"`
	AccessToken   string    `json:"access_token,omitempty"`
	PrivateKey    string    `json:"private_key"`
	PublicKey     string    `json:"public_key"`
	PeerPublicKey string    `json:"peer_public_key"`
	Endpoint      string    `json:"endpoint"`
	AddressV4     string    `json:"address_v4"`
	AddressV6     string    `json:"address_v6,omitempty"`
	Reserved      []int     `json:"reserved,omitempty"`
	MTU           int       `json:"mtu"`
	LicenseKey    string    `json:"license_key,omitempty"`
	APIBase       string    `json:"api_base,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Manager 管理单节点 WARP 凭据生命周期，所有读写操作受互斥锁保护。
type Manager struct {
	mu      sync.Mutex
	path    string
	client  *http.Client
	apiBase string
	now     func() time.Time
}

// New 创建指向 <dataDir>/warp.json 的 WARP 管理器。
func New(dataDir string) *Manager {
	return &Manager{
		path:    filepath.Join(dataDir, FileName),
		client:  &http.Client{Timeout: 20 * time.Second},
		apiBase: xrpc.DefaultWarpAPIBase,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Path 返回 warp.json 路径。
func (m *Manager) Path() string { return m.path }

// Status 只读查询节点 WARP 状态，绝不返回私钥、access_token 或 license_key。
func (m *Manager) Status(_ context.Context) (*xrpc.WarpStatusResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok, err := m.loadLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("读取 WARP 状态失败：%v", err)}
	}
	if !ok {
		return &xrpc.WarpStatusResult{Installed: false, Message: "节点尚未配置 WARP"}, nil
	}
	res := st.toStatus()
	return &res, nil
}

// Credentials 读取节点 WARP WireGuard 凭据供主控构造 sing-box 出站 Plan；未安装报 CodeConflict。
func (m *Manager) Credentials(_ context.Context) (*xrpc.WarpCredentialsResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok, err := m.loadLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("读取 WARP 凭据失败：%v", err)}
	}
	if !ok {
		return nil, &xrpc.Error{Code: xrpc.CodeConflict, Message: "节点尚未安装或导入 WARP 凭据，请先执行 server warp install 或 server warp authorize"}
	}
	mtu := st.MTU
	if mtu == 0 {
		mtu = xrpc.DefaultWarpMTU
	}
	return &xrpc.WarpCredentialsResult{
		Installed:     true,
		AccountType:   st.AccountType,
		PrivateKey:    st.PrivateKey,
		PublicKey:     st.PublicKey,
		PeerPublicKey: st.PeerPublicKey,
		Endpoint:      st.Endpoint,
		AddressV4:     st.AddressV4,
		AddressV6:     st.AddressV6,
		Reserved:      append([]int(nil), st.Reserved...),
		MTU:           mtu,
	}, nil
}

// Install 向 Cloudflare WARP API 注册新设备并落盘 warp.json（已安装且未传 Force 时幂等返回）。
func (m *Manager) Install(ctx context.Context, p xrpc.WarpInstallParams) (*xrpc.WarpInstallResult, error) {
	mtu, err := validateMTU(p.MTU)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	endpoint, err := validateOptionalEndpoint(p.Endpoint)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	apiBase, err := validateAPIBase(p.APIBase, m.apiBase)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	license := strings.TrimSpace(p.LicenseKey)

	m.mu.Lock()
	defer m.mu.Unlock()

	if !p.Force {
		if existing, ok, lerr := m.loadLocked(); lerr == nil && ok {
			res := &xrpc.WarpInstallResult{
				WarpStatusResult: existing.toStatus(),
				AlreadyInstalled: true,
			}
			res.Message = "WARP 已配置（如需重新注册请指定 force）"
			return res, nil
		}
	}

	privB64, pubB64, err := generateWireGuardKeypair()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("生成 WireGuard 密钥失败：%v", err)}
	}
	regResp, err := m.registerDevice(ctx, apiBase, pubB64)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("注册 Cloudflare WARP 设备失败：%v", err)}
	}

	st := stateFromCFReg(regResp, privB64, pubB64, mtu, endpoint, apiBase, m.now())
	if license != "" {
		if err := m.bindLicense(ctx, apiBase, st.DeviceID, st.AccessToken, license); err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("绑定 WARP+ license 失败：%v", err)}
		}
		st.LicenseKey = license
		st.AccountType = "plus"
		if refreshed, rerr := m.fetchDevice(ctx, apiBase, st.DeviceID, st.AccessToken); rerr == nil && refreshed != nil {
			mergeCFRefresh(&st, refreshed)
		}
	}

	if err := m.saveLocked(st); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("持久化 WARP 凭据失败：%v", err)}
	}
	res := &xrpc.WarpInstallResult{
		WarpStatusResult: st.toStatus(),
		AlreadyInstalled: false,
	}
	res.Message = "WARP WireGuard 凭据已生成并安全落盘"
	return res, nil
}

// Authorize 支持两种互斥模式：WARP+ license 绑定（升级现有设备）或离线 WireGuard 凭据导入。
func (m *Manager) Authorize(ctx context.Context, p xrpc.WarpAuthorizeParams) (*xrpc.WarpAuthorizeResult, error) {
	license := strings.TrimSpace(p.LicenseKey)
	privKey := strings.TrimSpace(p.PrivateKey)
	hasLicense := license != ""
	hasImport := privKey != "" || strings.TrimSpace(p.AddressV4) != ""
	if hasLicense && hasImport {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "license_key 授权模式与离线导入模式（private_key/address_v4）不能同时指定"}
	}
	if !hasLicense && !hasImport {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "必须提供 license_key 或离线导入所需的 private_key 与 address_v4"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if hasImport {
		st, err := buildImportedState(p, m.now())
		if err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
		}
		if err := m.saveLocked(st); err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("保存离线 WARP 凭据失败：%v", err)}
		}
		res := &xrpc.WarpAuthorizeResult{
			WarpStatusResult: st.toStatus(),
			Mode:             "import",
		}
		res.Message = "已导入离线 WARP WireGuard 凭据"
		return res, nil
	}

	// WARP+ license 绑定模式
	st, ok, err := m.loadLocked()
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("读取现有 WARP 配置失败：%v", err)}
	}
	if !ok || strings.TrimSpace(st.DeviceID) == "" || strings.TrimSpace(st.AccessToken) == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeConflict, Message: "节点尚未完成 WARP 设备注册（或当前为离线导入凭据），无法绑定 WARP+ license"}
	}
	fallbackBase := st.APIBase
	if fallbackBase == "" {
		fallbackBase = m.apiBase
	}
	apiBase, err := validateAPIBase(p.APIBase, fallbackBase)
	if err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: err.Error()}
	}
	if err := m.bindLicense(ctx, apiBase, st.DeviceID, st.AccessToken, license); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("绑定 WARP+ license 失败：%v", err)}
	}
	st.LicenseKey = license
	st.AccountType = "plus"
	st.APIBase = apiBase
	st.UpdatedAt = m.now()
	if refreshed, rerr := m.fetchDevice(ctx, apiBase, st.DeviceID, st.AccessToken); rerr == nil && refreshed != nil {
		mergeCFRefresh(&st, refreshed)
	}
	if err := m.saveLocked(st); err != nil {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("更新 WARP 凭据失败：%v", err)}
	}
	res := &xrpc.WarpAuthorizeResult{
		WarpStatusResult: st.toStatus(),
		Mode:             "license",
	}
	res.Message = "WARP+ license 绑定成功"
	return res, nil
}

// Remove 原子删除节点 warp.json（未安装时幂等返回成功）。
func (m *Manager) Remove(_ context.Context) (*xrpc.WarpRemoveResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := os.Remove(m.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, &xrpc.Error{Code: xrpc.CodeFailed, Message: fmt.Sprintf("删除 WARP 凭据失败：%v", err)}
	}
	msg := "已清理节点 WARP 凭据"
	if errors.Is(err, os.ErrNotExist) {
		msg = "节点原本未配置 WARP 凭据"
	}
	return &xrpc.WarpRemoveResult{Removed: true, Message: msg}, nil
}

func (s State) toStatus() xrpc.WarpStatusResult {
	ts := s.UpdatedAt.UTC()
	var tp *time.Time
	if !ts.IsZero() {
		tp = &ts
	}
	return xrpc.WarpStatusResult{
		Installed:     true,
		AccountType:   s.AccountType,
		DeviceID:      s.DeviceID,
		PublicKey:     s.PublicKey,
		PeerPublicKey: s.PeerPublicKey,
		Endpoint:      s.Endpoint,
		AddressV4:     s.AddressV4,
		AddressV6:     s.AddressV6,
		Reserved:      append([]int(nil), s.Reserved...),
		MTU:           s.MTU,
		HasLicense:    strings.TrimSpace(s.LicenseKey) != "",
		UpdatedAt:     tp,
	}
}

func (m *Manager) loadLocked() (State, bool, error) {
	raw, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, false, err
	}
	if strings.TrimSpace(st.PrivateKey) == "" || strings.TrimSpace(st.AddressV4) == "" {
		return State{}, false, fmt.Errorf("warp.json 内容不完整")
	}
	return st, true, nil
}

func (m *Manager) saveLocked(st State) error {
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := fmt.Sprintf("%s.tmp.%d", m.path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// --- Cloudflare WARP Client API 交互 ---

type cfRegResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		ID          string `json:"id"`
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
				V4   string `json:"v4"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func (m *Manager) registerDevice(ctx context.Context, apiBase, pubB64 string) (*cfRegResponse, error) {
	payload := map[string]any{
		"key":           pubB64,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           m.now().Format(time.RFC3339),
		"model":         "PC",
		"serial_number": "",
		"locale":        "en_US",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/reg", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setCFHeaders(req, "")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WARP API 返回状态码 %d：%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out cfRegResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("解析 WARP 注册响应失败：%w", err)
	}
	if strings.TrimSpace(out.ID) == "" || strings.TrimSpace(out.Token) == "" {
		return nil, fmt.Errorf("WARP 注册响应缺少 id 或 token")
	}
	return &out, nil
}

func (m *Manager) bindLicense(ctx context.Context, apiBase, deviceID, accessToken, license string) error {
	body, _ := json.Marshal(map[string]string{"license": license})
	u := fmt.Sprintf("%s/reg/%s/account", strings.TrimRight(apiBase, "/"), url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	setCFHeaders(req, accessToken)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("WARP license API 返回状态码 %d：%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (m *Manager) fetchDevice(ctx context.Context, apiBase, deviceID, accessToken string) (*cfRegResponse, error) {
	u := fmt.Sprintf("%s/reg/%s", strings.TrimRight(apiBase, "/"), url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	setCFHeaders(req, accessToken)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out cfRegResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func setCFHeaders(req *http.Request, bearer string) {
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
}

func stateFromCFReg(r *cfRegResponse, privB64, pubB64 string, mtu int, endpointOverride, apiBase string, now time.Time) State {
	peerPub := xrpc.DefaultWarpPeerPublicKey
	endpoint := xrpc.DefaultWarpEndpoint
	if len(r.Config.Peers) > 0 {
		if pk := strings.TrimSpace(r.Config.Peers[0].PublicKey); pk != "" {
			peerPub = pk
		}
		if h := strings.TrimSpace(r.Config.Peers[0].Endpoint.Host); h != "" {
			if _, _, err := net.SplitHostPort(h); err == nil {
				endpoint = h
			} else if v4 := strings.TrimSpace(r.Config.Peers[0].Endpoint.V4); v4 != "" {
				endpoint = v4
			}
		} else if v4 := strings.TrimSpace(r.Config.Peers[0].Endpoint.V4); v4 != "" {
			endpoint = v4
		}
	}
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	addrV4 := ensureCIDR(strings.TrimSpace(r.Config.Interface.Addresses.V4), 32)
	if addrV4 == "" {
		addrV4 = "172.16.0.2/32"
	}
	addrV6 := ensureCIDR(strings.TrimSpace(r.Config.Interface.Addresses.V6), 128)
	reserved := decodeClientIDReserved(r.Config.ClientID)
	acctType := strings.ToLower(strings.TrimSpace(r.Account.AccountType))
	if acctType == "" {
		acctType = "free"
	}
	return State{
		AccountType:   acctType,
		DeviceID:      r.ID,
		AccessToken:   r.Token,
		PrivateKey:    privB64,
		PublicKey:     pubB64,
		PeerPublicKey: peerPub,
		Endpoint:      endpoint,
		AddressV4:     addrV4,
		AddressV6:     addrV6,
		Reserved:      reserved,
		MTU:           mtu,
		LicenseKey:    strings.TrimSpace(r.Account.License),
		APIBase:       apiBase,
		UpdatedAt:     now,
	}
}

func mergeCFRefresh(st *State, r *cfRegResponse) {
	if acct := strings.ToLower(strings.TrimSpace(r.Account.AccountType)); acct != "" {
		st.AccountType = acct
	}
	if v4 := ensureCIDR(strings.TrimSpace(r.Config.Interface.Addresses.V4), 32); v4 != "" {
		st.AddressV4 = v4
	}
	if v6 := ensureCIDR(strings.TrimSpace(r.Config.Interface.Addresses.V6), 128); v6 != "" {
		st.AddressV6 = v6
	}
	if res := decodeClientIDReserved(r.Config.ClientID); len(res) == 3 {
		st.Reserved = res
	}
}

func buildImportedState(p xrpc.WarpAuthorizeParams, now time.Time) (State, error) {
	privStr := strings.TrimSpace(p.PrivateKey)
	if privStr == "" {
		return State{}, fmt.Errorf("离线导入必须提供 private_key")
	}
	privBytes, err := base64.StdEncoding.DecodeString(privStr)
	if err != nil || len(privBytes) != 32 {
		return State{}, fmt.Errorf("private_key 必须是标准 Base64 编码的 32 字节 WireGuard 私钥")
	}
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return State{}, fmt.Errorf("private_key 解析失败：%v", err)
	}
	pubStr := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())

	v4, err := validateCIDR(p.AddressV4, false)
	if err != nil {
		return State{}, fmt.Errorf("address_v4 非法：%v", err)
	}
	v6 := ""
	if strings.TrimSpace(p.AddressV6) != "" {
		v6, err = validateCIDR(p.AddressV6, true)
		if err != nil {
			return State{}, fmt.Errorf("address_v6 非法：%v", err)
		}
	}

	peerPub := strings.TrimSpace(p.PeerPublicKey)
	if peerPub == "" {
		peerPub = xrpc.DefaultWarpPeerPublicKey
	} else {
		rawPeer, perr := base64.StdEncoding.DecodeString(peerPub)
		if perr != nil || len(rawPeer) != 32 {
			return State{}, fmt.Errorf("peer_public_key 必须是标准 Base64 编码的 32 字节公钥")
		}
	}

	endpoint, err := validateOptionalEndpoint(p.Endpoint)
	if err != nil {
		return State{}, err
	}
	if endpoint == "" {
		endpoint = xrpc.DefaultWarpEndpoint
	}
	if len(p.Reserved) != 0 && len(p.Reserved) != 3 {
		return State{}, fmt.Errorf("reserved 必须为空或恰好 3 个 0..255 字节，当前 %d 个", len(p.Reserved))
	}
	for _, b := range p.Reserved {
		if b < 0 || b > 255 {
			return State{}, fmt.Errorf("reserved 字节 %d 必须在 0..255 之间", b)
		}
	}
	mtu, err := validateMTU(p.MTU)
	if err != nil {
		return State{}, err
	}

	return State{
		AccountType:   "imported",
		PrivateKey:    privStr,
		PublicKey:     pubStr,
		PeerPublicKey: peerPub,
		Endpoint:      endpoint,
		AddressV4:     v4,
		AddressV6:     v6,
		Reserved:      append([]int(nil), p.Reserved...),
		MTU:           mtu,
		UpdatedAt:     now,
	}, nil
}

func generateWireGuardKeypair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		nil
}

func decodeClientIDReserved(clientID string) []int {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(clientID))
	if err != nil || len(raw) < 3 {
		return nil
	}
	return []int{int(raw[0]), int(raw[1]), int(raw[2])}
}

func ensureCIDR(raw string, bits int) string {
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "/") {
		return raw
	}
	return fmt.Sprintf("%s/%d", raw, bits)
}

func validateCIDR(raw string, wantV6 bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("地址不能为空")
	}
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", err
		}
		if wantV6 && !addr.Is6() {
			return "", fmt.Errorf("%q 不是 IPv6 地址", s)
		}
		if !wantV6 && !addr.Is4() {
			return "", fmt.Errorf("%q 不是 IPv4 地址", s)
		}
		if wantV6 {
			return addr.String() + "/128", nil
		}
		return addr.String() + "/32", nil
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return "", err
	}
	if wantV6 && !pfx.Addr().Is6() {
		return "", fmt.Errorf("%q 不是 IPv6 CIDR", s)
	}
	if !wantV6 && !pfx.Addr().Is4() {
		return "", fmt.Errorf("%q 不是 IPv4 CIDR", s)
	}
	return pfx.String(), nil
}

func validateMTU(mtu int) (int, error) {
	if mtu == 0 {
		return xrpc.DefaultWarpMTU, nil
	}
	if mtu < xrpc.MinWarpMTU || mtu > xrpc.MaxWarpMTU {
		return 0, fmt.Errorf("mtu %d 必须在 %d..%d 之间", mtu, xrpc.MinWarpMTU, xrpc.MaxWarpMTU)
	}
	return mtu, nil
}

func validateOptionalEndpoint(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("endpoint %q 必须是 host:port 格式", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("endpoint %q 端口必须在 1..65535 之间", raw)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validateAPIBase(raw, fallback string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		s = strings.TrimSpace(fallback)
	}
	if s == "" {
		s = xrpc.DefaultWarpAPIBase
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("api_base %q 必须是合法的 http:// 或 https:// 地址", raw)
	}
	return strings.TrimRight(s, "/"), nil
}

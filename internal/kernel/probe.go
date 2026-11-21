package kernel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	maxProbeBodyBytes = 4096
	maxProbeRedirects = 3
)

var (
	// ErrNotRunning 表示内核尚未启动，无法执行运行期出站探活。
	ErrNotRunning = errors.New("内核未运行")
	// ErrOutboundNotFound 表示当前运行中内核找不到指定 tag 的出站或 endpoint。
	ErrOutboundNotFound = errors.New("未找到指定出站")
	// ErrInvalidProbeURL 表示探测地址不是合法的 http(s) URL。
	ErrInvalidProbeURL = errors.New("探测地址必须是合法的 http:// 或 https:// URL")
)

// ValidateProbeURL 校验出站探活目标地址仅允许带主机的 http:// 或 https://。
func ValidateProbeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w：%v", ErrInvalidProbeURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || strings.TrimSpace(u.Hostname()) == "" {
		return nil, fmt.Errorf("%w：%q", ErrInvalidProbeURL, raw)
	}
	return u, nil
}

// ProbeOutbound 通过运行中 sing-box 内核的指定出站（或顶层 endpoint）发起单次 HTTP GET 探测。
// 探测过程不修改磁盘配置、不重启内核、不中断现有连接；禁用跨协议跳转并限制响应体读取上限。
func (k *Kernel) ProbeOutbound(ctx context.Context, tag, targetURL string) (int, int64, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return 0, 0, fmt.Errorf("%w：tag 不能为空", ErrOutboundNotFound)
	}
	parsedURL, err := ValidateProbeURL(targetURL)
	if err != nil {
		return 0, 0, err
	}

	k.mu.Lock()
	inst := k.instance
	k.mu.Unlock()
	if inst == nil {
		return 0, 0, ErrNotRunning
	}

	var dialer adapter.Outbound
	if ob, ok := inst.Outbound().Outbound(tag); ok && ob != nil {
		dialer = ob
	} else if em := inst.Endpoint(); em != nil {
		if ep, ok := em.Get(tag); ok && ep != nil {
			dialer = ep
		}
	}
	if dialer == nil {
		return 0, 0, fmt.Errorf("%w：%s", ErrOutboundNotFound, tag)
	}

	tr := &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, N.NetworkName(network), M.ParseSocksaddr(addr))
		},
		DisableKeepAlives: true,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxProbeRedirects {
				return fmt.Errorf("重定向次数超过上限（%d）", maxProbeRedirects)
			}
			prevScheme := strings.ToLower(via[len(via)-1].URL.Scheme)
			nextScheme := strings.ToLower(req.URL.Scheme)
			if (nextScheme != "http" && nextScheme != "https") || nextScheme != prevScheme {
				return fmt.Errorf("禁止跨协议跳转：%s -> %s", prevScheme, nextScheme)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "satchel-agent-probe/1")

	start := time.Now()
	resp, err := client.Do(req)
	latencyMs := time.Since(start).Milliseconds()
	if latencyMs < 0 {
		latencyMs = 0
	}
	if err != nil {
		return 0, latencyMs, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))
	return resp.StatusCode, latencyMs, nil
}

package channel

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultIPProbeInterval 是后台公网 IP 漂移探测的默认间隔。
const DefaultIPProbeInterval = 60 * time.Second

// IPProber 探测当前出口公网 IPv4 / IPv6（任一协议栈不可用时对应返回空串）。
type IPProber func(ctx context.Context) (v4, v6 string, err error)

// DefaultIPProber 分别使用 tcp4 与 tcp6 短超时出向查询公网 IP；失败时不阻塞或误清空缓存。
func DefaultIPProber(ctx context.Context) (v4, v6 string, err error) {
	v4, err4 := queryPublicIP(ctx, "tcp4", "https://api4.ipify.org")
	v6, err6 := queryPublicIP(ctx, "tcp6", "https://api6.ipify.org")
	if v4 == "" && v6 == "" {
		if err4 != nil {
			return "", "", err4
		}
		return "", "", err6
	}
	return v4, v6, nil
}

func queryPublicIP(ctx context.Context, network, endpoint string) (string, error) {
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(c, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	ipStr := strings.TrimSpace(string(raw))
	if net.ParseIP(ipStr) == nil {
		return "", nil
	}
	return ipStr, nil
}

func (c *Client) runIPProber(ctx context.Context) {
	interval := c.cfg.IPProbeInterval
	if interval <= 0 || c.cfg.IPProber == nil {
		return
	}
	var (
		hasBaseline bool
		lastV4      string
		lastV6      string
	)
	check := func() {
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		v4, v6, err := c.cfg.IPProber(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil && v4 == "" && v6 == "" {
			return // 保留旧缓存，探测失败不清空也不误报变化
		}
		nextV4, nextV6 := lastV4, lastV6
		if v4 != "" {
			nextV4 = v4
		}
		if v6 != "" {
			nextV6 = v6
		}
		if !hasBaseline {
			if nextV4 != "" || nextV6 != "" {
				hasBaseline = true
				lastV4, lastV6 = nextV4, nextV6
			}
			return
		}
		if nextV4 != lastV4 || nextV6 != lastV6 {
			c.cfg.Logger.Info("检测到出口公网 IP 变化，立即唤醒通道探测重连",
				"old_v4", lastV4, "new_v4", nextV4, "old_v6", lastV6, "new_v6", nextV6)
			lastV4, lastV6 = nextV4, nextV6
			c.triggerWakeup()
		}
	}

	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

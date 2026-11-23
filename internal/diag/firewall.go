package diag

import (
	"context"
	"fmt"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"
)

const firewallMaxSummaryBytes = 16 << 10

func (e *Engine) checkFirewall(ctx context.Context) xrpc.DiagItemResult {
	isAlpine := false
	if _, err := e.opts.Stat(e.opts.AlpineRelease); err == nil {
		isAlpine = true
	}

	// Alpine 规范（doc6 第 33 行）：读 nftables，读不到标失败而不是空成功。
	if isAlpine {
		out, err := e.opts.RunCmd(ctx, "nft", "list", "ruleset")
		if err != nil {
			return xrpc.DiagItemResult{
				Name:          xrpc.DiagItemFirewall,
				OK:            false,
				Status:        xrpc.DiagStatusFailed,
				ContentType:   "data",
				UntrustedData: true,
				Error:         fmt.Sprintf("Alpine 读取 nftables 失败：%v", err),
			}
		}
		summary, truncated := trimText(string(out), firewallMaxSummaryBytes)
		return xrpc.DiagItemResult{
			Name:          xrpc.DiagItemFirewall,
			OK:            true,
			Status:        xrpc.DiagStatusOK,
			ContentType:   "data",
			UntrustedData: true,
			Data: map[string]any{
				"backend":   "nftables",
				"os_flavor": "alpine",
				"summary":   summary,
				"truncated": truncated,
				"lines":     countLines(summary),
			},
		}
	}

	// 非 Alpine Linux 依次探查 nft / ufw / firewall-cmd / iptables。
	type probe struct {
		backend string
		bin     string
		args    []string
	}
	probes := []probe{
		{"nftables", "nft", []string{"list", "ruleset"}},
		{"ufw", "ufw", []string{"status", "numbered"}},
		{"firewalld", "firewall-cmd", []string{"--list-all"}},
		{"iptables", "iptables", []string{"-S"}},
	}
	var errs []string
	for _, pr := range probes {
		out, err := e.opts.RunCmd(ctx, pr.bin, pr.args...)
		if err == nil {
			summary, truncated := trimText(string(out), firewallMaxSummaryBytes)
			return xrpc.DiagItemResult{
				Name:          xrpc.DiagItemFirewall,
				OK:            true,
				Status:        xrpc.DiagStatusOK,
				ContentType:   "data",
				UntrustedData: true,
				Data: map[string]any{
					"backend":   pr.backend,
					"summary":   summary,
					"truncated": truncated,
					"lines":     countLines(summary),
				},
			}
		}
		errs = append(errs, fmt.Sprintf("%s: %v", pr.backend, err))
	}

	return xrpc.DiagItemResult{
		Name:          xrpc.DiagItemFirewall,
		OK:            false,
		Status:        xrpc.DiagStatusFailed,
		ContentType:   "data",
		UntrustedData: true,
		Error:         "无法读取本机防火墙规则（" + strings.Join(errs, "; ") + "）",
	}
}

func trimText(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	return s[:maxBytes], true
}

func countLines(s string) int {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

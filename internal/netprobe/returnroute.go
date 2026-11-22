package netprobe

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// DefaultCarrierTargets 为中国主流运营商提供默认返程测路目标（可被 probe.target_ip 覆盖）。
var DefaultCarrierTargets = map[string]struct {
	IP     string
	Region string
}{
	"CT":  {IP: "202.97.94.229", Region: "Shanghai"},
	"CU":  {IP: "210.22.97.1", Region: "Shanghai"},
	"CM":  {IP: "211.136.112.200", Region: "Shanghai"},
	"EDU": {IP: "202.112.14.151", Region: "Beijing"},
}

// Tracer 抽象路由追踪执行器，便于单测注入确定性跃点。
type Tracer interface {
	Trace(ctx context.Context, target string, port, maxHops int, timeout time.Duration) ([]xrpc.ReturnRouteHop, string, error)
}

// SystemTracer 优先调用系统 traceroute / tracepath，若精简容器缺失则回落纯 Go TCP 连通探测。
type SystemTracer struct {
	LookPath func(file string) (string, error)
	RunCmd   func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultTracer 返回默认系统追踪器。
func DefaultTracer() Tracer {
	return &SystemTracer{
		LookPath: exec.LookPath,
		RunCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
	}
}

func (t *SystemTracer) Trace(ctx context.Context, target string, port, maxHops int, timeout time.Duration) ([]xrpc.ReturnRouteHop, string, error) {
	lookPath := t.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	runCmd := t.RunCmd
	if runCmd == nil {
		runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}

	waitSec := int(timeout.Seconds())
	if waitSec < 1 {
		waitSec = 1
	}
	if _, err := lookPath("traceroute"); err == nil {
		out, cerr := runCmd(ctx, "traceroute", "-n", "-q", "1", "-w", strconv.Itoa(waitSec), "-m", strconv.Itoa(maxHops), target)
		hops := parseTracerouteOutput(string(out))
		if len(hops) > 0 {
			return hops, "traceroute", nil
		}
		if cerr == nil {
			return hops, "traceroute", nil
		}
	}
	if _, err := lookPath("tracepath"); err == nil {
		out, cerr := runCmd(ctx, "tracepath", "-n", "-m", strconv.Itoa(maxHops), target)
		hops := parseTracerouteOutput(string(out))
		if len(hops) > 0 {
			return hops, "tracepath", nil
		}
		if cerr == nil {
			return hops, "tracepath", nil
		}
	}

	// 纯 Go 回落：探测目标端口连通并记录终跳，避免精简容器因缺少 traceroute 报错中断任务。
	if port <= 0 {
		port = 80
	}
	t0 := time.Now()
	d := &net.Dialer{Timeout: timeout}
	conn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if derr != nil {
		return nil, "direct-fallback", fmt.Errorf("未检测到 traceroute/tracepath 且 TCP 探测 %s:%d 失败：%v", target, port, derr)
	}
	remoteIP := target
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
		remoteIP = ra.IP.String()
	}
	_ = conn.Close()
	return []xrpc.ReturnRouteHop{
		{Hop: 1, IP: remoteIP, LatencyMS: time.Since(t0).Milliseconds(), Note: "direct TCP fallback (traceroute unavailable)"},
	}, "direct-fallback", nil
}

var (
	ipTokenRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	msTokenRe = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
)

func parseTracerouteOutput(raw string) []xrpc.ReturnRouteHop {
	lines := strings.Split(raw, "\n")
	hops := make([]xrpc.ReturnRouteHop, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "traceroute") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hopStr := strings.TrimSuffix(fields[0], ":")
		hopNum, err := strconv.Atoi(hopStr)
		if err != nil || hopNum <= 0 {
			continue
		}
		ip := ipTokenRe.FindString(line)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		var lat int64
		if m := msTokenRe.FindStringSubmatch(line); len(m) == 2 {
			if f, ferr := strconv.ParseFloat(m[1], 64); ferr == nil {
				lat = int64(f + 0.5)
			}
		}
		hops = append(hops, xrpc.ReturnRouteHop{
			Hop:       hopNum,
			IP:        ip,
			LatencyMS: lat,
		})
	}
	return hops
}

// TestReturnRoute 执行返程路由追踪与骨干线路分类。目标不可达或无特征跳时返回 RouteType="Unknown" 而非 RPC 错误。
func TestReturnRoute(ctx context.Context, p xrpc.NetworkReturnRouteTestParams, tracer Tracer) (*xrpc.NetworkReturnRouteTestResult, error) {
	carrier := strings.TrimSpace(p.Carrier)
	if carrier == "" {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "carrier 不能为空"}
	}
	upperCarrier := strings.ToUpper(carrier)
	switch upperCarrier {
	case "CT", "CU", "CM", "EDU":
		carrier = upperCarrier
	}

	target := strings.TrimSpace(p.TargetIP)
	defaultRegion := ""
	if target == "" {
		if def, ok := DefaultCarrierTargets[upperCarrier]; ok {
			target = def.IP
			defaultRegion = def.Region
		} else {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("自定义运营商 %q 必须提供 target_ip", carrier)}
		}
	} else {
		var err error
		target, err = ValidateHost(target)
		if err != nil {
			return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: "target_ip 非法：" + err.Error()}
		}
	}

	maxHops := p.MaxHops
	if maxHops == 0 {
		maxHops = xrpc.ReturnRouteDefaultMaxHops
	}
	if maxHops < 1 || maxHops > xrpc.ReturnRouteMaxHops {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("max_hops %d 必须在 1..%d 之间", maxHops, xrpc.ReturnRouteMaxHops)}
	}
	timeoutMS := p.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = xrpc.ReturnRouteDefaultTimeoutMS
	}
	if timeoutMS < xrpc.ReturnRouteMinTimeoutMS || timeoutMS > xrpc.ReturnRouteMaxTimeoutMS {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("timeout_ms %d 必须在 %d..%d 之间", timeoutMS, xrpc.ReturnRouteMinTimeoutMS, xrpc.ReturnRouteMaxTimeoutMS)}
	}
	if p.Port < 0 || p.Port > 65535 {
		return nil, &xrpc.Error{Code: xrpc.CodeBadParams, Message: fmt.Sprintf("port %d 必须在 1..65535 之间", p.Port)}
	}

	if tracer == nil {
		tracer = DefaultTracer()
	}

	now := time.Now().UTC()
	hops, method, terr := tracer.Trace(ctx, target, p.Port, maxHops, time.Duration(timeoutMS)*time.Millisecond)
	if terr != nil {
		return &xrpc.NetworkReturnRouteTestResult{
			Carrier:   carrier,
			TargetIP:  target,
			RouteType: "Unknown",
			Region:    defaultRegion,
			Reason:    terr.Error(),
			TestedAt:  now,
		}, nil
	}

	routeType, entryIP, entryASN, reason := ClassifyReturnRoute(carrier, hops)
	if reason == "" && method != "" {
		reason = fmt.Sprintf("via %s (%d hops)", method, len(hops))
	}
	return &xrpc.NetworkReturnRouteTestResult{
		Carrier:   carrier,
		TargetIP:  target,
		RouteType: routeType,
		Region:    defaultRegion,
		EntryIP:   entryIP,
		EntryASN:  entryASN,
		Reason:    reason,
		Hops:      hops,
		TestedAt:  now,
	}, nil
}

// ClassifyReturnRoute 根据跃点 IP 前缀与已知 ASN 特征判定国内主流返程线路类型。
func ClassifyReturnRoute(carrier string, hops []xrpc.ReturnRouteHop) (routeType, entryIP, entryASN, reason string) {
	var saw5943, saw20297 bool
	var ip5943, ip20297 string

	var saw9929, saw4837 bool
	var ip9929, ip4837 string

	var sawCMIN2, sawCMI bool
	var ipCMIN2, ipCMI string

	var sawCERNET bool
	var ipCERNET string

	for i := range hops {
		ip := strings.TrimSpace(hops[i].IP)
		asn := strings.ToUpper(strings.TrimSpace(hops[i].ASN))
		switch {
		case strings.HasPrefix(ip, "59.43.") || asn == "AS4809":
			if !saw5943 {
				saw5943, ip5943 = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS4809"
			}
		case strings.HasPrefix(ip, "202.97.") || asn == "AS4134":
			if !saw20297 {
				saw20297, ip20297 = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS4134"
			}
		case strings.HasPrefix(ip, "218.105.") || strings.HasPrefix(ip, "210.51.") || asn == "AS9929":
			if !saw9929 {
				saw9929, ip9929 = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS9929"
			}
		case strings.HasPrefix(ip, "219.158.") || asn == "AS4837":
			if !saw4837 {
				saw4837, ip4837 = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS4837"
			}
		case strings.HasPrefix(ip, "223.120.") || asn == "AS58807":
			if !sawCMIN2 {
				sawCMIN2, ipCMIN2 = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS58807"
			}
		case strings.HasPrefix(ip, "221.183.") || strings.HasPrefix(ip, "223.118.") || asn == "AS58453" || asn == "AS9808":
			if !sawCMI {
				sawCMI, ipCMI = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS58453"
			}
		case strings.HasPrefix(ip, "202.112.") || asn == "AS4538":
			if !sawCERNET {
				sawCERNET, ipCERNET = true, ip
			}
			if hops[i].ASN == "" {
				hops[i].ASN = "AS4538"
			}
		}
	}

	switch {
	case saw5943 && !saw20297:
		return "CN2 GIA", ip5943, "AS4809", "命中 59.43 (AS4809) 且未经过 202.97"
	case saw5943 && saw20297:
		return "CN2 GT", ip5943, "AS4809", "同时命中 59.43 (AS4809) 与 202.97 (AS4134)"
	case saw9929:
		return "AS9929", ip9929, "AS9929", "命中联通 A 网 AS9929 骨干"
	case sawCMIN2:
		return "CMIN2", ipCMIN2, "AS58807", "命中移动高端 CMIN2 (AS58807) 骨干"
	case sawCMI:
		return "CMI", ipCMI, "AS58453", "命中移动 CMI (AS58453) 骨干"
	case saw4837:
		return "AS4837", ip4837, "AS4837", "命中联通 169 骨干 AS4837"
	case saw20297:
		return "163", ip20297, "AS4134", "命中电信 163 骨干 AS4134"
	case sawCERNET:
		return "CERNET", ipCERNET, "AS4538", "命中教育网 CERNET (AS4538)"
	default:
		if len(hops) == 0 {
			return "Unknown", "", "", "未采集到有效路由跃点"
		}
		return "Unknown", hops[len(hops)-1].IP, hops[len(hops)-1].ASN, "未匹配到已知国内骨干网段特征"
	}
}

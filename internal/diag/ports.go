package diag

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"
)

// ListeningPort 描述本机处于监听/绑定状态的 TCP 或 UDP 端口。
type ListeningPort struct {
	Protocol string `json:"protocol"` // tcp | tcp6 | udp | udp6
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

func (e *Engine) checkPorts(ctx context.Context) xrpc.DiagItemResult {
	ports, source, err := e.collectListeningPorts(ctx)
	if err != nil {
		return xrpc.DiagItemResult{
			Name:   xrpc.DiagItemPorts,
			OK:     false,
			Status: xrpc.DiagStatusFailed,
			Error:  err.Error(),
		}
	}
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemPorts,
		OK:     true,
		Status: xrpc.DiagStatusOK,
		Data: map[string]any{
			"source": source,
			"count":  len(ports),
			"ports":  ports,
		},
	}
}

func (e *Engine) collectListeningPorts(ctx context.Context) ([]ListeningPort, string, error) {
	procFiles := []struct {
		path   string
		proto  string
		isTCP  bool
		isIPv6 bool
	}{
		{"/proc/net/tcp", "tcp", true, false},
		{"/proc/net/tcp6", "tcp6", true, true},
		{"/proc/net/udp", "udp", false, false},
		{"/proc/net/udp6", "udp6", false, true},
	}
	var all []ListeningPort
	readAny := false
	for _, pf := range procFiles {
		raw, err := e.opts.ReadFile(pf.path)
		if err != nil {
			continue
		}
		readAny = true
		parsed := ParseProcNet(raw, pf.proto, pf.isTCP, pf.isIPv6)
		all = append(all, parsed...)
	}
	if readAny {
		all = dedupSortPorts(all)
		return all, "procfs", nil
	}

	// 非 Linux 环境回退到 ss / netstat（只读）。
	if out, err := e.opts.RunCmd(ctx, "ss", "-tuln"); err == nil {
		return dedupSortPorts(parseSSOutput(out)), "ss", nil
	}
	if out, err := e.opts.RunCmd(ctx, "netstat", "-an"); err == nil {
		return dedupSortPorts(parseNetstatOutput(out)), "netstat", nil
	}
	return nil, "", fmt.Errorf("无法读取 /proc/net/* 且 ss/netstat 不可用")
}

// ParseProcNet 解析 Linux /proc/net/{tcp,tcp6,udp,udp6} 内容，提取 TCP LISTEN（状态 0A）与已绑定 UDP 端口。
func ParseProcNet(raw []byte, proto string, isTCP, isIPv6 bool) []ListeningPort {
	var out []ListeningPort
	sc := bufio.NewScanner(bytes.NewReader(raw))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		state := strings.ToUpper(fields[3])
		if isTCP {
			if state != "0A" { // TCP_LISTEN
				continue
			}
		} else {
			if state != "07" { // UDP_CLOSE (unbound/listening socket)
				continue
			}
		}
		addrHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port64, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || port64 == 0 {
			continue
		}
		ipStr := decodeProcHexIP(addrHex, isIPv6)
		if ipStr == "" {
			continue
		}
		out = append(out, ListeningPort{
			Protocol: proto,
			Address:  ipStr,
			Port:     int(port64),
		})
	}
	return out
}

func decodeProcHexIP(h string, isIPv6 bool) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	if !isIPv6 {
		if len(b) != 4 {
			return ""
		}
		// /proc/net/tcp IPv4 为小端 32 位整数。
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	}
	if len(b) != 16 {
		return ""
	}
	// /proc/net/tcp6 IPv6 按每 4 字节小端排列。
	ip := make(net.IP, 16)
	for i := 0; i < 16; i += 4 {
		ip[i] = b[i+3]
		ip[i+1] = b[i+2]
		ip[i+2] = b[i+1]
		ip[i+3] = b[i]
	}
	return ip.String()
}

func parseSSOutput(raw []byte) []ListeningPort {
	var out []ListeningPort
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		netid := strings.ToLower(fields[0])
		if netid != "tcp" && netid != "udp" {
			continue
		}
		local := fields[4]
		host, portStr, err := net.SplitHostPort(local)
		if err != nil {
			idx := strings.LastIndex(local, ":")
			if idx <= 0 {
				continue
			}
			host, portStr = local[:idx], local[idx+1:]
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		proto := netid
		if strings.Contains(host, ":") {
			proto += "6"
		}
		out = append(out, ListeningPort{Protocol: proto, Address: strings.Trim(host, "[]"), Port: port})
	}
	return out
}

func parseNetstatOutput(raw []byte) []ListeningPort {
	var out []ListeningPort
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		protoRaw := strings.ToLower(fields[0])
		isTCP := strings.HasPrefix(protoRaw, "tcp")
		isUDP := strings.HasPrefix(protoRaw, "udp")
		if !isTCP && !isUDP {
			continue
		}
		if isTCP && !strings.Contains(strings.ToUpper(line), "LISTEN") {
			continue
		}
		local := fields[3]
		sep := strings.LastIndexAny(local, ".:")
		if sep <= 0 || sep >= len(local)-1 {
			continue
		}
		port, err := strconv.Atoi(local[sep+1:])
		if err != nil || port <= 0 {
			continue
		}
		proto := "tcp"
		if isUDP {
			proto = "udp"
		}
		if strings.Contains(protoRaw, "6") {
			proto += "6"
		}
		out = append(out, ListeningPort{Protocol: proto, Address: local[:sep], Port: port})
	}
	return out
}

func dedupSortPorts(in []ListeningPort) []ListeningPort {
	seen := make(map[string]struct{}, len(in))
	out := make([]ListeningPort, 0, len(in))
	for _, p := range in {
		k := fmt.Sprintf("%s|%s|%d", p.Protocol, p.Address, p.Port)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Address < out[j].Address
	})
	return out
}

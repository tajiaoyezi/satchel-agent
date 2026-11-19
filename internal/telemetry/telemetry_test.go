package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

func TestSysCollector(t *testing.T) {
	statIdx := 0
	statSnapshots := []string{
		"cpu  1000 0 200 8800 0 0 0 0 0 0\nbtime 1700000000\n",
		"cpu  1200 0 300 9500 0 0 0 0 0 0\nbtime 1700000000\n",
	}
	files := map[string]string{
		"/proc/meminfo": `MemTotal:       16384000 kB
MemFree:         2000000 kB
MemAvailable:    8192000 kB
`,
		"/proc/cpuinfo": `processor	: 0
model name	: AMD EPYC 7763
physical id	: 0
core id		: 0

processor	: 1
model name	: AMD EPYC 7763
physical id	: 0
core id		: 0

processor	: 2
model name	: AMD EPYC 7763
physical id	: 0
core id		: 1

processor	: 3
model name	: AMD EPYC 7763
physical id	: 0
core id		: 1
`,
		"/proc/uptime":                     "12345.67 45678.90\n",
		"/proc/loadavg":                    "0.42 0.35 0.28 1/200 1234\n",
		"/etc/os-release":                  "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"/proc/sys/kernel/osrelease":       "6.1.0-20-amd64\n",
		"/proc/sys/net/ipv4/tcp_fastopen":  "3\n",
	}
	readFile := func(p string) ([]byte, error) {
		if p == "/proc/stat" {
			s := statSnapshots[statIdx]
			if statIdx < len(statSnapshots)-1 {
				statIdx++
			}
			return []byte(s), nil
		}
		v, ok := files[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(v), nil
	}

	fixedNow := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	c := NewSysCollector(SysReader{
		ReadFile:      readFile,
		Hostname:      func() (string, error) { return "hk-node-1", nil },
		StatFS:        func(string) (int64, int64, error) { return 100 << 30, 40 << 30, nil },
		Now:           func() time.Time { return fixedNow },
		NumCPU:        func() int { return 4 },
		Arch:          "amd64",
		InDocker:      func() bool { return true },
		AgentVersion:  "0.2.0",
		CPUProbeDelay: 0,
	})

	// 首次采样 CPU 建立基线，第二次采集拿到 delta = (300 busy / 1000 total) = 30%。
	if pct := c.SampleCPU(); pct != 0 {
		t.Fatalf("first SampleCPU = %v, want 0", pct)
	}
	info := c.Info()
	if info.Hostname != "hk-node-1" || info.OS != "Debian GNU/Linux 12 (bookworm)" || info.Kernel != "6.1.0-20-amd64" {
		t.Fatalf("basic sysinfo mismatch: %+v", info)
	}
	if info.Arch != "amd64" || info.CPUCores != 2 || info.CPUThreads != 4 || info.CPUModel != "AMD EPYC 7763" {
		t.Fatalf("cpu info mismatch: %+v", info)
	}
	if info.CPUPct != 30 {
		t.Fatalf("CPUPct = %v, want 30", info.CPUPct)
	}
	if info.UptimeSeconds != 12345 || info.LoadAvg != "0.42 0.35 0.28" || info.Load1 != 0.42 || info.Load5 != 0.35 || info.Load15 != 0.28 {
		t.Fatalf("uptime/load mismatch: %+v", info)
	}
	wantMemTotal := int64(16384000 * 1024)
	wantMemAvail := int64(8192000 * 1024)
	if info.MemTotalBytes != wantMemTotal || info.MemAvailableBytes != wantMemAvail || info.MemUsedBytes != wantMemTotal-wantMemAvail {
		t.Fatalf("mem mismatch: %+v", info)
	}
	if info.DiskTotalBytes != 100<<30 || info.DiskAvailableBytes != 40<<30 || info.DiskUsedBytes != 60<<30 {
		t.Fatalf("disk mismatch: %+v", info)
	}
	if !info.TCPFastOpenServer || !info.InDocker || info.AgentVersion != "0.2.0" {
		t.Fatalf("flags mismatch: %+v", info)
	}
	if !info.CollectedAt.Equal(fixedNow) {
		t.Fatalf("CollectedAt = %v, want %v", info.CollectedAt, fixedNow)
	}
	if boot := ReadBootTimeUnix(readFile); boot != 1700000000 {
		t.Fatalf("ReadBootTimeUnix = %d, want 1700000000", boot)
	}

	// tcp_fastopen = 1 仅开启客户端，服务端位（bit 1）未启用。
	files["/proc/sys/net/ipv4/tcp_fastopen"] = "1\n"
	if readTFOServer(readFile) {
		t.Fatal("tcp_fastopen=1 should report TCPFastOpenServer=false")
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse cidr %s: %v", s, err)
	}
	return &net.IPNet{IP: ip, Mask: ipnet.Mask}
}

func TestListNICsWith(t *testing.T) {
	ifaces := []NetIface{
		{
			Name:  "lo",
			Flags: net.FlagUp | net.FlagLoopback,
			Addrs: []net.Addr{mustCIDR(t, "127.0.0.1/8"), mustCIDR(t, "::1/128")},
		},
		{
			Name:  "eth1",
			Flags: 0, // down
			Addrs: []net.Addr{mustCIDR(t, "198.51.100.1/24")},
		},
		{
			Name:  "eth2",
			Flags: net.FlagUp,
			Addrs: []net.Addr{mustCIDR(t, "fe80::1/64"), mustCIDR(t, "0.0.0.0/0")}, // only filtered addrs
		},
		{
			Name:  "eth0",
			Flags: net.FlagUp | net.FlagBroadcast,
			Addrs: []net.Addr{
				mustCIDR(t, "fe80::1/64"),
				mustCIDR(t, "169.254.1.5/16"),
				mustCIDR(t, "fd00::5/64"),
				mustCIDR(t, "2001:db8::9/64"),
				mustCIDR(t, "100.64.1.2/10"),
				mustCIDR(t, "10.0.0.8/24"),
				mustCIDR(t, "203.0.113.10/24"),
			},
		},
	}

	nics, err := ListNICsWith(func() ([]NetIface, error) { return ifaces, nil })
	if err != nil {
		t.Fatalf("ListNICsWith: %v", err)
	}
	if len(nics) != 1 || nics[0].Name != "eth0" {
		t.Fatalf("nics = %+v, want only eth0", nics)
	}
	got := map[string]xrpc.NICAddr{}
	for _, a := range nics[0].Addrs {
		got[a.IP] = a
	}
	if len(got) != 5 {
		t.Fatalf("addrs len = %d (%+v), want 5", len(got), nics[0].Addrs)
	}
	check := func(ip, family, cidr, scope string) {
		t.Helper()
		a, ok := got[ip]
		if !ok {
			t.Fatalf("missing addr %s", ip)
		}
		if a.Family != family || a.CIDR != cidr || a.Scope != scope {
			t.Fatalf("addr %s = %+v, want family=%s cidr=%s scope=%s", ip, a, family, cidr, scope)
		}
	}
	check("203.0.113.10", "v4", "203.0.113.10/24", "global")
	check("100.64.1.2", "v4", "100.64.1.2/10", "private")
	check("10.0.0.8", "v4", "10.0.0.8/24", "private")
	check("fd00::5", "v6", "fd00::5/64", "ula")
	check("2001:db8::9", "v6", "2001:db8::9/64", "global")
}

func TestSpeedCollectorVirtualFilterAndRates(t *testing.T) {
	// 验证全部 15 类虚拟接口前缀都被过滤，物理网卡放行。
	virtuals := []string{
		"lo", "docker0", "veth1a2b", "br-99a", "virbr0", "vnet0",
		"flannel.1", "cni0", "calico123", "tunl0", "wg0",
		"tailscale0", "tun0", "tap0", "dummy0",
	}
	for _, v := range virtuals {
		if IsPhysicalInterface(v) {
			t.Fatalf("virtual interface %q should be filtered", v)
		}
	}
	for _, p := range []string{"eth0", "ens3", "enp1s0", "eno1"} {
		if !IsPhysicalInterface(p) {
			t.Fatalf("physical interface %q should be allowed", p)
		}
	}

	netDevs := []string{
		`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999 0 0 0 0 0 0 0 9999999 0 0 0 0 0 0 0
docker0: 888888 0 0 0 0 0 0 0 888888 0 0 0 0 0 0 0
veth01: 777777 0 0 0 0 0 0 0 777777 0 0 0 0 0 0 0
  wg0: 666666 0 0 0 0 0 0 0 666666 0 0 0 0 0 0 0
  eth0: 10000 10 0 0 0 0 0 0 20000 10 0 0 0 0 0 0
  ens3:  5000  5 0 0 0 0 0 0  3000  5 0 0 0 0 0 0
`,
		`Inter-|   Receive | Transmit
    lo: 99999999 0 0 0 0 0 0 0 99999999 0 0 0 0 0 0 0
  eth0: 16000 10 0 0 0 0 0 0 32000 10 0 0 0 0 0 0
  ens3:  5000  5 0 0 0 0 0 0  3000  5 0 0 0 0 0 0
`,
		// 第三次模拟计数器回退，速率应钳位到 0。
		`Inter-|   Receive | Transmit
  eth0: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
`,
	}
	idx := 0
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	readFile := func(p string) ([]byte, error) {
		switch p {
		case "/proc/net/dev":
			return []byte(netDevs[idx]), nil
		case "/proc/stat":
			return []byte("btime 1700000123\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}
	sc := NewSpeedCollector(readFile, func() time.Time { return now })

	// 1. 首次建基线报 0, 0，并带物理网卡累计和 btime。
	r1 := sc.Sample()
	if r1.UploadSpeed != 0 || r1.DownloadSpeed != 0 {
		t.Fatalf("first sample should be 0/0, got %+v", r1)
	}
	if r1.SystemRxBytes != 15000 || r1.SystemTxBytes != 23000 || r1.SystemBootTimeUnix != 1700000123 {
		t.Fatalf("first cumulative mismatch: %+v", r1)
	}

	// 200ms 内 LatestOrSample 复用缓存。
	now = now.Add(200 * time.Millisecond)
	idx = 1
	cached := sc.LatestOrSample()
	if cached.SystemRxBytes != 15000 {
		t.Fatalf("LatestOrSample within 500ms should return cached sample, got %+v", cached)
	}

	// 2. 3s 后采样：rx +6000 -> 2000 B/s，tx +12000 -> 4000 B/s。
	now = time.Date(2026, 11, 19, 10, 0, 3, 0, time.UTC)
	r2 := sc.Sample()
	if r2.DownloadSpeed != 2000 || r2.UploadSpeed != 4000 {
		t.Fatalf("second sample rates = (%d, %d), want (down=2000, up=4000)", r2.DownloadSpeed, r2.UploadSpeed)
	}
	if r2.SystemRxBytes != 21000 || r2.SystemTxBytes != 35000 {
		t.Fatalf("second cumulative mismatch: %+v", r2)
	}

	// 3. 计数器倒退钳位为 0。
	idx = 2
	now = now.Add(3 * time.Second)
	r3 := sc.Sample()
	if r3.DownloadSpeed != 0 || r3.UploadSpeed != 0 {
		t.Fatalf("counter drop should clamp to 0, got %+v", r3)
	}
}

func TestLogInspectorFilesListAndGuards(t *testing.T) {
	dir := t.TempDir()
	agentLog := filepath.Join(dir, "satchel-agent.log")
	agentRot := filepath.Join(dir, "satchel-agent-2026-11-18.log")
	coreLog := filepath.Join(dir, "core.log")
	otherLog := filepath.Join(dir, "unrelated.log")

	agentContent := strings.Join([]string{
		`time=2026-11-19T10:00:01Z level=DEBUG msg="debug line" tag=alpha`,
		`time=2026-11-19T10:00:02Z level=INFO msg="info line" tag=beta`,
		`time=2026-11-19T10:00:03Z level=WARN msg="warn secret123"`,
		`time=2026-11-19T10:00:04Z level=ERROR msg="error Secret123"`,
	}, "\n") + "\n"
	if err := os.WriteFile(agentLog, []byte(agentContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentRot, []byte("time=2026-11-18T09:00:00Z level=WARN msg=\"old rotated\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coreLog, []byte("time=2026-11-19T10:01:00Z level=INFO msg=\"core started\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherLog, []byte("should be invisible\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	insp := NewLogInspector(dir, "satchel-agent.log", "core.log")

	// 1. Files 白名单与排序：活跃文件在前，不泄露 unrelated.log。
	filesRes, err := insp.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(filesRes.Files) != 3 {
		t.Fatalf("files len = %d (%+v), want 3", len(filesRes.Files), filesRes.Files)
	}
	if !filesRes.Files[0].Active || !filesRes.Files[1].Active || filesRes.Files[2].Active {
		t.Fatalf("active files should sort first: %+v", filesRes.Files)
	}
	for _, f := range filesRes.Files {
		if f.Name == "unrelated.log" {
			t.Fatal("unrelated.log must not appear in allowlisted files")
		}
	}

	// 2. List 级别 + grep 区分大小写过滤 + 从新到旧排序。
	res, err := insp.List(context.Background(), xrpc.AgentLogsParams{
		Service: "agent",
		Level:   "warn",
		Grep:    "secret123",
	})
	if err != nil {
		t.Fatalf("List agent: %v", err)
	}
	if res.Total != 1 || len(res.Items) != 1 || res.Items[0].Level != "WARN" {
		t.Fatalf("unexpected agent list result: %+v", res)
	}

	// 3. 指定轮转文件与 core 日志读取。
	rotRes, err := insp.List(context.Background(), xrpc.AgentLogsParams{
		Service: "agent",
		File:    "satchel-agent-2026-11-18.log",
	})
	if err != nil || rotRes.Total != 1 || rotRes.Items[0].Msg != "old rotated" {
		t.Fatalf("rotated list = %+v, err=%v", rotRes, err)
	}
	coreRes, err := insp.List(context.Background(), xrpc.AgentLogsParams{Service: "core"})
	if err != nil || coreRes.Total != 1 || coreRes.Items[0].Msg != "core started" {
		t.Fatalf("core list = %+v, err=%v", coreRes, err)
	}

	// 4. 路径穿越、非白名单、不存在文件一律报 CodeNotFound。
	for _, badFile := range []string{"../../etc/shadow", "../satchel-agent.log", "unrelated.log", "satchel-agent-missing.log", `sub\file.log`} {
		_, err := insp.List(context.Background(), xrpc.AgentLogsParams{Service: "agent", File: badFile})
		var xe *xrpc.Error
		if !errors.As(err, &xe) || xe.Code != xrpc.CodeNotFound {
			t.Fatalf("bad file %q: err = %v, want xrpc.CodeNotFound", badFile, err)
		}
	}

	// 5. 非法 service / level 与 nginx 带 file 报 CodeBadParams。
	for _, p := range []xrpc.AgentLogsParams{
		{Service: "../systemd"},
		{Service: "agent", Level: "trace"},
		{Service: "nginx", File: "satchel-agent.log"},
	} {
		_, err := insp.List(context.Background(), p)
		var xe *xrpc.Error
		if !errors.As(err, &xe) || xe.Code != xrpc.CodeBadParams {
			t.Fatalf("bad params %+v: err = %v, want CodeBadParams", p, err)
		}
	}

	// 6. 512 KiB 响应体积上限截断保护。
	bigPath := filepath.Join(dir, "satchel-agent-big.log")
	var sb strings.Builder
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "time=2026-11-19T10:00:00Z level=INFO msg=\"%03d-%s\"\n", i, chunk)
	}
	if err := os.WriteFile(bigPath, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	bigRes, err := insp.List(context.Background(), xrpc.AgentLogsParams{
		Service: "agent",
		File:    "satchel-agent-big.log",
		Limit:   500,
	})
	if err != nil {
		t.Fatalf("big List: %v", err)
	}
	if !bigRes.Truncated {
		t.Fatalf("expected Truncated=true for >512KiB payload, items=%d", len(bigRes.Items))
	}
	enc, _ := json.Marshal(bigRes)
	if len(enc) > xrpc.AgentLogsMaxReplyBytes {
		t.Fatalf("encoded reply size %d exceeds 512KiB (%d)", len(enc), xrpc.AgentLogsMaxReplyBytes)
	}

	// 7. nginx：journalctl 正常路径 + 无 systemd 文件回落 + 两者均不可用明确提示。
	insp.RunJournalctl = func(_ context.Context, lines int) ([]byte, error) {
		if lines != xrpc.AgentLogsMaxScanLines {
			t.Errorf("journalctl lines = %d, want %d", lines, xrpc.AgentLogsMaxScanLines)
		}
		return []byte("line-1 alpha\nline-2 beta\n"), nil
	}
	ngRes, err := insp.List(context.Background(), xrpc.AgentLogsParams{Service: "nginx", Grep: "beta"})
	if err != nil || ngRes.Total != 1 || ngRes.Items[0].Raw != "line-2 beta" {
		t.Fatalf("nginx journalctl result = %+v, err=%v", ngRes, err)
	}

	fbPath := filepath.Join(dir, "nginx-error.log")
	if err := os.WriteFile(fbPath, []byte("2026/11/19 [error] fallback line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	insp.RunJournalctl = func(context.Context, int) ([]byte, error) { return nil, errors.New("no systemd") }
	insp.NginxFallbackPath = fbPath
	ngFb, err := insp.List(context.Background(), xrpc.AgentLogsParams{Service: "nginx"})
	if err != nil || ngFb.Total != 1 || !strings.Contains(ngFb.Items[0].Raw, "fallback line") {
		t.Fatalf("nginx fallback result = %+v, err=%v", ngFb, err)
	}

	insp.NginxFallbackPath = filepath.Join(dir, "missing-nginx.log")
	ngNone, err := insp.List(context.Background(), xrpc.AgentLogsParams{Service: "nginx"})
	if err != nil || ngNone.Total != 0 || ngNone.Message == "" {
		t.Fatalf("nginx unavailable should return non-fatal message: %+v, err=%v", ngNone, err)
	}
}

// Package telemetry 提供节点侧纯 Go 遥测采集与只读日志检查能力（node-telemetry）：
// 系统硬件指标、活跃非回环网卡枚举、物理网卡实时网速与开机累计、以及受白名单与载荷上限保护的日志读取。
package telemetry

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// SysReader 允许测试注入虚拟 /proc、/etc/os-release 与文件系统统计源。
type SysReader struct {
	ReadFile      func(path string) ([]byte, error)
	Hostname      func() (string, error)
	StatFS        func(path string) (total, avail int64, err error)
	Now           func() time.Time
	NumCPU        func() int
	Arch          string
	InDocker      func() bool
	AgentVersion  string
	CPUProbeDelay time.Duration // 首次无基线采样 CPU 时的短等待（生产默认 100ms，单测可置 0）
}

type cpuTimes struct {
	idle  uint64
	total uint64
}

// SysCollector 负责纯 Go 采集系统与硬件指标，并维护上次 CPU 时间片以计算使用率。
type SysCollector struct {
	r SysReader

	mu         sync.Mutex
	lastCPU    cpuTimes
	hasLastCPU bool
	lastCPUPct float64
}

// NewSysCollector 建系统信息采集器。
func NewSysCollector(r SysReader) *SysCollector {
	if r.ReadFile == nil {
		r.ReadFile = os.ReadFile
	}
	if r.Hostname == nil {
		r.Hostname = os.Hostname
	}
	if r.StatFS == nil {
		r.StatFS = defaultStatFS
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.NumCPU == nil {
		r.NumCPU = runtime.NumCPU
	}
	if r.Arch == "" {
		r.Arch = runtime.GOARCH
	}
	if r.InDocker == nil {
		r.InDocker = func() bool { return false }
	}
	return &SysCollector{r: r}
}

// SampleCPU 采样一次 /proc/stat CPU 时间片并更新最近使用率（可由后台速率循环周期调用）。
func (c *SysCollector) SampleCPU() float64 {
	cur, ok := readCPUTimes(c.r.ReadFile)
	if !ok {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasLastCPU {
		c.lastCPU = cur
		c.hasLastCPU = true
		return 0
	}
	pct := computeCPUPct(c.lastCPU, cur)
	c.lastCPU = cur
	c.lastCPUPct = pct
	return pct
}

// Info 采集一份完整的只读系统信息快照。
func (c *SysCollector) Info() xrpc.SystemInfo {
	threads := c.r.NumCPU()
	if threads < 1 {
		threads = 1
	}
	info := xrpc.SystemInfo{
		OS:                runtime.GOOS,
		Arch:              c.r.Arch,
		CPUCores:          threads,
		CPUThreads:        threads,
		TCPFastOpenServer: readTFOServer(c.r.ReadFile),
		AgentVersion:      c.r.AgentVersion,
		InDocker:          c.r.InDocker(),
		CollectedAt:       c.r.Now().UTC().Truncate(time.Millisecond),
	}
	if host, err := c.r.Hostname(); err == nil {
		info.Hostname = host
	}
	if model, cores := readCPUInfo(c.r.ReadFile); model != "" || cores > 0 {
		info.CPUModel = model
		if cores > 0 {
			info.CPUCores = cores
		}
	}
	if osName := readOSRelease(c.r.ReadFile); osName != "" {
		info.OS = osName
	}
	if kernel := readKernelRelease(c.r.ReadFile); kernel != "" {
		info.Kernel = kernel
	}
	if up, ok := readUptime(c.r.ReadFile); ok {
		info.UptimeSeconds = up
	}
	if la, l1, l5, l15, ok := readLoadAvg(c.r.ReadFile); ok {
		info.LoadAvg = la
		info.Load1, info.Load5, info.Load15 = l1, l5, l15
	}
	if memTotal, memUsed, memAvail, ok := readMemInfo(c.r.ReadFile); ok {
		info.MemTotalBytes = memTotal
		info.MemUsedBytes = memUsed
		info.MemAvailableBytes = memAvail
	}
	if dTotal, dAvail, err := c.r.StatFS("/"); err == nil && dTotal > 0 {
		info.DiskTotalBytes = dTotal
		info.DiskAvailableBytes = dAvail
		if dTotal >= dAvail {
			info.DiskUsedBytes = dTotal - dAvail
		}
	}

	info.CPUPct = c.measureCPUPct()
	return info
}

func (c *SysCollector) measureCPUPct() float64 {
	c.mu.Lock()
	hasLast := c.hasLastCPU
	last := c.lastCPU
	c.mu.Unlock()

	cur, ok := readCPUTimes(c.r.ReadFile)
	if !ok {
		return 0
	}
	if !hasLast {
		c.mu.Lock()
		c.lastCPU = cur
		c.hasLastCPU = true
		c.mu.Unlock()
		if c.r.CPUProbeDelay <= 0 {
			return 0
		}
		time.Sleep(c.r.CPUProbeDelay)
		cur2, ok2 := readCPUTimes(c.r.ReadFile)
		if !ok2 {
			return 0
		}
		pct := computeCPUPct(cur, cur2)
		c.mu.Lock()
		c.lastCPU = cur2
		c.lastCPUPct = pct
		c.mu.Unlock()
		return pct
	}
	pct := computeCPUPct(last, cur)
	c.mu.Lock()
	c.lastCPU = cur
	if cur.total > last.total {
		c.lastCPUPct = pct
	} else {
		pct = c.lastCPUPct
	}
	c.mu.Unlock()
	return pct
}

func computeCPUPct(prev, cur cpuTimes) float64 {
	if cur.total <= prev.total {
		return 0
	}
	totalDelta := float64(cur.total - prev.total)
	var idleDelta float64
	if cur.idle > prev.idle {
		idleDelta = float64(cur.idle - prev.idle)
	}
	busy := totalDelta - idleDelta
	if busy < 0 {
		busy = 0
	}
	pct := (busy / totalDelta) * 100
	if pct > 100 {
		pct = 100
	}
	return math.Round(pct*100) / 100
}

func readCPUTimes(readFile func(string) ([]byte, error)) (cpuTimes, bool) {
	raw, err := readFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return cpuTimes{}, false
		}
		var vals []uint64
		var total uint64
		for _, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return cpuTimes{}, false
			}
			vals = append(vals, v)
			total += v
		}
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4] // iowait
		}
		return cpuTimes{idle: idle, total: total}, true
	}
	return cpuTimes{}, false
}

// ReadBootTimeUnix 从 /proc/stat 读取系统开机 Unix 时间戳（btime）。
func ReadBootTimeUnix(readFile func(string) ([]byte, error)) int64 {
	raw, err := readFile("/proc/stat")
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

func readCPUInfo(readFile func(string) ([]byte, error)) (model string, cores int) {
	raw, err := readFile("/proc/cpuinfo")
	if err != nil {
		return "", 0
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	physCores := map[string]struct{}{}
	physID, coreID := "0", ""
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if coreID != "" {
				physCores[physID+":"+coreID] = struct{}{}
				physID, coreID = "0", ""
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if model == "" && (k == "model name" || k == "Hardware") {
			model = v
		}
		if k == "physical id" {
			physID = v
		}
		if k == "core id" {
			coreID = v
		}
	}
	if coreID != "" {
		physCores[physID+":"+coreID] = struct{}{}
	}
	return model, len(physCores)
}

func readOSRelease(readFile func(string) ([]byte, error)) string {
	raw, err := readFile("/etc/os-release")
	if err != nil {
		return ""
	}
	var name string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
	}
	return name
}

func readKernelRelease(readFile func(string) ([]byte, error)) string {
	if raw, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	}
	if raw, err := readFile("/proc/version"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return ""
}

func readUptime(readFile func(string) ([]byte, error)) (int64, bool) {
	raw, err := readFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return int64(v), true
}

func readLoadAvg(readFile func(string) ([]byte, error)) (rawStr string, l1, l5, l15 float64, ok bool) {
	raw, err := readFile("/proc/loadavg")
	if err != nil {
		return "", 0, 0, 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return "", 0, 0, 0, false
	}
	f1, e1 := strconv.ParseFloat(fields[0], 64)
	f5, e5 := strconv.ParseFloat(fields[1], 64)
	f15, e15 := strconv.ParseFloat(fields[2], 64)
	if e1 != nil || e5 != nil || e15 != nil {
		return "", 0, 0, 0, false
	}
	return fields[0] + " " + fields[1] + " " + fields[2], f1, f5, f15, true
}

func readMemInfo(readFile func(string) ([]byte, error)) (total, used, avail int64, ok bool) {
	raw, err := readFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, false
	}
	vals := map[string]int64{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// /proc/meminfo 单位通常为 kB。
		if len(fields) >= 2 && strings.EqualFold(fields[1], "kB") {
			n *= 1024
		}
		vals[k] = n
	}
	total, hasTotal := vals["MemTotal"]
	if !hasTotal || total <= 0 {
		return 0, 0, 0, false
	}
	if a, hasAvail := vals["MemAvailable"]; hasAvail {
		avail = a
	} else {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if avail > total {
		avail = total
	}
	if avail < 0 {
		avail = 0
	}
	used = total - avail
	return total, used, avail, true
}

func readTFOServer(readFile func(string) ([]byte, error)) bool {
	raw, err := readFile("/proc/sys/net/ipv4/tcp_fastopen")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	return err == nil && n&2 != 0
}

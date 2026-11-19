package telemetry

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// virtualInterfacePrefixes 是实时网速与系统网卡累计过滤掉的 15 类虚拟接口前缀（与 mmwx 一致）。
var virtualInterfacePrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "vnet",
	"flannel", "cni", "calico", "tunl", "wg",
	"tailscale", "tun", "tap", "dummy",
}

// IsPhysicalInterface 报告接口名是否属于应计入节点流量与网速的物理接口。
func IsPhysicalInterface(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// ReadPhysicalNetDev 从 /proc/net/dev 读取并汇总所有物理网卡的累计 RX/TX 字节数。
func ReadPhysicalNetDev(readFile func(string) ([]byte, error)) (rxBytes, txBytes int64, ok bool) {
	if readFile == nil {
		readFile = os.ReadFile
	}
	raw, err := readFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if !IsPhysicalInterface(iface) {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		rx, err1 := strconv.ParseInt(fields[0], 10, 64)
		tx, err2 := strconv.ParseInt(fields[8], 10, 64)
		if err1 == nil && err2 == nil && rx >= 0 && tx >= 0 {
			rxBytes += rx
			txBytes += tx
			ok = true
		}
	}
	return rxBytes, txBytes, ok
}

// SpeedCollector 维护上次物理网卡字节基线并计算实时上下行速率（B/s）。
type SpeedCollector struct {
	readFile func(string) ([]byte, error)
	now      func() time.Time

	mu        sync.Mutex
	primed    bool
	lastRx    int64
	lastTx    int64
	lastAt    time.Time
	lastRep   xrpc.SpeedReport
	hasReport bool
}

// NewSpeedCollector 建物理网卡实时网速采样器。
func NewSpeedCollector(readFile func(string) ([]byte, error), now func() time.Time) *SpeedCollector {
	if readFile == nil {
		readFile = os.ReadFile
	}
	if now == nil {
		now = time.Now
	}
	return &SpeedCollector{readFile: readFile, now: now}
}

// Sample 执行一次物理网卡采样并返回 SpeedReport（首次建基线速率报 0, 0，计数器回退钳位到 0）。
func (c *SpeedCollector) Sample() xrpc.SpeedReport {
	rx, tx, ok := ReadPhysicalNetDev(c.readFile)
	boot := ReadBootTimeUnix(c.readFile)
	at := c.now().UTC().Truncate(time.Millisecond)

	c.mu.Lock()
	defer c.mu.Unlock()

	var up, down int64
	if ok && c.primed {
		elapsed := at.Sub(c.lastAt).Seconds()
		if elapsed > 0 {
			if tx > c.lastTx {
				up = int64(float64(tx-c.lastTx) / elapsed)
			}
			if rx > c.lastRx {
				down = int64(float64(rx-c.lastRx) / elapsed)
			}
		}
	}
	if ok {
		c.primed = true
		c.lastRx = rx
		c.lastTx = tx
		c.lastAt = at
	}
	rep := xrpc.SpeedReport{
		UploadSpeed:        up,
		DownloadSpeed:      down,
		SystemRxBytes:      rx,
		SystemTxBytes:      tx,
		SystemBootTimeUnix: boot,
		At:                 at,
	}
	c.lastRep = rep
	c.hasReport = true
	return rep
}

// LatestOrSample 若 500ms 内刚采过样直接返回缓存，否则重新采样一次（供 pull_port speed.get 使用）。
func (c *SpeedCollector) LatestOrSample() xrpc.SpeedReport {
	c.mu.Lock()
	if c.hasReport && c.now().UTC().Sub(c.lastRep.At) < 500*time.Millisecond {
		rep := c.lastRep
		c.mu.Unlock()
		return rep
	}
	c.mu.Unlock()
	return c.Sample()
}

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	kt "github.com/satchel/satchel-agent/internal/kernel/kerneltest"
	"github.com/satchel/satchel-agent/internal/limits"
	"github.com/satchel/satchel-agent/internal/tracker"
)

// agent-kernel「run 按本地配置起内核」：没有 kernel.json 不起内核，坏了也不起、只记日志，startKernel 都照常返回。
func TestStartKernelWithoutUsableConfig(t *testing.T) {
	for name, content := range map[string]string{"没有内核配置": "", "内核配置坏了": "{"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if content != "" {
				os.WriteFile(filepath.Join(dir, kernelConfig), []byte(content), 0o600)
			}
			var logs bytes.Buffer
			deps, k := startKernel(context.Background(), dir, slog.New(slog.NewTextHandler(&logs, nil)))
			if k.Running() || deps.Inbounds != nil || deps.Limits == nil {
				t.Fatalf("不应当起内核、没有入站名、限速存储照常可用：%v %v", k.Running(), deps.Inbounds)
			}
			if content != "" && !strings.Contains(logs.String(), "解析不了") {
				t.Fatalf("日志里应当有内核配置解析不了：%s", logs.String())
			}
		})
	}
}

// 内核配置里有注释（sing-box 的配置允许）：startKernel 解析入站名与起内核用同一套规则，照常起来。
func TestStartKernelAcceptsComments(t *testing.T) {
	s := kt.StartServer(t)
	config := s.Config()
	if err := s.Kernel.Stop(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, kernelConfig), append([]byte("// 测试用的内核配置\n"), config...), 0o600)
	deps, k := startKernel(context.Background(), dir, slog.New(slog.DiscardHandler))
	defer k.Stop()
	if !k.Running() || !slices.Equal(deps.Inbounds, []string{kt.InVLESS, kt.InHY2}) {
		t.Fatalf("带注释的配置应当照常起内核：%v %v", k.Running(), deps.Inbounds)
	}
}

// agent-kernel「重启后先有限速再有流量」：limiter-state.json 里 A 在 VLESS 上有主控临时 5 Mbps，startKernel 之后 A 立刻用
// 4 条并发下载打满，从第一个窗口起吞吐就落在 5 Mbps 的 ±20%（快速版窗口 6 秒）。
func TestStartKernelReplaysLimitsFirst(t *testing.T) {
	s := kt.StartServer(t)
	config := s.Config()
	if err := s.Kernel.Stop(); err != nil { // 让出端口，由 startKernel 起的内核接手同样的入站
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, kernelConfig), config, 0o600)
	prev, err := limits.Open(filepath.Join(dir, limits.FileName), tracker.New(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prev.Set(kt.InVLESS, kt.UserA, xrpc.SourceMaster, 5_000_000, nil); err != nil {
		t.Fatal(err)
	}
	deps, k := startKernel(context.Background(), dir, slog.New(slog.DiscardHandler))
	defer k.Stop()
	if !k.Running() || !slices.Equal(deps.Inbounds, []string{kt.InVLESS, kt.InHY2}) {
		t.Fatalf("应当照 kernel.json 起内核：%v %v", k.Running(), deps.Inbounds)
	}
	c := kt.StartClient(t, s, kt.UserA, kt.InVLESS)
	var flows []*kt.Flow
	for range 4 {
		flows = append(flows, kt.Download(t, c, 1, 0, 0))
	}
	defer func() {
		for _, f := range flows {
			f.Stop()
		}
	}()
	start := time.Now()
	time.Sleep(6 * time.Second)
	var total int64
	for _, f := range flows {
		total += f.Meter.Bytes()
	}
	got := float64(total) * 8 / time.Since(start).Seconds() / 1e6
	if got < 4 || got > 6 {
		t.Fatalf("从第一个窗口起 A 的合计吞吐应当在 5 Mbps 的 ±20%%：%.2f Mbps", got)
	}
}

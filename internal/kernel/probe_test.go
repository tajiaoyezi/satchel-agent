package kernel_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/tracker"
	kt "github.com/satchel/satchel-agent/pkg/kerneltest"
)

// agent-kernel「无侵入实时出站探活（outbound.probe）」：
// - 内核未运行时返回 ErrNotRunning；
// - 运行中内核的 direct 出站经真实 DialContext 命中本地测试端点返回 200 与非负耗时；
// - 指向不可达端口的 bad-socks 返回拨号错误；
// - 不存在的 tag 返回 ErrOutboundNotFound；
// - 跨协议重定向被拒绝、响应体大流量截断不 OOM；
// - 整个探活过程不中断正在运行的客户端代理连接。
func TestProbeOutbound(t *testing.T) {
	// 1. 未运行内核返回 ErrNotRunning。
	idle := kernel.New(tracker.New())
	if _, _, err := idle.ProbeOutbound(context.Background(), "direct", "http://127.0.0.1:80"); !errors.Is(err, kernel.ErrNotRunning) {
		t.Fatalf("未运行内核应返回 ErrNotRunning，得到：%v", err)
	}

	// 2. 启动带测试端点的本地 HTTP 服务（200、大响应体、跨协议跳转、503）。
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("pong"))
		case "/large":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("x", 64*1024)))
		case "/cross-scheme":
			http.Redirect(w, r, "https://127.0.0.1:1/never", http.StatusFound)
		case "/err503":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer targetSrv.Close()

	// 找一个确定关闭的本地端口给 bad-socks，保证立即可复现连接拒绝。
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()

	cfg := fmt.Sprintf(`{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "bad-socks", "server": "127.0.0.1", "server_port": %d}
  ]
}`, deadPort)

	k := kernel.New(tracker.New())
	if err := k.Start(context.Background(), []byte(cfg)); err != nil {
		t.Fatalf("启动测试内核失败：%v", err)
	}
	t.Cleanup(func() { _ = k.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 2a. direct 探活成功。
	code, lat, err := k.ProbeOutbound(ctx, "direct", targetSrv.URL+"/ok")
	if err != nil || code != http.StatusOK || lat < 0 {
		t.Fatalf("direct 探活应当成功：code=%d lat=%d err=%v", code, lat, err)
	}

	// 2b. 大响应体截断成功不报错。
	code, _, err = k.ProbeOutbound(ctx, "direct", targetSrv.URL+"/large")
	if err != nil || code != http.StatusOK {
		t.Fatalf("大响应体探活应当返回 200：code=%d err=%v", code, err)
	}

	// 2c. 非 2xx/3xx 返回真实状态码（由 control 判定 OK=false）。
	code, _, err = k.ProbeOutbound(ctx, "direct", targetSrv.URL+"/err503")
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("503 端点应当返回 503：code=%d err=%v", code, err)
	}

	// 2d. 跨协议重定向被拒绝。
	if _, _, err := k.ProbeOutbound(ctx, "direct", targetSrv.URL+"/cross-scheme"); err == nil || !strings.Contains(err.Error(), "跨协议") {
		t.Fatalf("跨协议重定向应当被拒绝，得到：%v", err)
	}

	// 2e. 非 http(s) URL 被拒绝。
	if _, _, err := k.ProbeOutbound(ctx, "direct", "file:///etc/passwd"); !errors.Is(err, kernel.ErrInvalidProbeURL) {
		t.Fatalf("非 http(s) 地址应返回 ErrInvalidProbeURL，得到：%v", err)
	}

	// 2f. 不可达 bad-socks 返回拨号错误。
	if _, _, err := k.ProbeOutbound(ctx, "bad-socks", targetSrv.URL+"/ok"); err == nil {
		t.Fatal("不可达 bad-socks 应当返回拨号错误")
	}

	// 2g. 不存在的出站返回 ErrOutboundNotFound。
	if _, _, err := k.ProbeOutbound(ctx, "no-such-outbound", targetSrv.URL+"/ok"); !errors.Is(err, kernel.ErrOutboundNotFound) {
		t.Fatalf("不存在的出站应返回 ErrOutboundNotFound，得到：%v", err)
	}

	// 3. 验证正在跑业务的内核在执行 ProbeOutbound 后不中断现有代理连接且不增加内核代数。
	srv := kt.StartServer(t)
	cli := kt.StartClient(t, srv.Target(), kt.UserA, kt.InVLESS)
	kt.Echo(t, cli, 1)
	genBefore := srv.Tracker().Generation()

	code, _, err = srv.Kernel.ProbeOutbound(ctx, kt.Out1, targetSrv.URL+"/ok")
	if err != nil || code != http.StatusOK {
		t.Fatalf("运行业务内核探活 %s 失败：code=%d err=%v", kt.Out1, code, err)
	}
	if srv.Tracker().Generation() != genBefore {
		t.Fatalf("探活不该重启内核：before=%d after=%d", genBefore, srv.Tracker().Generation())
	}
	kt.Echo(t, cli, 2)
}

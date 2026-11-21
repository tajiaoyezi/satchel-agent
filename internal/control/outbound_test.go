package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/tracker"
)

func TestOutboundProbeMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusNoContent)
		case "/fail":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()

	tr := tracker.New()
	k := kernel.New(tr)
	t.Cleanup(func() { _ = k.Stop() })

	methods := Methods(Deps{
		Tracker: tr,
		Kernel:  k,
	})
	call := func(p xrpc.OutboundProbeParams) xrpc.Reply {
		raw, _ := json.Marshal(p)
		return methods.Serve(context.Background(), xrpc.Call{
			Method: xrpc.MethodOutboundProbe,
			Params: raw,
		})
	}

	// 1. 参数校验与未运行拒绝。
	if r := call(xrpc.OutboundProbeParams{}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("空 tag 应当返回 bad_params：%+v", r.Error)
	}
	if r := call(xrpc.OutboundProbeParams{Tag: "direct", URL: "ftp://example.com"}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("非法协议应当返回 bad_params：%+v", r.Error)
	}
	if r := call(xrpc.OutboundProbeParams{Tag: "direct", URL: srv.URL, TimeoutMS: 60000}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("超限 timeout_ms 应当返回 bad_params：%+v", r.Error)
	}
	if r := call(xrpc.OutboundProbeParams{Tag: "direct", URL: srv.URL}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("未启动内核应当返回 bad_params：%+v", r.Error)
	}

	// 2. 启动内核：direct 与不可达 bad-socks。
	cfg := fmt.Sprintf(`{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "bad-socks", "server": "127.0.0.1", "server_port": %d}
  ]
}`, deadPort)
	if err := k.Start(context.Background(), []byte(cfg)); err != nil {
		t.Fatal(err)
	}

	// 2a. 成功 204 -> OK=true。
	r := call(xrpc.OutboundProbeParams{Tag: "direct", URL: srv.URL + "/ok", TimeoutMS: 5000})
	if r.Error != nil {
		t.Fatalf("direct 探活不该报 RPC 错：%+v", r.Error)
	}
	var res xrpc.OutboundProbeResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.StatusCode != http.StatusNoContent || res.LatencyMS < 0 || res.ProbedAt.IsZero() {
		t.Fatalf("direct 204 结果不对：%+v", res)
	}

	// 2b. 502 -> OK=false + Error。
	r = call(xrpc.OutboundProbeParams{Tag: "direct", URL: srv.URL + "/fail", TimeoutMS: 5000})
	if r.Error != nil {
		t.Fatalf("502 不该报 RPC 错：%+v", r.Error)
	}
	res = xrpc.OutboundProbeResult{}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.StatusCode != http.StatusBadGateway || res.Error == "" {
		t.Fatalf("502 应标记 OK=false：%+v", res)
	}

	// 2c. bad-socks -> OK=false + Error。
	r = call(xrpc.OutboundProbeParams{Tag: "bad-socks", URL: srv.URL + "/ok", TimeoutMS: 3000})
	if r.Error != nil {
		t.Fatalf("bad-socks 不该报 RPC 错：%+v", r.Error)
	}
	res = xrpc.OutboundProbeResult{}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error == "" {
		t.Fatalf("bad-socks 应标记 OK=false 且带错误原因：%+v", res)
	}

	// 2d. 不存在的 tag -> bad_params。
	if r := call(xrpc.OutboundProbeParams{Tag: "missing", URL: srv.URL + "/ok"}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("不存在的出站应当返回 bad_params：%+v", r.Error)
	}
}

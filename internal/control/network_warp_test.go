package control

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/warpctl"
)

type stubTracer struct {
	hops []xrpc.ReturnRouteHop
}

func (s stubTracer) Trace(_ context.Context, _ string, _, _ int, _ time.Duration) ([]xrpc.ReturnRouteHop, string, error) {
	return s.hops, "stub", nil
}

func TestControlNetworkAndWarpMethods(t *testing.T) {
	dir := t.TempDir()
	methods := Methods(Deps{
		ConfigDir: dir,
		Warp:      warpctl.New(dir),
		Tracer: stubTracer{hops: []xrpc.ReturnRouteHop{
			{Hop: 1, IP: "10.0.0.1", LatencyMS: 2},
			{Hop: 2, IP: "59.43.130.1", LatencyMS: 12},
		}},
	})
	ctx := context.Background()

	// 1. 全部 9 个新 RPC 均已注册。
	for _, name := range []string{
		xrpc.MethodNetworkPortScan,
		xrpc.MethodNetworkValidateSite,
		xrpc.MethodNetworkDomainLatency,
		xrpc.MethodNetworkReturnRouteTest,
		xrpc.MethodWarpStatus,
		xrpc.MethodWarpInstall,
		xrpc.MethodWarpAuthorize,
		xrpc.MethodWarpRemove,
		xrpc.MethodWarpCredentials,
	} {
		if _, ok := methods[name]; !ok {
			t.Fatalf("缺少 RPC 方法 %s", name)
		}
	}

	// 2. network.port_scan 实测开放端口。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port
	pRaw, _ := json.Marshal(xrpc.NetworkPortScanParams{Host: "127.0.0.1", Ports: []int{openPort}, TimeoutMS: 500})
	rep := methods.Serve(ctx, xrpc.Call{ID: "1", Method: xrpc.MethodNetworkPortScan, Params: pRaw})
	if rep.Error != nil {
		t.Fatalf("network.port_scan 失败：%+v", rep.Error)
	}
	var scanRes xrpc.NetworkPortScanResult
	if err := json.Unmarshal(rep.Result, &scanRes); err != nil || len(scanRes.OpenPorts) != 1 || scanRes.OpenPorts[0] != openPort {
		t.Fatalf("port_scan 结果异常：%s err=%v", string(rep.Result), err)
	}

	// 3. network.domain_latency 实测与超限拦截。
	latRaw, _ := json.Marshal(xrpc.NetworkDomainLatencyParams{Domains: []string{"127.0.0.1"}, Port: openPort, Mode: "tcp", TimeoutMS: 1000, Concurrency: 1})
	rep = methods.Serve(ctx, xrpc.Call{ID: "2", Method: xrpc.MethodNetworkDomainLatency, Params: latRaw})
	if rep.Error != nil {
		t.Fatalf("network.domain_latency 失败：%+v", rep.Error)
	}
	badConc, _ := json.Marshal(xrpc.NetworkDomainLatencyParams{Domains: []string{"127.0.0.1"}, Concurrency: 17})
	rep = methods.Serve(ctx, xrpc.Call{ID: "3", Method: xrpc.MethodNetworkDomainLatency, Params: badConc})
	if rep.Error == nil || rep.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("超 16 并发应报 bad_params：%+v", rep.Error)
	}

	// 4. network.return_route_test 分类验证。
	rrRaw, _ := json.Marshal(xrpc.NetworkReturnRouteTestParams{Carrier: "ct"})
	rep = methods.Serve(ctx, xrpc.Call{ID: "4", Method: xrpc.MethodNetworkReturnRouteTest, Params: rrRaw})
	if rep.Error != nil {
		t.Fatalf("network.return_route_test 失败：%+v", rep.Error)
	}
	var rrRes xrpc.NetworkReturnRouteTestResult
	if err := json.Unmarshal(rep.Result, &rrRes); err != nil || rrRes.RouteType != "CN2 GIA" || rrRes.EntryASN != "AS4809" {
		t.Fatalf("return_route_test 结果异常：%s err=%v", string(rep.Result), err)
	}

	// 5. warp.* 闭环（未安装 -> 离线导入 -> status -> credentials -> remove）。
	rep = methods.Serve(ctx, xrpc.Call{ID: "5", Method: xrpc.MethodWarpCredentials})
	if rep.Error == nil || rep.Error.Code != xrpc.CodeConflict {
		t.Fatalf("未安装时 warp.credentials 应报 conflict：%+v", rep.Error)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authRaw, _ := json.Marshal(xrpc.WarpAuthorizeParams{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		AddressV4:  "172.16.0.2/32",
		Reserved:   []int{1, 2, 3},
	})
	rep = methods.Serve(ctx, xrpc.Call{ID: "6", Method: xrpc.MethodWarpAuthorize, Params: authRaw})
	if rep.Error != nil {
		t.Fatalf("warp.authorize 失败：%+v", rep.Error)
	}
	rep = methods.Serve(ctx, xrpc.Call{ID: "7", Method: xrpc.MethodWarpStatus})
	if rep.Error != nil {
		t.Fatalf("warp.status 失败：%+v", rep.Error)
	}
	rep = methods.Serve(ctx, xrpc.Call{ID: "8", Method: xrpc.MethodWarpCredentials})
	if rep.Error != nil {
		t.Fatalf("warp.credentials 失败：%+v", rep.Error)
	}
	var creds xrpc.WarpCredentialsResult
	if err := json.Unmarshal(rep.Result, &creds); err != nil {
		t.Fatal(err)
	}
	// 用真实内嵌 sing-box@v1.14.4 Validate 校验主控构造的 WireGuard endpoint + 防送中规则配置。
	wgConfig, _ := json.Marshal(map[string]any{
		"log": map[string]any{"level": "warn"},
		"outbounds": []map[string]any{
			{"type": "direct", "tag": "direct"},
		},
		"endpoints": []map[string]any{
			{
				"type":        "wireguard",
				"tag":         "warp",
				"mtu":         creds.MTU,
				"address":     []string{creds.AddressV4},
				"private_key": creds.PrivateKey,
				"peers": []map[string]any{{
					"address":     "engage.cloudflareclient.com",
					"port":        2408,
					"public_key":  creds.PeerPublicKey,
					"allowed_ips": []string{"0.0.0.0/0", "::/0"},
					"reserved":    creds.Reserved,
				}},
			},
		},
		"route": map[string]any{
			"rules": []map[string]any{
				{"action": "sniff"},
				{"rule_set": []string{"geosite-google"}, "outbound": "warp"},
			},
			"rule_set": []map[string]any{
				{
					"tag":             "geosite-google",
					"type":            "remote",
					"format":          "binary",
					"url":             "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs",
					"download_detour": "direct",
				},
			},
		},
	})
	if _, err := kernel.Validate(wgConfig); err != nil {
		t.Fatalf("WARP WireGuard endpoint 真实 sing-box Validate 失败：%v\n%s", err, string(wgConfig))
	}
	rep = methods.Serve(ctx, xrpc.Call{ID: "9", Method: xrpc.MethodWarpRemove})
	if rep.Error != nil {
		t.Fatalf("warp.remove 失败：%+v", rep.Error)
	}
}

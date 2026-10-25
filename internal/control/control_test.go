package control_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/control"
	kt "github.com/satchel/satchel-agent/internal/kernel/kerneltest"
)

// serve 按方法名调一次，返回结果；出错让测试失败。
func serve(t *testing.T, m xrpc.Methods, method string, params any) json.RawMessage {
	t.Helper()
	raw, _ := json.Marshal(params)
	r := m.Serve(context.Background(), xrpc.Call{ID: "1", Method: method, Params: raw})
	if r.Error != nil {
		t.Fatalf("%s 出错：%v", method, r.Error)
	}
	return r.Result
}

// 真内核：A 在 VLESS 上开 3 条 TCP 与 2 条 UDP、在 Hysteria2 上开 1 条 TCP；列出的 VLESS 连接与 tracker 逐条对得上，
// 给入站踢线时只断 VLESS 上的，快照里报内核在跑、带版本与启动时间。
func TestConnectionsKickAndSnapshot(t *testing.T) {
	s := kt.StartServer(t)
	tr := s.Tracker()
	m := control.Methods(control.Deps{Tracker: tr, Kernel: s.Kernel, Inbounds: []string{kt.InVLESS, kt.InHY2}})
	vless := kt.StartClient(t, s, kt.UserA, kt.InVLESS)
	hy2 := kt.StartClient(t, s, kt.UserA, kt.InHY2)
	for range 3 {
		kt.Echo(t, vless, 1)
	}
	for range 2 {
		kt.EchoUDP(t, vless, 1)
	}
	kt.Echo(t, hy2, 1)
	want := kt.WaitConns(t, tr, kt.InVLESS, kt.UserA, 5, 5*time.Second)
	if len(want) != 5 || len(kt.WaitConns(t, tr, kt.InHY2, kt.UserA, 1, 5*time.Second)) != 1 {
		t.Fatalf("tracker 里应当有 VLESS 5 条、Hysteria2 1 条：%d", len(want))
	}
	var list xrpc.ConnectionsList
	json.Unmarshal(serve(t, m, xrpc.MethodConnectionsList, xrpc.ConnectionsListParams{Inbound: kt.InVLESS, Credential: kt.UserA}), &list)
	if len(list.Connections) != 5 {
		t.Fatalf("应当列出 5 条：%+v", list)
	}
	tcp := 0
	for i, c := range list.Connections {
		w := want[i]
		if c.ID != w.ID || c.Network != w.Network || c.Peer != w.Source || c.Outbound != w.Outbound || !c.Start.Equal(w.Start) {
			t.Fatalf("第 %d 条与 tracker 对不上：%+v vs %+v", i, c, w)
		}
		if c.Network == "tcp" {
			tcp++
		}
	}
	if tcp != 3 {
		t.Fatalf("应当有 3 条 tcp：%d", tcp)
	}

	var kicked xrpc.ConnectionsKicked
	json.Unmarshal(serve(t, m, xrpc.MethodConnectionsKick, xrpc.ConnectionsKickParams{Credential: kt.UserA, Inbound: kt.InVLESS}), &kicked)
	if kicked.Kicked != 5 {
		t.Fatalf("应当踢掉 VLESS 上的 5 条：%d", kicked.Kicked)
	}
	if n := len(kt.WaitConns(t, tr, kt.InVLESS, kt.UserA, 0, 3*time.Second)); n != 0 {
		t.Fatalf("VLESS 上的连接 3 秒内应当都断开：%d", n)
	}
	if n := len(tr.Connections(kt.InHY2, kt.UserA)); n != 1 {
		t.Fatalf("Hysteria2 上的连接不应当受影响：%d", n)
	}

	// 不给入站：A 在两个入站上的连接都断开，B 的不受影响。
	kt.Echo(t, vless, 1)
	kt.Echo(t, kt.StartClient(t, s, kt.UserB, kt.InVLESS), 1)
	kt.WaitConns(t, tr, kt.InVLESS, kt.UserA, 1, 5*time.Second)
	kt.WaitConns(t, tr, kt.InVLESS, kt.UserB, 1, 5*time.Second)
	kicked = xrpc.ConnectionsKicked{}
	json.Unmarshal(serve(t, m, xrpc.MethodConnectionsKick, xrpc.ConnectionsKickParams{Credential: kt.UserA}), &kicked)
	if kicked.Kicked != 2 {
		t.Fatalf("不给入站应当踢掉 A 在两个入站上的 2 条：%d", kicked.Kicked)
	}
	if a1, a2 := len(kt.WaitConns(t, tr, kt.InVLESS, kt.UserA, 0, 3*time.Second)), len(kt.WaitConns(t, tr, kt.InHY2, kt.UserA, 0, 3*time.Second)); a1+a2 != 0 {
		t.Fatalf("A 在两个入站上的连接 3 秒内应当都断开：%d %d", a1, a2)
	}
	if n := len(tr.Connections(kt.InVLESS, kt.UserB)); n != 1 {
		t.Fatalf("B 的连接不应当受影响：%d", n)
	}

	var snap xrpc.TrafficSnapshot
	json.Unmarshal(serve(t, m, xrpc.MethodTrafficSnapshot, nil), &snap)
	if !snap.KernelRunning || snap.KernelVersion == "" || snap.KernelStartedAt == nil || snap.Generation != 1 || len(snap.Counts) == 0 {
		t.Fatalf("快照应当报内核在跑、带版本与启动时间、有计数：%+v", snap)
	}
}

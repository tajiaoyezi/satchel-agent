package diag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/telemetry"
)

func TestParseProcNetPorts(t *testing.T) {
	tcpRaw := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:2710 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:9999 0100007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`)
	got := ParseProcNet(tcpRaw, "tcp", true, false)
	if len(got) != 2 {
		t.Fatalf("应解析出 2 个 LISTEN 端口，得到 %+v", got)
	}
	if got[0].Address != "0.0.0.0" || got[0].Port != 443 {
		t.Fatalf("第 1 项应为 0.0.0.0:443，得到 %+v", got[0])
	}
	if got[1].Address != "127.0.0.1" || got[1].Port != 10000 {
		t.Fatalf("第 2 项应为 127.0.0.1:10000，得到 %+v", got[1])
	}

	tcp6Raw := []byte(`  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A
`)
	got6 := ParseProcNet(tcp6Raw, "tcp6", true, true)
	if len(got6) != 1 || got6[0].Address != "::1" || got6[0].Port != 80 {
		t.Fatalf("IPv6 LISTEN 解析异常：%+v", got6)
	}
}

func TestDiagAllItemsRedactionCertsAndAlpineFirewall(t *testing.T) {
	dir := t.TempDir()
	// 写入测试 kernel.json（含敏感键）与模拟证书+私钥。
	kernelJSON := `{
		"inbounds": [{"tag":"vless-in","type":"vless","users":[{"uuid":"11111111-2222-3333-4444-555555555555"}],"tls":{"reality":{"private_key":"TOP_SECRET_REALITY_KEY","short_id":["aabbcc"]}}}],
		"outbounds": [{"tag":"direct","type":"direct"}]
	}`
	if err := os.WriteFile(filepath.Join(dir, "kernel.json"), []byte(kernelJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedCert(t, filepath.Join(certDir, "site.crt"), filepath.Join(certDir, "site.key"), "diag.example.com", 45*24*time.Hour)

	// 启动本地 TCP 监听供 connectivity 实测。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 模拟 Alpine 存在 /etc/alpine-release 但 nft 读失败（必须报 ok:false 而非空成功！）。
	alpineMarker := filepath.Join(dir, "alpine-release")
	if err := os.WriteFile(alpineMarker, []byte("3.20.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	eng := New(Options{
		ConfigDir:     dir,
		CertDirs:      []string{certDir},
		AgentVersion:  "0.2.0-test",
		StartedAt:     now.Add(-time.Hour),
		AlpineRelease: alpineMarker,
		ProbeTargets:  []string{ln.Addr().String()},
		Sys:           telemetry.NewSysCollector(telemetry.SysReader{}),
		Now:           func() time.Time { return now },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return nil, errors.New("permission denied")
			}
			return nil, errors.New("not found")
		},
	})

	// 1. 未知项应返回 bad_params。
	if _, err := eng.Run(context.Background(), xrpc.DiagRunParams{Items: []string{"no-such"}}); err == nil {
		t.Fatal("未知诊断项应报错")
	}

	// 2. 全量 10 项（IncludeSecrets=false）：校验每一项语义。
	res, err := eng.Run(context.Background(), xrpc.DiagRunParams{
		MasterTimeUnixMS: now.Add(-3 * time.Second).UnixMilli(),
		IncludeSecrets:   false,
	})
	if err != nil {
		t.Fatalf("全量诊断失败：%v", err)
	}
	if len(res.Items) != 10 {
		t.Fatalf("应返回 10 项，得到 %d", len(res.Items))
	}
	byName := map[string]xrpc.DiagItemResult{}
	for _, it := range res.Items {
		byName[it.Name] = it
	}

	// Alpine firewall 读不到 nft 必须 ok=false。
	fw := byName[xrpc.DiagItemFirewall]
	if fw.OK || fw.Status != xrpc.DiagStatusFailed || !strings.Contains(fw.Error, "nftables") {
		t.Fatalf("Alpine nft 失败必须标 ok=false：%+v", fw)
	}
	// speedtest 在 M2 必须为 not_available。
	st := byName[xrpc.DiagItemSpeedtest]
	if st.Status != xrpc.DiagStatusNotAvailable {
		t.Fatalf("speedtest 应为 not_available：%+v", st)
	}
	// config 必须脱敏且标 UntrustedData。
	cfgItem := byName[xrpc.DiagItemConfig]
	if !cfgItem.UntrustedData || cfgItem.ContentType != "data" {
		t.Fatalf("config 必须标注 data/untrusted_data：%+v", cfgItem)
	}
	cfgMap := cfgItem.Data.(map[string]any)
	cfgText, _ := cfgMap["kernel_config"].(string)
	if strings.Contains(cfgText, "TOP_SECRET_REALITY_KEY") || strings.Contains(cfgText, "11111111-2222") {
		t.Fatalf("未带 secrets 时 config 泄露了密钥：%s", cfgText)
	}
	// logs 必须标注 UntrustedData。
	if !byName[xrpc.DiagItemLogs].UntrustedData || byName[xrpc.DiagItemLogs].ContentType != "data" {
		t.Fatalf("logs 必须标注 data/untrusted_data：%+v", byName[xrpc.DiagItemLogs])
	}
	// certs 应解析出 site.crt（~45 天剩余）且不读 site.key。
	certMap := byName[xrpc.DiagItemCerts].Data.(map[string]any)
	certs := certMap["certs"].([]CertSummary)
	if len(certs) != 1 || certs[0].Subject != "diag.example.com" || certs[0].DaysLeft < 40 {
		t.Fatalf("certs 解析异常：%+v", certs)
	}
	// connectivity 应连上本地测试端口。
	if !byName[xrpc.DiagItemConnectivity].OK {
		t.Fatalf("connectivity 应可达本地端口：%+v", byName[xrpc.DiagItemConnectivity])
	}
	// clock 应算出约 +3 秒偏差。
	clkMap := byName[xrpc.DiagItemClock].Data.(map[string]any)
	if off, _ := clkMap["offset_seconds"].(float64); off < 2.5 || off > 3.5 {
		t.Fatalf("clock 偏差应约为 3 秒，得到 %v", off)
	}
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath, cn string, validFor time.Duration) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validFor),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

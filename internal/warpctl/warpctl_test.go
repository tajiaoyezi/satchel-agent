package warpctl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/satchel/satchel/pkg/xrpc"
)

func startMockWarpServer(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	accountType := "free"
	license := ""
	clientID := base64.StdEncoding.EncodeToString([]byte{11, 22, 33, 44})

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/reg":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "dev-12345",
				"token": "cf-secret-token",
				"account": map[string]any{
					"id":           "acct-1",
					"account_type": accountType,
					"license":      license,
				},
				"config": map[string]any{
					"client_id": clientID,
					"peers": []map[string]any{{
						"public_key": xrpc.DefaultWarpPeerPublicKey,
						"endpoint":   map[string]any{"host": "engage.cloudflareclient.com:2408"},
					}},
					"interface": map[string]any{
						"addresses": map[string]any{"v4": "172.16.0.2", "v6": "2606:4700:110:8a36:df92:102a:9602:fa18"},
					},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/reg/dev-12345/account":
			if r.Header.Get("Authorization") != "Bearer cf-secret-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if strings.TrimSpace(req["license"]) == "" {
				http.Error(w, "missing license", http.StatusBadRequest)
				return
			}
			license = req["license"]
			accountType = "plus"
			_ = json.NewEncoder(w).Encode(map[string]any{"account_type": accountType, "license": license})
		case r.Method == http.MethodGet && r.URL.Path == "/reg/dev-12345":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "dev-12345",
				"token": "cf-secret-token",
				"account": map[string]any{
					"id":           "acct-1",
					"account_type": accountType,
					"license":      license,
				},
				"config": map[string]any{
					"client_id": clientID,
					"interface": map[string]any{
						"addresses": map[string]any{"v4": "172.16.0.2", "v6": "2606:4700:110:8a36:df92:102a:9602:fa18"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestWarpInstallAuthorizeCredentialsAndRemove(t *testing.T) {
	srv := startMockWarpServer(t)
	defer srv.Close()

	dir := t.TempDir()
	mgr := New(dir)
	ctx := context.Background()

	// 1. 初始未安装。
	st, err := mgr.Status(ctx)
	if err != nil || st.Installed {
		t.Fatalf("初始状态应为未安装：st=%+v err=%v", st, err)
	}
	if _, err := mgr.Credentials(ctx); err == nil {
		t.Fatal("未安装时 Credentials 应报 conflict")
	}

	// 2. 安装注册（含文件权限 0600 校验）。
	inst, err := mgr.Install(ctx, xrpc.WarpInstallParams{APIBase: srv.URL, MTU: 1320})
	if err != nil {
		t.Fatalf("Install 失败：%v", err)
	}
	if !inst.Installed || inst.AccountType != "free" || inst.DeviceID != "dev-12345" || inst.MTU != 1320 || len(inst.Reserved) != 3 || inst.Reserved[0] != 11 {
		t.Fatalf("Install 结果异常：%+v", inst)
	}
	fi, err := os.Stat(mgr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("warp.json 权限应为 0600，实际 %o", fi.Mode().Perm())
	}

	// 幂等再安装返回 AlreadyInstalled=true。
	inst2, err := mgr.Install(ctx, xrpc.WarpInstallParams{APIBase: srv.URL})
	if err != nil || !inst2.AlreadyInstalled {
		t.Fatalf("重复 Install 应幂等返回 AlreadyInstalled：%+v err=%v", inst2, err)
	}

	// 3. 绑定 WARP+ license。
	auth, err := mgr.Authorize(ctx, xrpc.WarpAuthorizeParams{LicenseKey: "TEST-PLUS-KEY", APIBase: srv.URL})
	if err != nil {
		t.Fatalf("Authorize license 失败：%v", err)
	}
	if auth.Mode != "license" || auth.AccountType != "plus" || !auth.HasLicense {
		t.Fatalf("Authorize license 结果异常：%+v", auth)
	}

	// 4. Credentials 返回完整私钥与 WireGuard 参数，Status 不含敏感字段。
	creds, err := mgr.Credentials(ctx)
	if err != nil || creds.PrivateKey == "" || creds.AddressV4 != "172.16.0.2/32" || creds.MTU != 1320 {
		t.Fatalf("Credentials 异常：%+v err=%v", creds, err)
	}

	// 5. Remove 原子清理并幂等。
	rem, err := mgr.Remove(ctx)
	if err != nil || !rem.Removed {
		t.Fatalf("Remove 失败：%+v err=%v", rem, err)
	}
	if _, err := os.Stat(mgr.Path()); !os.IsNotExist(err) {
		t.Fatalf("warp.json 应已删除：%v", err)
	}

	// 6. 离线导入模式。
	priv, _, err := generateWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	imp, err := mgr.Authorize(ctx, xrpc.WarpAuthorizeParams{
		PrivateKey: priv,
		AddressV4:  "172.16.0.9",
		AddressV6:  "fd01::2",
		Reserved:   []int{7, 8, 9},
		MTU:        1280,
	})
	if err != nil {
		t.Fatalf("离线导入失败：%v", err)
	}
	if imp.Mode != "import" || imp.AccountType != "imported" || imp.AddressV4 != "172.16.0.9/32" || imp.AddressV6 != "fd01::2/128" {
		t.Fatalf("离线导入结果异常：%+v", imp)
	}
}

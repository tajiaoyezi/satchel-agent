package nginxctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/satchel/satchel/pkg/xrpc"
)

type fakeRunner struct {
	bins     map[string]string
	runFn    func(name string, args ...string) (string, error)
	recorded []string
}

func (f *fakeRunner) LookPath(file string) (string, error) {
	if p, ok := f.bins[file]; ok {
		return p, nil
	}
	return "", errors.New("not found: " + file)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.recorded = append(f.recorded, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if f.runFn != nil {
		return f.runFn(name, args...)
	}
	if name == "nginx" && len(args) > 0 && args[0] == "-v" {
		return "nginx version: nginx/1.26.2\n", nil
	}
	return "", nil
}

func TestNginxCtlStatusControlAndDockerLifecycle(t *testing.T) {
	root := t.TempDir()
	r := &fakeRunner{bins: map[string]string{"nginx": "/usr/sbin/nginx"}}
	running := true
	ctl := New(Options{
		RootDir:      root,
		InDocker:     func() bool { return true },
		Runner:       r,
		CheckRunning: func(context.Context, string) bool { return running },
	})

	st := ctl.Status(context.Background())
	if !st.Installed || !st.Running || !st.InDocker || st.Version != "1.26.2" || st.InitSystem != "direct" || !st.ConfigOK {
		t.Fatalf("unexpected status: %+v", st)
	}

	// Docker install returns already_installed=true without invoking package managers
	inst, err := ctl.Install(context.Background())
	if err != nil || !inst.Installed || !inst.AlreadyInstalled || !inst.InDocker {
		t.Fatalf("unexpected docker install: res=%+v err=%v", inst, err)
	}
	// Docker uninstall is rejected with conflict
	if _, err := ctl.Uninstall(context.Background()); err == nil {
		t.Fatal("expected docker uninstall to fail")
	} else {
		var xe *xrpc.Error
		if !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
			t.Fatalf("expected conflict error, got %v", err)
		}
	}

	// Control reload / stop / start
	if _, _, err := ctl.Control(context.Background(), "reload"); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	running = false
	if _, _, err := ctl.Control(context.Background(), "reload"); err == nil {
		t.Fatal("reload while stopped must return conflict")
	}
	if _, _, err := ctl.Control(context.Background(), "start"); err != nil {
		t.Fatalf("start failed: %v", err)
	}
}

func TestNginxCtlApplyWebsitesGuardsAndRollback(t *testing.T) {
	root := t.TempDir()
	serversDir := filepath.Join(root, "servers")
	streamDir := filepath.Join(root, "stream_servers")
	if err := os.MkdirAll(serversDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(streamDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 放一份未纳管手工站点文件（不含 # satchel-managed:）与一份冲突同名未纳管文件
	manualPath := filepath.Join(serversDir, "manual.conf")
	manualBytes := []byte("server {\n    listen 80;\n    server_name legacy.example.com;\n    root /var/www/legacy;\n}\n")
	if err := os.WriteFile(manualPath, manualBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	unmanagedCollision := filepath.Join(serversDir, "satchel-site-hand.example.com.conf")
	if err := os.WriteFile(unmanagedCollision, []byte("server { listen 80; server_name hand.example.com; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	failTest := false
	r := &fakeRunner{
		bins: map[string]string{"nginx": "/usr/sbin/nginx"},
		runFn: func(name string, args ...string) (string, error) {
			if name == "nginx" && len(args) > 0 && args[0] == "-t" && failTest {
				return "nginx: [emerg] unexpected end of file", errors.New("exit status 1")
			}
			return "nginx version: nginx/1.26.2\n", nil
		},
	}
	ctl := New(Options{
		RootDir:      root,
		InDocker:     func() bool { return true },
		Runner:       r,
		CheckRunning: func(context.Context, string) bool { return true },
	})

	// 1. 拒绝覆盖未纳管同名文件
	_, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		Sites: []xrpc.ManagedWebsiteFile{
			{Domain: "hand.example.com", Conf: xrpc.SatchelManagedHeader + " domain=hand.example.com\nserver { listen 80; server_name hand.example.com; }\n"},
		},
	})
	var xe *xrpc.Error
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("expected conflict refusing to overwrite unmanaged file, got %v", err)
	}

	// 2. 同机 443 防抢占守卫
	_, err = ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		ProtectMaster443: true,
		Sites: []xrpc.ManagedWebsiteFile{
			{Domain: "tls.example.com", Conf: xrpc.SatchelManagedHeader + " domain=tls.example.com\nserver {\n    listen 443 ssl;\n    server_name tls.example.com;\n}\n"},
		},
	})
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("expected conflict for 443 under ProtectMaster443, got %v", err)
	}

	// 3. 正常应用站点（含静态 HTML），绝不触碰 manual.conf
	res, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		Sites: []xrpc.ManagedWebsiteFile{
			{
				Domain:      "app.example.com",
				Conf:        xrpc.SatchelManagedHeader + " website_id=1 domain=app.example.com\nserver {\n    listen 80;\n    server_name app.example.com;\n    location /ws {\n        proxy_pass http://127.0.0.1:10000;\n    }\n}\n",
				HTMLPath:    "/etc/nginx/html/app.example.com/index.html",
				HTMLContent: "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>app.example.com</title></head><body>OK</body></html>\n",
			},
		},
	})
	if err != nil || !res.Reloaded || len(res.Applied) != 1 {
		t.Fatalf("apply websites failed: res=%+v err=%v", res, err)
	}
	if got, _ := os.ReadFile(manualPath); string(got) != string(manualBytes) {
		t.Fatalf("manual.conf was altered!")
	}
	siteConfPath := filepath.Join(serversDir, "satchel-site-app.example.com.conf")
	origSiteConf, err := os.ReadFile(siteConfPath)
	if err != nil {
		t.Fatalf("expected written site conf: %v", err)
	}

	// 4. 扫描站点与 server 块：清晰区分 managed 与 unmanaged
	scanRes, err := ctl.ScanWebsites()
	if err != nil {
		t.Fatalf("ScanWebsites failed: %v", err)
	}
	foundManaged, foundUnmanaged := false, false
	for _, s := range scanRes.Sites {
		if s.Domain == "app.example.com" && s.Managed && s.Type == "proxy" {
			foundManaged = true
		}
		if s.Domain == "legacy.example.com" && !s.Managed && s.Type == "static" {
			foundUnmanaged = true
		}
	}
	if !foundManaged || !foundUnmanaged {
		t.Fatalf("expected both managed and unmanaged sites in scan: %+v", scanRes.Sites)
	}

	// 5. nginx -t 失败自动回滚：旧站点保持原内容，新站点文件被删掉
	failTest = true
	rbRes, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		Sites: []xrpc.ManagedWebsiteFile{
			{Domain: "app.example.com", Conf: xrpc.SatchelManagedHeader + " updated\nserver { listen 80; broken }\n"},
			{Domain: "new.example.com", Conf: xrpc.SatchelManagedHeader + " new\nserver { listen 80; server_name new.example.com; }\n"},
		},
	})
	if err != nil {
		t.Fatalf("rollback result should be returned in struct without RPC error: %v", err)
	}
	if !rbRes.RolledBack || rbRes.Reloaded || rbRes.Error == "" {
		t.Fatalf("expected rolled_back=true, got %+v", rbRes)
	}
	if afterRB, _ := os.ReadFile(siteConfPath); string(afterRB) != string(origSiteConf) {
		t.Fatalf("existing site conf not rolled back: %q", string(afterRB))
	}
	if _, err := os.Stat(filepath.Join(serversDir, "satchel-site-new.example.com.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("newly created conf should be removed on rollback, got err=%v", err)
	}
}

func TestNginxCtlClearStreamProtectionAndRollback(t *testing.T) {
	root := t.TempDir()
	streamDir := filepath.Join(root, "stream_servers")
	if err := os.MkdirAll(streamDir, 0o755); err != nil {
		t.Fatal(err)
	}
	master443 := filepath.Join(streamDir, MasterHTTPS443File)
	if err := os.WriteFile(master443, []byte(xrpc.SatchelMaster443Marker+"\nserver {\n    listen 443;\n    proxy_pass 127.0.0.1:8443;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	managed8443 := filepath.Join(streamDir, "satchel-stream-8443.conf")
	if err := os.WriteFile(managed8443, []byte(xrpc.SatchelManagedHeader+" stream=8443\nserver {\n    listen 8443;\n    proxy_pass 127.0.0.1:9443;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unmanaged8443 := filepath.Join(streamDir, "custom-8443.conf")
	if err := os.WriteFile(unmanaged8443, []byte("server {\n    listen 8443;\n    proxy_pass 127.0.0.1:9999;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &fakeRunner{bins: map[string]string{"nginx": "/usr/sbin/nginx"}}
	ctl := New(Options{
		RootDir:      root,
		InDocker:     func() bool { return false },
		Runner:       r,
		CheckRunning: func(context.Context, string) bool { return true },
	})

	// 清理 443 被磁盘主控 443 守卫拦截
	_, err := ctl.ClearStream(context.Background(), xrpc.NginxClearStreamParams{Port: 443})
	var xe *xrpc.Error
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("expected conflict protecting master 443, got %v", err)
	}
	if _, err := os.Stat(master443); err != nil {
		t.Fatalf("master_https_443.conf must remain intact")
	}

	// 清理 8443：只删 satchel-stream-8443.conf，保留 custom-8443.conf
	res, err := ctl.ClearStream(context.Background(), xrpc.NginxClearStreamParams{Port: 8443})
	if err != nil || !res.Reloaded || len(res.RemovedFiles) != 1 || res.RemovedFiles[0] != managed8443 {
		t.Fatalf("unexpected clear-stream 8443 result: res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(managed8443); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed 8443 file should be removed")
	}
	if _, err := os.Stat(unmanaged8443); err != nil {
		t.Fatalf("unmanaged custom-8443.conf must NEVER be deleted")
	}
}

func TestNginxCtlApplyWebsitesStealSiteTxAndGuards(t *testing.T) {
	root := t.TempDir()
	serversDir := filepath.Join(root, "servers")
	if err := os.MkdirAll(serversDir, 0o755); err != nil {
		t.Fatal(err)
	}
	failTest := false
	r := &fakeRunner{
		bins: map[string]string{"nginx": "/usr/sbin/nginx"},
		runFn: func(name string, args ...string) (string, error) {
			if name == "nginx" && len(args) > 0 && args[len(args)-1] == "-t" && failTest {
				return "nginx: [emerg] broken steal conf", errors.New("exit status 1")
			}
			return "ok", nil
		},
	}
	ctl := New(Options{
		RootDir:      root,
		InDocker:     func() bool { return false },
		Runner:       r,
		CheckRunning: func(context.Context, string) bool { return true },
	})

	// 1. steal_site 与 remove_steal 互斥拦截
	_, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		StealSite:   &xrpc.ManagedWebsiteFile{Domain: "decoy.example.com", Conf: xrpc.SatchelManagedHeader + " steal\nserver { listen 127.0.0.1:8001 ssl; }\n"},
		RemoveSteal: true,
	})
	var xe *xrpc.Error
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeBadParams {
		t.Fatalf("互斥参数应报 bad_params，得到：%v", err)
	}

	// 2. 同机 443 守卫拦截含 listen 443 的 steal_site
	_, err = ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		ProtectMaster443: true,
		StealSite: &xrpc.ManagedWebsiteFile{
			Domain: "decoy.example.com",
			Conf:   xrpc.SatchelManagedHeader + " steal\nserver {\n    listen 443 ssl;\n}\n",
		},
	})
	if !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("同机 443 守卫应拦截 listen 443 的 steal_site，得到：%v", err)
	}

	// 3. 合法 steal_site 原子落盘并重载（含默认 decoy index.html），且不出现在 ScanWebsites 中
	origStealConf := xrpc.SatchelManagedHeader + " steal_self=true domain=decoy.example.com\nserver {\n    listen 127.0.0.1:8001 ssl;\n    server_name decoy.example.com;\n}\n"
	res, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		StealSite: &xrpc.ManagedWebsiteFile{
			Domain:      "decoy.example.com",
			Conf:        origStealConf,
			HTMLPath:    "/etc/nginx/html/decoy.example.com/index.html",
			HTMLContent: "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Decoy</title></head><body>ok</body></html>\n",
		},
	})
	if err != nil || !res.Reloaded || !res.StealApplied || res.StealRemoved || res.StealConfPath != filepath.Join(serversDir, ManagedStealFile) {
		t.Fatalf("steal_site 应用结果异常：res=%+v err=%v", res, err)
	}
	if scan, serr := ctl.ScanWebsites(); serr != nil || len(scan.Sites) != 0 {
		t.Fatalf("ScanWebsites 应忽略 satchel-steal.conf，得到：%+v err=%v", scan.Sites, serr)
	}
	if srvList, lerr := ctl.ListServers(); lerr != nil || len(srvList.Servers) != 1 || !srvList.Servers[0].Managed {
		t.Fatalf("ListServers 应能看到受管的 satchel-steal.conf，得到：%+v err=%v", srvList.Servers, lerr)
	}

	// 4. 更新 steal_site 时 nginx -t 失败 -> 完整回滚至原内容
	failTest = true
	rbRes, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		StealSite: &xrpc.ManagedWebsiteFile{
			Domain: "decoy.example.com",
			Conf:   xrpc.SatchelManagedHeader + " broken\nserver { invalid }\n",
		},
	})
	if err != nil || !rbRes.RolledBack || rbRes.StealApplied || rbRes.Error == "" {
		t.Fatalf("nginx -t 失败应回滚：res=%+v err=%v", rbRes, err)
	}
	afterRB, _ := os.ReadFile(filepath.Join(serversDir, ManagedStealFile))
	if string(afterRB) != origStealConf {
		t.Fatalf("satchel-steal.conf 未完整回滚：\n%s", afterRB)
	}

	// 5. remove_steal 原子删除并支持幂等二次调用
	failTest = false
	remRes, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		RemoveSteal: true,
	})
	if err != nil || !remRes.Reloaded || !remRes.StealRemoved || remRes.StealApplied {
		t.Fatalf("remove_steal 应成功删除：res=%+v err=%v", remRes, err)
	}
	if _, serr := os.Stat(filepath.Join(serversDir, ManagedStealFile)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("satchel-steal.conf 应已删除，err=%v", serr)
	}
	remRes2, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		RemoveSteal: true,
	})
	if err != nil || remRes2.StealRemoved {
		t.Fatalf("二次 remove_steal 应幂等成功且 StealRemoved=false：res=%+v err=%v", remRes2, err)
	}

	// 6. 磁盘上若存在手工未纳管的 satchel-steal.conf，覆盖与删除均报 conflict
	if err := os.WriteFile(filepath.Join(serversDir, ManagedStealFile), []byte("server { listen 8001; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		StealSite: &xrpc.ManagedWebsiteFile{Domain: "decoy.example.com", Conf: origStealConf},
	}); !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("未纳管 satchel-steal.conf 应拒绝覆盖，得到：%v", err)
	}
	if _, err := ctl.ApplyWebsites(context.Background(), xrpc.NginxWebsitesApplyParams{
		RemoveSteal: true,
	}); !errors.As(err, &xe) || xe.Code != xrpc.CodeConflict {
		t.Fatalf("未纳管 satchel-steal.conf 应拒绝删除，得到：%v", err)
	}
}

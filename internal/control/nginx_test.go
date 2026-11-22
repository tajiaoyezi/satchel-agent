package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/nginxctl"
	"github.com/satchel/satchel-agent/internal/tracker"
)

type stubNginxRunner struct {
	bins map[string]string
}

func (s stubNginxRunner) LookPath(file string) (string, error) {
	if p, ok := s.bins[file]; ok {
		return p, nil
	}
	return "", os.ErrNotExist
}

func (s stubNginxRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "nginx" && len(args) > 0 && args[0] == "-v" {
		return "nginx version: nginx/1.26.2\n", nil
	}
	return "", nil
}

func TestNginxAndServiceControlMethods(t *testing.T) {
	cfgDir := t.TempDir()
	nginxRoot := t.TempDir()
	validCfg := `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"direct"}]}`
	if err := os.WriteFile(filepath.Join(cfgDir, KernelConfig), []byte(validCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := tracker.New()
	k := kernel.New(tr)
	t.Cleanup(func() { _ = k.Stop() })

	ctl := nginxctl.New(nginxctl.Options{
		RootDir:      nginxRoot,
		InDocker:     func() bool { return true },
		Runner:       stubNginxRunner{bins: map[string]string{"nginx": "/usr/sbin/nginx"}},
		CheckRunning: func(context.Context, string) bool { return true },
	})
	methods := Methods(Deps{
		Tracker:      tr,
		Kernel:       k,
		Inbounds:     NewInbounds([]string{}),
		ConfigDir:    cfgDir,
		Nginx:        ctl,
		AgentVersion: "dev-test",
		StartedAt:    time.Now().Add(-30 * time.Second),
		InDocker:     func() bool { return true },
	})

	call := func(method string, params any) xrpc.Reply {
		var raw json.RawMessage
		if params != nil {
			raw, _ = json.Marshal(params)
		}
		return methods.Serve(context.Background(), xrpc.Call{ID: "1", Method: method, Params: raw})
	}

	// 1. service.status
	rep := call(xrpc.MethodServiceStatus, nil)
	if rep.Error != nil {
		t.Fatalf("service.status failed: %+v", rep.Error)
	}
	var st xrpc.ServiceStatusResult
	if err := json.Unmarshal(rep.Result, &st); err != nil || !st.Nginx.Installed || !st.Agent.Running || st.Agent.Version != "dev-test" {
		t.Fatalf("unexpected service.status: %s err=%v", rep.Result, err)
	}

	// 2. service.control kernel start/stop/restart & nginx reload
	if r := call(xrpc.MethodServiceControl, xrpc.ServiceControlParams{Service: "kernel", Action: "start"}); r.Error != nil {
		t.Fatalf("kernel start failed: %+v", r.Error)
	}
	if !k.Running() {
		t.Fatal("expected kernel to be running after start")
	}
	if r := call(xrpc.MethodServiceControl, xrpc.ServiceControlParams{Service: "kernel", Action: "reload"}); r.Error == nil || r.Error.Code != xrpc.CodeBadParams {
		t.Fatalf("kernel reload should return bad_params, got %+v", r.Error)
	}
	if r := call(xrpc.MethodServiceControl, xrpc.ServiceControlParams{Service: "kernel", Action: "stop"}); r.Error != nil {
		t.Fatalf("kernel stop failed: %+v", r.Error)
	}
	if k.Running() {
		t.Fatal("expected kernel stopped")
	}
	if r := call(xrpc.MethodServiceControl, xrpc.ServiceControlParams{Service: "nginx", Action: "reload"}); r.Error != nil {
		t.Fatalf("nginx reload failed: %+v", r.Error)
	}

	// 3. nginx.install (docker already installed) & nginx.uninstall (docker conflict)
	if r := call(xrpc.MethodNginxInstall, xrpc.NginxInstallParams{}); r.Error != nil {
		t.Fatalf("nginx.install failed: %+v", r.Error)
	}
	if r := call(xrpc.MethodNginxUninstall, xrpc.NginxUninstallParams{}); r.Error == nil || r.Error.Code != xrpc.CodeConflict {
		t.Fatalf("docker nginx.uninstall expected conflict, got %+v", r.Error)
	}

	// 4. nginx.websites.apply -> nginx.websites.scan -> nginx.servers
	applyRep := call(xrpc.MethodNginxWebsitesApply, xrpc.NginxWebsitesApplyParams{
		Sites: []xrpc.ManagedWebsiteFile{
			{Domain: "demo.example.com", Conf: xrpc.SatchelManagedHeader + " id=1\nserver {\n    listen 80;\n    server_name demo.example.com;\n    root /etc/nginx/html/demo.example.com;\n}\n"},
		},
	})
	if applyRep.Error != nil {
		t.Fatalf("nginx.websites.apply failed: %+v", applyRep.Error)
	}
	scanRep := call(xrpc.MethodNginxWebsitesScan, nil)
	if scanRep.Error != nil {
		t.Fatalf("nginx.websites.scan failed: %+v", scanRep.Error)
	}
	var sr xrpc.NginxWebsitesScanResult
	if err := json.Unmarshal(scanRep.Result, &sr); err != nil || len(sr.Sites) != 1 || !sr.Sites[0].Managed {
		t.Fatalf("unexpected scan result: %s err=%v", scanRep.Result, err)
	}
	srvRep := call(xrpc.MethodNginxServers, nil)
	if srvRep.Error != nil {
		t.Fatalf("nginx.servers failed: %+v", srvRep.Error)
	}
	csRep := call(xrpc.MethodNginxClearStream, xrpc.NginxClearStreamParams{Port: 8443})
	if csRep.Error != nil {
		t.Fatalf("nginx.clear_stream failed: %+v", csRep.Error)
	}
}

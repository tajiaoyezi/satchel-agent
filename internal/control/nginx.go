package control

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/release"
	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/nginxctl"
)

func (d Deps) nginxController() *nginxctl.Controller {
	if d.Nginx != nil {
		return d.Nginx
	}
	root := ""
	if len(d.NginxRoots) > 0 {
		root = d.NginxRoots[0]
	}
	return nginxctl.New(nginxctl.Options{
		RootDir:  root,
		InDocker: d.InDocker,
	})
}

func (d Deps) isInDocker() bool {
	if d.InDocker != nil {
		return d.InDocker()
	}
	return release.InDocker("/")
}

func (d Deps) collectServiceStatus(ctx context.Context, ctl *nginxctl.Controller) xrpc.ServiceStatusResult {
	now := d.now().UTC()
	var kRunning bool
	var kStarted *time.Time
	if d.Kernel != nil {
		kRunning = d.Kernel.Running()
		if at := d.Kernel.StartedAt(); !at.IsZero() {
			t := at.UTC()
			kStarted = &t
		}
	}
	var uptime int64
	if !d.StartedAt.IsZero() {
		if sec := int64(now.Sub(d.StartedAt).Seconds()); sec >= 0 {
			uptime = sec
		}
	}
	return xrpc.ServiceStatusResult{
		Kernel: xrpc.KernelServiceStatus{
			Running:   kRunning,
			Version:   kernel.Version,
			StartedAt: kStarted,
		},
		Nginx: ctl.Status(ctx),
		Agent: xrpc.AgentServiceStatus{
			Running:       true,
			Version:       d.AgentVersion,
			UptimeSeconds: uptime,
			InDocker:      d.isInDocker(),
		},
		CheckedAt: now,
	}
}

func registerNginxAndServiceMethods(m xrpc.Methods, d Deps) {
	ctl := d.nginxController()

	m[xrpc.MethodServiceStatus] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		return d.collectServiceStatus(ctx, ctl), nil
	}

	m[xrpc.MethodServiceControl] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.ServiceControlParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		svc := strings.ToLower(strings.TrimSpace(p.Service))
		act := strings.ToLower(strings.TrimSpace(p.Action))

		switch svc {
		case "kernel":
			d.ConfigMu.Lock()
			defer d.ConfigMu.Unlock()
			if d.Kernel == nil {
				return nil, &xrpc.Error{Code: xrpc.CodeConflict, Message: "节点未装配内嵌内核"}
			}
			var msg string
			switch act {
			case "start":
				if d.Kernel.Running() {
					msg = "kernel 已在运行中"
				} else {
					cfg, tags, err := ReadKernelConfig(d.ConfigDir)
					if err != nil {
						return nil, badParams("%v", err)
					}
					if err := d.Kernel.Start(d.kernelCtx(), cfg); err != nil {
						return nil, err
					}
					d.Inbounds.Set(tags)
					msg = "kernel 已启动"
				}
			case "stop":
				if !d.Kernel.Running() {
					msg = "kernel 已处于停止状态"
				} else {
					if err := d.Kernel.Stop(); err != nil {
						return nil, err
					}
					msg = "kernel 已停止"
				}
			case "restart":
				cfg, tags, err := ReadKernelConfig(d.ConfigDir)
				if err != nil {
					return nil, badParams("%v", err)
				}
				if err := d.Kernel.Restart(d.kernelCtx(), cfg); err != nil {
					return nil, err
				}
				d.Inbounds.Set(tags)
				msg = "kernel 已重启"
			default:
				return nil, badParams("kernel 服务不支持 action %q（仅支持 start、stop 或 restart）", p.Action)
			}
			st := d.collectServiceStatus(ctx, ctl)
			return xrpc.ServiceControlResult{
				Service: "kernel",
				Action:  act,
				Running: st.Kernel.Running,
				Message: msg,
				Status:  st,
			}, nil

		case "nginx":
			nxSt, msg, err := ctl.Control(ctx, act)
			if err != nil {
				return nil, err
			}
			st := d.collectServiceStatus(ctx, ctl)
			st.Nginx = nxSt
			return xrpc.ServiceControlResult{
				Service: "nginx",
				Action:  act,
				Running: nxSt.Running,
				Message: msg,
				Status:  st,
			}, nil

		default:
			return nil, badParams("不支持的 service %q（仅支持 kernel 或 nginx）", p.Service)
		}
	}

	m[xrpc.MethodNginxInstall] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		return ctl.Install(ctx)
	}

	m[xrpc.MethodNginxUninstall] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		return ctl.Uninstall(ctx)
	}

	m[xrpc.MethodNginxServers] = func(_ context.Context, _ json.RawMessage) (any, error) {
		return ctl.ListServers()
	}

	m[xrpc.MethodNginxClearStream] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NginxClearStreamParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return ctl.ClearStream(ctx, p)
	}

	m[xrpc.MethodNginxWebsitesScan] = func(_ context.Context, _ json.RawMessage) (any, error) {
		return ctl.ScanWebsites()
	}

	m[xrpc.MethodNginxWebsitesApply] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NginxWebsitesApplyParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return ctl.ApplyWebsites(ctx, p)
	}
}

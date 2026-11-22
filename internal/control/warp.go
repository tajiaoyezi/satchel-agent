package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/warpctl"
)

func (d Deps) warpManager() *warpctl.Manager {
	if d.Warp != nil {
		return d.Warp
	}
	if d.ConfigDir != "" {
		return warpctl.New(d.ConfigDir)
	}
	return nil
}

func registerWarpMethods(m xrpc.Methods, d Deps) {
	mgr := d.warpManager()
	if mgr == nil {
		return
	}

	m[xrpc.MethodWarpStatus] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return mgr.Status(pctx)
	}

	m[xrpc.MethodWarpInstall] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.WarpInstallParams
		if len(raw) > 0 && string(raw) != "null" {
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
		}
		timeout := 60 * time.Second
		if p.TimeoutMS > 0 {
			t := time.Duration(p.TimeoutMS) * time.Millisecond
			if t < timeout {
				timeout = t
			}
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return mgr.Install(pctx, p)
	}

	m[xrpc.MethodWarpAuthorize] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.WarpAuthorizeParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		timeout := 60 * time.Second
		if p.TimeoutMS > 0 {
			t := time.Duration(p.TimeoutMS) * time.Millisecond
			if t < timeout {
				timeout = t
			}
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return mgr.Authorize(pctx, p)
	}

	m[xrpc.MethodWarpRemove] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return mgr.Remove(pctx)
	}

	m[xrpc.MethodWarpCredentials] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return mgr.Credentials(pctx)
	}
}

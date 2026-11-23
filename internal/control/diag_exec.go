package control

import (
	"context"
	"encoding/json"

	"github.com/satchel/satchel/pkg/xrpc"
)

func registerDiagAndExecMethods(m xrpc.Methods, d Deps) {
	if d.Diag != nil {
		m[xrpc.MethodDiagRun] = func(ctx context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.DiagRunParams
			if len(raw) > 0 && string(raw) != "null" {
				if err := decode(raw, &p); err != nil {
					return nil, err
				}
			}
			return d.Diag.Run(ctx, p)
		}
	}
	if d.Exec != nil {
		m[xrpc.MethodExecStart] = func(ctx context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.ExecStartParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			return d.Exec.Start(ctx, p)
		}
		m[xrpc.MethodExecStatus] = func(_ context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.ExecStatusParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			return d.Exec.Status(p)
		}
		m[xrpc.MethodExecCancel] = func(_ context.Context, raw json.RawMessage) (any, error) {
			var p xrpc.ExecCancelParams
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
			return d.Exec.Cancel(p)
		}
	}
}

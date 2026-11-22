package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/netprobe"
)

func registerNetworkMethods(m xrpc.Methods, d Deps) {
	m[xrpc.MethodNetworkPortScan] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NetworkPortScanParams
		if len(raw) > 0 && string(raw) != "null" {
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return netprobe.PortScan(pctx, p)
	}

	m[xrpc.MethodNetworkValidateSite] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NetworkValidateSiteParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		pctx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		if d.ValidateSiteOpts != nil {
			return netprobe.ValidateSite(pctx, p, *d.ValidateSiteOpts)
		}
		return netprobe.ValidateSite(pctx, p)
	}

	m[xrpc.MethodNetworkDomainLatency] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NetworkDomainLatencyParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		return netprobe.DomainLatency(pctx, p)
	}

	m[xrpc.MethodNetworkReturnRouteTest] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.NetworkReturnRouteTestParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		pctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		return netprobe.TestReturnRoute(pctx, p, d.Tracer)
	}
}

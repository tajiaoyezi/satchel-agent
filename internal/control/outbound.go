package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
)

func registerOutboundMethods(m xrpc.Methods, d Deps) {
	m[xrpc.MethodOutboundProbe] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.OutboundProbeParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		tag := strings.TrimSpace(p.Tag)
		if tag == "" {
			return nil, badParams("tag 不能为空")
		}
		targetURL := strings.TrimSpace(p.URL)
		if targetURL == "" {
			targetURL = xrpc.DefaultOutboundProbeURL
		}
		if _, err := kernel.ValidateProbeURL(targetURL); err != nil {
			return nil, badParams("%v", err)
		}
		timeoutMS := p.TimeoutMS
		if timeoutMS == 0 {
			timeoutMS = xrpc.DefaultOutboundProbeTimeoutMS
		}
		if timeoutMS < 0 {
			return nil, badParams("timeout_ms 不能为负数")
		}
		if timeoutMS > xrpc.MaxOutboundProbeTimeoutMS {
			return nil, badParams("timeout_ms 不能超过 %d", xrpc.MaxOutboundProbeTimeoutMS)
		}
		if timeoutMS < xrpc.MinOutboundProbeTimeoutMS {
			timeoutMS = xrpc.MinOutboundProbeTimeoutMS
		}
		if d.Kernel == nil || !d.Kernel.Running() {
			return nil, badParams("节点内核未运行，无法执行出站探活")
		}

		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
		defer cancel()

		statusCode, latencyMs, err := d.Kernel.ProbeOutbound(probeCtx, tag, targetURL)
		if errors.Is(err, kernel.ErrNotRunning) || errors.Is(err, kernel.ErrOutboundNotFound) || errors.Is(err, kernel.ErrInvalidProbeURL) {
			return nil, badParams("%v", err)
		}
		res := xrpc.OutboundProbeResult{
			Tag:        tag,
			URL:        targetURL,
			LatencyMS:  latencyMs,
			StatusCode: statusCode,
			ProbedAt:   d.now().UTC(),
		}
		if err != nil {
			res.OK = false
			res.Error = err.Error()
			return res, nil
		}
		if statusCode >= 200 && statusCode <= 399 {
			res.OK = true
			return res, nil
		}
		res.OK = false
		res.Error = fmt.Sprintf("HTTP %d", statusCode)
		return res, nil
	}
}

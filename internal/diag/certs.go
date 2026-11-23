package diag

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/satchel/satchel/pkg/xrpc"
)

// CertSummary 描述单张证书的只读到期摘要（绝不含私钥）。
type CertSummary struct {
	Path     string    `json:"path"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	DNSNames []string  `json:"dns_names,omitempty"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Expired  bool      `json:"expired"`
	ParseErr string    `json:"parse_error,omitempty"`
}

func (e *Engine) checkCerts(ctx context.Context) xrpc.DiagItemResult {
	now := e.opts.Now().UTC()
	seen := make(map[string]struct{})
	var certs []CertSummary
	for _, dir := range e.opts.CertDirs {
		if ctx.Err() != nil {
			break
		}
		cleanDir := filepath.Clean(strings.TrimSpace(dir))
		if cleanDir == "" {
			continue
		}
		entries, err := os.ReadDir(cleanDir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if ctx.Err() != nil {
				break
			}
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			lower := strings.ToLower(name)
			// 严格跳过私钥文件。
			if strings.HasSuffix(lower, ".key") || strings.Contains(lower, "privkey") || strings.Contains(lower, "key.pem") {
				continue
			}
			if !strings.HasSuffix(lower, ".crt") && !strings.HasSuffix(lower, ".pem") && !strings.HasSuffix(lower, ".cer") {
				continue
			}
			full := filepath.Join(cleanDir, name)
			if _, dup := seen[full]; dup {
				continue
			}
			seen[full] = struct{}{}
			raw, err := e.opts.ReadFile(full)
			if err != nil || len(raw) == 0 || len(raw) > 256<<10 {
				continue
			}
			if summary, ok := parseCertPEM(full, raw, now); ok {
				certs = append(certs, summary)
			}
		}
	}
	sort.Slice(certs, func(i, j int) bool {
		if certs[i].DaysLeft != certs[j].DaysLeft {
			return certs[i].DaysLeft < certs[j].DaysLeft
		}
		return certs[i].Path < certs[j].Path
	})
	return xrpc.DiagItemResult{
		Name:   xrpc.DiagItemCerts,
		OK:     true,
		Status: xrpc.DiagStatusOK,
		Data: map[string]any{
			"count": len(certs),
			"certs": certs,
		},
	}
}

func parseCertPEM(path string, raw []byte, now time.Time) (CertSummary, bool) {
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		// 绝不处理任何 PRIVATE KEY 块。
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			continue
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CertSummary{Path: path, ParseErr: err.Error()}, true
		}
		days := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
		subj := cert.Subject.CommonName
		if subj == "" {
			subj = cert.Subject.String()
		}
		iss := cert.Issuer.CommonName
		if iss == "" {
			iss = cert.Issuer.String()
		}
		return CertSummary{
			Path:     path,
			Subject:  subj,
			Issuer:   iss,
			DNSNames: append([]string(nil), cert.DNSNames...),
			NotAfter: cert.NotAfter.UTC(),
			DaysLeft: days,
			Expired:  now.After(cert.NotAfter),
		}, true
	}
	return CertSummary{}, false
}

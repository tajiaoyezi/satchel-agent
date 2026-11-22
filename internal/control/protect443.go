package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/nginxctl"
	"github.com/satchel/satchel-agent/internal/pathguard"
)

// Protect443BackupSuffix 是节点启动自愈剥离 443 入站前保留原 kernel.json 的备份后缀。
const Protect443BackupSuffix = ".before-master-https-protect"

// HasMaster443Marker 检测给定 nginx 根目录的 stream_servers 下是否存在主控 443 保护文件或标记。
// nginxRoots 为空时使用 defaultNginxRoots（/etc/nginx、/usr/local/nginx）。
func HasMaster443Marker(nginxRoots []string) bool {
	roots := nginxRoots
	if len(roots) == 0 {
		roots = defaultNginxRoots
	}
	for _, root := range roots {
		streamDir := filepath.Join(root, "stream_servers")
		entries, err := os.ReadDir(streamDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if e.Name() == nginxctl.MasterHTTPS443File {
				return true
			}
			full := filepath.Join(streamDir, e.Name())
			realPath, err := pathguard.PathWithinDirs(full, streamDir)
			if err != nil {
				continue
			}
			raw, err := os.ReadFile(realPath)
			if err == nil && strings.Contains(string(raw), xrpc.SatchelMaster443Marker) {
				return true
			}
		}
	}
	return false
}

// ConfigHasPort443Inbound 检查一份 sing-box JSON 配置的 inbounds[] 中是否存在 listen_port == 443 的入站。
func ConfigHasPort443Inbound(raw []byte) (bool, []string, error) {
	doc, err := decodeJSONObject(raw)
	if err != nil {
		return false, nil, err
	}
	inbounds, _ := doc["inbounds"].([]any)
	var tags []string
	for _, item := range inbounds {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if listenPortIs443(m["listen_port"]) {
			tag, _ := m["tag"].(string)
			if strings.TrimSpace(tag) == "" {
				tag = "<unnamed>"
			}
			tags = append(tags, tag)
		}
	}
	return len(tags) > 0, tags, nil
}

// ProtectMasterHTTPSPort443 是节点启动拉起内嵌 sing-box 之前的同机 443 自愈守卫：
// 若本地存在主控 443 保护标记且 kernelPath 含 listen_port == 443 的入站，
// 先以 0600 权限写出备份 <kernelPath>.before-master-https-protect，再仅剥离 443 入站及其关联路由规则并原子写回。
// 若无标记、无 kernel.json 或不含 443 入站，绝不改写磁盘文件。
func ProtectMasterHTTPSPort443(kernelPath string, nginxRoots []string) (modified bool, backupPath string, removedTags []string, err error) {
	if !HasMaster443Marker(nginxRoots) {
		return false, "", nil, nil
	}
	raw, err := os.ReadFile(kernelPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "", nil, nil
		}
		return false, "", nil, fmt.Errorf("读取 %s 失败：%w", kernelPath, err)
	}
	doc, err := decodeJSONObject(raw)
	if err != nil {
		return false, "", nil, fmt.Errorf("解析 %s 失败：%w", kernelPath, err)
	}

	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) == 0 {
		return false, "", nil, nil
	}

	keptInbounds := make([]any, 0, len(inbounds))
	removedSet := map[string]bool{}
	removedCount := 0
	for _, item := range inbounds {
		m, ok := item.(map[string]any)
		if ok && listenPortIs443(m["listen_port"]) {
			removedCount++
			tag, _ := m["tag"].(string)
			if trimmed := strings.TrimSpace(tag); trimmed != "" {
				removedSet[trimmed] = true
				removedTags = append(removedTags, trimmed)
			} else {
				removedTags = append(removedTags, "<unnamed>")
			}
			continue
		}
		keptInbounds = append(keptInbounds, item)
	}
	if removedCount == 0 {
		return false, "", nil, nil
	}

	doc["inbounds"] = keptInbounds
	if routeObj, ok := doc["route"].(map[string]any); ok {
		if rules, ok := routeObj["rules"].([]any); ok && len(removedSet) > 0 {
			keptRules := make([]any, 0, len(rules))
			for _, r := range rules {
				rm, ok := r.(map[string]any)
				if !ok {
					keptRules = append(keptRules, r)
					continue
				}
				drop, updated := stripRemovedInboundsFromRule(rm, removedSet)
				if drop {
					continue
				}
				keptRules = append(keptRules, updated)
			}
			routeObj["rules"] = keptRules
		}
	}

	// 1. 留存 0600 备份。
	backupPath = kernelPath + Protect443BackupSuffix
	if err := atomicWriteConfigFile(backupPath, raw, 0o600); err != nil {
		return false, "", nil, fmt.Errorf("写入备份 %s 失败：%w", backupPath, err)
	}

	// 2. 不转义 HTML 格式化写回 kernel.json。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return false, backupPath, removedTags, fmt.Errorf("编码自愈后的配置失败：%w", err)
	}
	if err := atomicWriteConfigFile(kernelPath, buf.Bytes(), 0o600); err != nil {
		return false, backupPath, removedTags, fmt.Errorf("写回自愈后的 %s 失败：%w", kernelPath, err)
	}
	return true, backupPath, removedTags, nil
}

func stripRemovedInboundsFromRule(rm map[string]any, removedSet map[string]bool) (drop bool, out map[string]any) {
	rawIn, exists := rm["inbound"]
	if !exists || rawIn == nil {
		return false, rm
	}
	switch v := rawIn.(type) {
	case string:
		if removedSet[strings.TrimSpace(v)] {
			return true, nil
		}
		return false, rm
	case []any:
		if len(v) == 0 {
			return false, rm
		}
		kept := make([]any, 0, len(v))
		changed := false
		for _, item := range v {
			if s, ok := item.(string); ok && removedSet[strings.TrimSpace(s)] {
				changed = true
				continue
			}
			kept = append(kept, item)
		}
		if !changed {
			return false, rm
		}
		if len(kept) == 0 {
			return true, nil
		}
		cloned := make(map[string]any, len(rm))
		for k, val := range rm {
			cloned[k] = val
		}
		cloned["inbound"] = kept
		return false, cloned
	default:
		return false, rm
	}
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("配置不是 JSON 对象")
	}
	return doc, nil
}

func listenPortIs443(v any) bool {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
		return err == nil && n == 443
	case float64:
		return x == 443
	case int:
		return x == 443
	case int64:
		return x == 443
	default:
		return false
	}
}

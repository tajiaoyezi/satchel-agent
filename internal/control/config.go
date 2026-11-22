package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/kernel"
	"github.com/satchel/satchel-agent/internal/pathguard"
)

var defaultNginxRoots = []string{"/etc/nginx", "/usr/local/nginx"}

var nginxAllowedSubdirs = []string{"conf.d", "sites-available", "sites-enabled", "servers", "stream_servers", "conf"}

var forbiddenConfigDirNames = map[string]bool{
	"cert": true, "certs": true, "ssl": true, "html": true, "keys": true, "private": true,
}

var forbiddenConfigExts = map[string]bool{
	".key": true, ".pem": true, ".crt": true, ".cer": true, ".p12": true, ".pfx": true,
	".der": true, ".jks": true, ".yaml": true, ".yml": true, ".json": true, ".db": true,
	".sqlite": true, ".log": true,
}

func registerConfigMethods(m xrpc.Methods, d Deps) {
	m[xrpc.MethodConfigStatus] = func(_ context.Context, _ json.RawMessage) (any, error) {
		return d.handleConfigStatus()
	}
	m[xrpc.MethodConfigTest] = func(_ context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.ConfigTestParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.Config) == "" {
			return nil, badParams("config 不能为空")
		}
		tags, err := kernel.Validate([]byte(p.Config))
		hash := xrpc.CanonicalConfigHash([]byte(p.Config))
		if err != nil {
			return xrpc.ConfigTestResult{
				OK:       false,
				Error:    err.Error(),
				Inbounds: []string{},
				Hash:     hash,
			}, nil
		}
		return xrpc.ConfigTestResult{
			OK:       true,
			Inbounds: tags,
			Hash:     hash,
		}, nil
	}
	m[xrpc.MethodConfigApply] = func(_ context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.ConfigApplyParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return d.handleConfigApply(p)
	}
	m[xrpc.MethodConfigFiles] = func(_ context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.ConfigFilesParams
		if len(raw) > 0 && string(raw) != "null" {
			if err := decode(raw, &p); err != nil {
				return nil, err
			}
		}
		return d.handleConfigFiles(p)
	}
	m[xrpc.MethodConfigRead] = func(_ context.Context, raw json.RawMessage) (any, error) {
		var p xrpc.ConfigReadParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return d.handleConfigRead(p)
	}
}

func (d Deps) handleConfigStatus() (xrpc.ConfigStatusResult, error) {
	d.ConfigMu.Lock()
	defer d.ConfigMu.Unlock()

	res := xrpc.ConfigStatusResult{
		Inbounds:      []string{},
		KernelRunning: d.Kernel != nil && d.Kernel.Running(),
	}
	if res.KernelRunning {
		res.KernelVersion = kernel.Version
	}
	if d.Tracker != nil {
		res.Generation = d.Tracker.Generation()
	}
	if d.ConfigDir == "" {
		return res, nil
	}
	kpath := filepath.Join(d.ConfigDir, KernelConfig)
	res.Path = kpath
	fi, err := os.Stat(kpath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("检查 %s 失败：%w", KernelConfig, err)
	}
	raw, err := os.ReadFile(kpath)
	if err != nil {
		return res, fmt.Errorf("读取 %s 失败：%w", KernelConfig, err)
	}
	mod := fi.ModTime().UTC()
	res.Exists = true
	res.Size = fi.Size()
	res.Modified = &mod
	res.Hash = xrpc.CanonicalConfigHash(raw)
	if tags, err := kernel.InboundTags(raw); err == nil {
		res.Inbounds = tags
	} else if cur := d.Inbounds.Get(); cur != nil {
		res.Inbounds = cur
	}
	return res, nil
}

func (d Deps) handleConfigApply(p xrpc.ConfigApplyParams) (xrpc.ConfigApplyResult, error) {
	if strings.TrimSpace(p.Config) == "" {
		return xrpc.ConfigApplyResult{}, badParams("config 不能为空")
	}
	if strings.TrimSpace(d.ConfigDir) == "" {
		return xrpc.ConfigApplyResult{}, badParams("节点未配置配置目录")
	}
	candidate := []byte(p.Config)
	// 同机 443 内核防抢占守卫：只要主控要求保护或节点磁盘检测到主控 443 标记，拒绝含 listen_port == 443 的候选配置。
	if p.ProtectMaster443 || HasMaster443Marker(d.nginxRoots()) {
		if has443, tags443, perr := ConfigHasPort443Inbound(candidate); perr == nil && has443 {
			return xrpc.ConfigApplyResult{}, &xrpc.Error{
				Code:    xrpc.CodeConflict,
				Message: fmt.Sprintf("主控同机 443 防抢占守卫生效，拒绝应用含 443 端口入站（%s）的配置", strings.Join(tags443, ", ")),
			}
		}
	}
	// 先在锁外执行无侵入校验：配置非法直接拒绝，不触碰磁盘与运行中内核。
	newTags, err := kernel.Validate(candidate)
	if err != nil {
		return xrpc.ConfigApplyResult{}, badParams("候选配置校验失败：%v", err)
	}
	newHash := xrpc.CanonicalConfigHash(candidate)

	d.ConfigMu.Lock()
	defer d.ConfigMu.Unlock()

	kpath := filepath.Join(d.ConfigDir, KernelConfig)
	oldData, readErr := os.ReadFile(kpath)
	existed := false
	currentHash := ""
	switch {
	case readErr == nil:
		existed = true
		currentHash = xrpc.CanonicalConfigHash(oldData)
	case !errors.Is(readErr, os.ErrNotExist):
		return xrpc.ConfigApplyResult{}, fmt.Errorf("读取当前 %s 失败：%w", KernelConfig, readErr)
	}
	wasRunning := d.Kernel != nil && d.Kernel.Running()
	oldTags := d.Inbounds.Get()

	if !p.ForceInitial && p.ExpectedCurrentHash != "" && p.ExpectedCurrentHash != currentHash {
		return xrpc.ConfigApplyResult{}, &xrpc.Error{
			Code:    xrpc.CodeConflict,
			Message: fmt.Sprintf("节点配置哈希冲突：期望 %s，当前实际为 %q", p.ExpectedCurrentHash, currentHash),
		}
	}

	if err := atomicWriteConfigFile(kpath, candidate, 0o600); err != nil {
		return xrpc.ConfigApplyResult{}, fmt.Errorf("原子写入 %s 失败：%w", KernelConfig, err)
	}

	if !p.WantRestart() || d.Kernel == nil {
		d.Inbounds.Set(newTags)
		return xrpc.ConfigApplyResult{
			Applied:       true,
			AppliedHash:   newHash,
			PreviousHash:  currentHash,
			CurrentHash:   newHash,
			Generation:    d.currentGeneration(),
			KernelRunning: d.Kernel != nil && d.Kernel.Running(),
			Inbounds:      nonNilTags(newTags),
		}, nil
	}

	if err := d.Kernel.Restart(d.kernelCtx(), candidate); err != nil {
		// 重启失败（例如端口被占或远程规则集不可达）：自动恢复旧配置（原无配置则删除新文件），原在运行则拉回旧内核。
		var rbErrs []string
		if existed {
			if werr := atomicWriteConfigFile(kpath, oldData, 0o600); werr != nil {
				rbErrs = append(rbErrs, "恢复旧文件失败: "+werr.Error())
			} else if wasRunning {
				if rerr := d.Kernel.Restart(d.kernelCtx(), oldData); rerr != nil {
					rbErrs = append(rbErrs, "重启旧内核失败: "+rerr.Error())
				}
			}
			d.Inbounds.Set(oldTags)
		} else {
			if rerr := os.Remove(kpath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				rbErrs = append(rbErrs, "清理首次失败文件失败: "+rerr.Error())
			}
			d.Inbounds.Set(nil)
		}
		rbErrStr := strings.Join(rbErrs, "; ")
		return xrpc.ConfigApplyResult{
			Applied:       false,
			PreviousHash:  currentHash,
			CurrentHash:   currentHash,
			Generation:    d.currentGeneration(),
			KernelRunning: d.Kernel.Running(),
			Inbounds:      nonNilTags(d.Inbounds.Get()),
			RolledBack:    rbErrStr == "",
			RollbackError: rbErrStr,
			Error:         err.Error(),
		}, nil
	}

	d.Inbounds.Set(newTags)
	return xrpc.ConfigApplyResult{
		Applied:       true,
		AppliedHash:   newHash,
		PreviousHash:  currentHash,
		CurrentHash:   newHash,
		Generation:    d.currentGeneration(),
		KernelRunning: d.Kernel.Running(),
		Inbounds:      nonNilTags(newTags),
	}, nil
}

func (d Deps) currentGeneration() uint64 {
	if d.Tracker == nil {
		return 0
	}
	return d.Tracker.Generation()
}

func nonNilTags(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}

func atomicWriteConfigFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (d Deps) nginxRoots() []string {
	if len(d.NginxRoots) > 0 {
		return d.NginxRoots
	}
	return defaultNginxRoots
}

func (d Deps) handleConfigFiles(p xrpc.ConfigFilesParams) (xrpc.ConfigFilesResult, error) {
	scope := strings.TrimSpace(p.Scope)
	if scope == "" {
		scope = "all"
	}
	switch scope {
	case "all", "kernel", "nginx":
	default:
		return xrpc.ConfigFilesResult{}, badParams("不支持的 scope %q（仅支持 all、kernel、nginx）", scope)
	}

	files := []xrpc.ConfigFileInfo{}
	seen := map[string]bool{}

	if (scope == "all" || scope == "kernel") && d.ConfigDir != "" {
		kpath := filepath.Join(d.ConfigDir, KernelConfig)
		if fi, err := os.Stat(kpath); err == nil && fi.Mode().IsRegular() {
			if real, perr := pathguard.PathWithinDirs(kpath, d.ConfigDir); perr == nil {
				seen[real] = true
				files = append(files, xrpc.ConfigFileInfo{
					Scope:    "kernel",
					Path:     kpath,
					Name:     KernelConfig,
					Size:     fi.Size(),
					Modified: fi.ModTime().UTC(),
				})
			}
		}
	}

	if scope == "all" || scope == "nginx" {
		allowedDirs := d.nginxAllowedDirs()
		for _, root := range d.nginxRoots() {
			// 主配置 nginx.conf
			mainConf := filepath.Join(root, "nginx.conf")
			if fi, err := os.Stat(mainConf); err == nil && fi.Mode().IsRegular() {
				if real, perr := pathguard.PathWithinDirs(mainConf, allowedDirs...); perr == nil && !seen[real] {
					seen[real] = true
					files = append(files, xrpc.ConfigFileInfo{
						Scope:    "nginx",
						Path:     mainConf,
						Name:     "nginx.conf",
						Size:     fi.Size(),
						Modified: fi.ModTime().UTC(),
					})
				}
			}
			// 白名单子目录
			for _, sub := range nginxAllowedSubdirs {
				dir := filepath.Join(root, sub)
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, ent := range entries {
					name := ent.Name()
					if strings.HasPrefix(name, ".") {
						continue
					}
					full := filepath.Join(dir, name)
					fi, err := os.Stat(full)
					if err != nil || !fi.Mode().IsRegular() {
						continue
					}
					if !isAllowedNginxFile(sub, name) {
						continue
					}
					real, err := pathguard.PathWithinDirs(full, allowedDirs...)
					if err != nil {
						continue
					}
					if d.isInForbiddenNginxSubdir(real) || !isAllowedNginxTarget(real) {
						continue
					}
					if seen[real] {
						continue
					}
					seen[real] = true
					files = append(files, xrpc.ConfigFileInfo{
						Scope:    "nginx",
						Path:     full,
						Name:     name,
						Size:     fi.Size(),
						Modified: fi.ModTime().UTC(),
					})
				}
			}
		}
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].Scope != files[j].Scope {
			return files[i].Scope < files[j].Scope
		}
		return files[i].Path < files[j].Path
	})
	return xrpc.ConfigFilesResult{Files: files}, nil
}

func (d Deps) handleConfigRead(p xrpc.ConfigReadParams) (xrpc.ConfigReadResult, error) {
	rawPath := strings.TrimSpace(p.Path)
	if rawPath == "" {
		return xrpc.ConfigReadResult{}, badParams("path 不能为空")
	}
	if err := pathguard.RejectControlChars("path", rawPath); err != nil {
		return xrpc.ConfigReadResult{}, badParams("%v", err)
	}
	limit := p.MaxBytes
	if limit <= 0 || limit > xrpc.ConfigReadMaxBytes {
		limit = xrpc.ConfigReadMaxBytes
	}

	scope, resolved, err := d.resolveReadableConfigPath(rawPath)
	if err != nil {
		return xrpc.ConfigReadResult{}, &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("配置文件 %q 不存在或不在只读白名单内", rawPath)}
	}
	fi, err := os.Stat(resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return xrpc.ConfigReadResult{}, &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("配置文件 %q 不存在", rawPath)}
	}
	f, err := os.Open(resolved)
	if err != nil {
		return xrpc.ConfigReadResult{}, &xrpc.Error{Code: xrpc.CodeNotFound, Message: fmt.Sprintf("无法打开配置文件 %q", rawPath)}
	}
	defer f.Close()

	buf, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return xrpc.ConfigReadResult{}, fmt.Errorf("读取配置文件失败：%w", err)
	}
	truncated := false
	if len(buf) > limit {
		buf = buf[:limit]
		truncated = true
	}
	hash := ""
	if !truncated {
		hash = xrpc.CanonicalConfigHash(buf)
	}
	return xrpc.ConfigReadResult{
		Scope:     scope,
		Path:      rawPath,
		Content:   string(buf),
		Size:      fi.Size(),
		Modified:  fi.ModTime().UTC(),
		Truncated: truncated,
		Hash:      hash,
	}, nil
}

func (d Deps) resolveReadableConfigPath(target string) (scope string, resolved string, err error) {
	// 1. kernel 作用域：严格限定为 filepath.Join(ConfigDir, "kernel.json")，绝不放行 config.yaml / limiter-state.json 等。
	if d.ConfigDir != "" {
		wantKernel := filepath.Join(d.ConfigDir, KernelConfig)
		if realTarget, perr := pathguard.PathWithinDirs(target, d.ConfigDir); perr == nil {
			if realWant, werr := pathguard.PathWithinDirs(wantKernel, d.ConfigDir); werr == nil && realTarget == realWant {
				return "kernel", realTarget, nil
			}
		}
	}

	// 2. nginx 作用域：严格限定为 nginx.conf 及白名单子目录下的配置文件，且软链解析后仍落在白名单内、不在敏感目录、不含敏感后缀。
	allowedDirs := d.nginxAllowedDirs()
	if len(allowedDirs) == 0 {
		return "", "", os.ErrNotExist
	}
	realTarget, perr := pathguard.PathWithinDirs(target, allowedDirs...)
	if perr != nil {
		return "", "", perr
	}
	if d.isInForbiddenNginxSubdir(realTarget) || !isAllowedNginxTarget(realTarget) {
		return "", "", os.ErrPermission
	}
	// 确认目标确实是 root/nginx.conf 或落在某允许子目录之下（排除 root 下其它任意文件）。
	for _, root := range d.nginxRoots() {
		if realMain, err := pathguard.PathWithinDirs(filepath.Join(root, "nginx.conf"), root); err == nil && realTarget == realMain {
			return "nginx", realTarget, nil
		}
		for _, sub := range nginxAllowedSubdirs {
			subDir := filepath.Join(root, sub)
			if _, err := pathguard.PathWithinDirs(realTarget, subDir); err == nil {
				if isAllowedNginxFile(sub, filepath.Base(realTarget)) {
					return "nginx", realTarget, nil
				}
			}
		}
	}
	return "", "", os.ErrPermission
}

func (d Deps) nginxAllowedDirs() []string {
	var dirs []string
	for _, root := range d.nginxRoots() {
		if fi, err := os.Stat(root); err == nil && fi.IsDir() {
			dirs = append(dirs, root)
		}
	}
	return dirs
}

// isInForbiddenNginxSubdir 仅检查位于各 nginx 根目录之下的相对路径段（不误判宿主机父路径如 macOS /private/var）。
func (d Deps) isInForbiddenNginxSubdir(realPath string) bool {
	for _, root := range d.nginxRoots() {
		realRoot, err := pathguard.PathWithinDirs(root, root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(realRoot, realPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
			if forbiddenConfigDirNames[strings.ToLower(seg)] {
				return true
			}
		}
		return false
	}
	return true
}

func isAllowedNginxFile(subdir, name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(name))
	if forbiddenConfigExts[ext] {
		return false
	}
	if name == "nginx.conf" || ext == ".conf" {
		return true
	}
	// Debian/Ubuntu nginx sites-available/sites-enabled 常见无后缀站点配置文件（如 default）。
	if (subdir == "sites-available" || subdir == "sites-enabled") && ext == "" {
		return true
	}
	return false
}

func isAllowedNginxTarget(realPath string) bool {
	base := filepath.Base(realPath)
	if strings.HasPrefix(base, ".") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(base))
	if forbiddenConfigExts[ext] {
		return false
	}
	return base == "nginx.conf" || ext == ".conf" || ext == ""
}

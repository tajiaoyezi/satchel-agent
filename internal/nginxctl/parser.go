package nginxctl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/satchel/satchel/pkg/xrpc"

	"github.com/satchel/satchel-agent/internal/pathguard"
)

var (
	domainSafeRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	listen443Re  = regexp.MustCompile(`(?m)^\s*listen\s+(?:\[::\]:|\*:|[0-9.]+:)?443(?:\s|;)`)
)

// HasManagedHeader 判断一段配置文件首条非空行是否以 # satchel-managed: 开头。
func HasManagedHeader(content string) bool {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		return strings.HasPrefix(trimmed, xrpc.SatchelManagedHeader)
	}
	return false
}

// HasPort443Listen 检测 nginx 配置文本是否直接声明监听 443 端口。
func HasPort443Listen(conf string) bool {
	return listen443Re.MatchString(conf)
}

func sanitizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !domainSafeRe.MatchString(d) {
		return "", fmt.Errorf("站点域名 %q 不合法", raw)
	}
	return d, nil
}

// ListServers 扫描白名单 nginx 目录（HTTP: servers/conf.d/sites-enabled；stream: stream_servers），
// 解析全部 server 块并标明是否 Satchel 纳管。
func (c *Controller) ListServers() (xrpc.NginxServersResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blocks := make([]xrpc.NginxServerBlock, 0)
	seenReal := map[string]bool{}

	scanDir := func(sub, kind string) {
		dir := filepath.Join(c.rootDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			ext := strings.ToLower(filepath.Ext(name))
			if sub != "sites-enabled" && ext != ".conf" {
				continue
			}
			if sub == "sites-enabled" && ext != "" && ext != ".conf" {
				continue
			}
			full := filepath.Join(dir, name)
			realPath, err := pathguard.PathWithinDirs(full, c.rootDir)
			if err != nil || seenReal[realPath] {
				continue
			}
			fi, err := os.Stat(realPath)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			raw, err := os.ReadFile(realPath)
			if err != nil {
				continue
			}
			seenReal[realPath] = true
			content := string(raw)
			parsed := parseServerBlocks(content, kind, full, HasManagedHeader(content))
			blocks = append(blocks, parsed...)
		}
	}

	scanDir("servers", "http")
	scanDir("conf.d", "http")
	scanDir("sites-enabled", "http")
	scanDir("stream_servers", "stream")

	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Kind != blocks[j].Kind {
			return blocks[i].Kind < blocks[j].Kind
		}
		if blocks[i].ConfPath != blocks[j].ConfPath {
			return blocks[i].ConfPath < blocks[j].ConfPath
		}
		ni := strings.Join(blocks[i].ServerNames, ",")
		nj := strings.Join(blocks[j].ServerNames, ",")
		return ni < nj
	})
	return xrpc.NginxServersResult{Servers: blocks}, nil
}

// ScanWebsites 扫描节点 nginx HTTP 站点目录，返回已纳管与未纳管站点的结构化清单。
func (c *Controller) ScanWebsites() (xrpc.NginxWebsitesScanResult, error) {
	all, err := c.ListServers()
	if err != nil {
		return xrpc.NginxWebsitesScanResult{}, err
	}
	sites := make([]xrpc.ScannedWebsite, 0)
	for _, b := range all.Servers {
		if b.Kind != "http" {
			continue
		}
		typ := "unknown"
		target := ""
		if b.ProxyPass != "" {
			typ = "proxy"
			target = b.ProxyPass
		} else if b.Root != "" {
			typ = "static"
			target = b.Root
		}
		names := b.ServerNames
		if len(names) == 0 {
			names = []string{"_"}
		}
		for _, dom := range names {
			d := strings.ToLower(strings.TrimSpace(dom))
			if d == "" {
				continue
			}
			sites = append(sites, xrpc.ScannedWebsite{
				Domain:      d,
				ConfPath:    b.ConfPath,
				Managed:     b.Managed,
				Type:        typ,
				Target:      target,
				ListenPorts: b.ListenPorts,
				HasSSL:      b.HasSSL,
				Root:        b.Root,
				ProxyPass:   b.ProxyPass,
			})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Domain != sites[j].Domain {
			return sites[i].Domain < sites[j].Domain
		}
		return sites[i].ConfPath < sites[j].ConfPath
	})
	return xrpc.NginxWebsitesScanResult{Sites: sites}, nil
}

func streamListensOnPort(content, portStr string) bool {
	blocks := parseServerBlocks(content, "stream", "", false)
	for _, b := range blocks {
		for _, p := range b.ListenPorts {
			if p == portStr {
				return true
			}
		}
	}
	return false
}

// parseServerBlocks 纯 Go 解析单个配置文件中的所有 server { ... } 块（跳过注释与字符串字面量内花括号）。
func parseServerBlocks(content, kind, confPath string, managed bool) []xrpc.NginxServerBlock {
	stripped := stripComments(content)
	var out []xrpc.NginxServerBlock
	n := len(stripped)
	i := 0
	for i < n {
		// 跳过空白
		for i < n && isSpace(stripped[i]) {
			i++
		}
		if i >= n {
			break
		}
		if matchWord(stripped, i, "server") {
			j := i + len("server")
			for j < n && isSpace(stripped[j]) {
				j++
			}
			if j < n && stripped[j] == '{' {
				end := findMatchingBrace(stripped, j)
				if end > j {
					body := stripped[j+1 : end]
					out = append(out, extractServerBlock(body, kind, confPath, managed))
					i = end + 1
					continue
				}
			}
		}
		// 若遇到外层 http/stream 块，跳过关键字与开括号继续深入其内部找 server 块。
		if matchWord(stripped, i, "http") || matchWord(stripped, i, "stream") {
			j := i
			for j < n && !isSpace(stripped[j]) && stripped[j] != '{' {
				j++
			}
			for j < n && isSpace(stripped[j]) {
				j++
			}
			if j < n && stripped[j] == '{' {
				i = j + 1
				continue
			}
		}
		i++
	}
	return out
}

func extractServerBlock(body, kind, confPath string, managed bool) xrpc.NginxServerBlock {
	blk := xrpc.NginxServerBlock{
		Kind:        kind,
		ConfPath:    confPath,
		Managed:     managed,
		ServerNames: []string{},
		ListenPorts: []string{},
	}
	portSet := map[string]bool{}
	nameSet := map[string]bool{}

	for _, stmt := range splitStatements(body) {
		fields := strings.Fields(stmt)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "listen":
			if len(fields) >= 2 {
				port := extractListenPort(fields[1])
				if port != "" && !portSet[port] {
					portSet[port] = true
					blk.ListenPorts = append(blk.ListenPorts, port)
				}
				for _, opt := range fields[2:] {
					if opt == "ssl" {
						blk.HasSSL = true
					}
				}
			}
		case "ssl_certificate":
			if len(fields) >= 2 {
				blk.HasSSL = true
			}
		case "server_name":
			for _, nm := range fields[1:] {
				nm = strings.Trim(nm, `"'`)
				if nm != "" && !nameSet[nm] {
					nameSet[nm] = true
					blk.ServerNames = append(blk.ServerNames, nm)
				}
			}
		case "root":
			if len(fields) >= 2 && blk.Root == "" {
				blk.Root = strings.Trim(fields[1], `"'`)
			}
		case "proxy_pass":
			if len(fields) >= 2 && blk.ProxyPass == "" {
				blk.ProxyPass = strings.Trim(fields[1], `"'`)
			}
		}
	}
	return blk
}

func extractListenPort(token string) string {
	token = strings.Trim(token, `"'`)
	if idx := strings.LastIndex(token, ":"); idx >= 0 {
		token = token[idx+1:]
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return ""
		}
	}
	return token
}

func splitStatements(body string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if quote != 0 {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < len(body) {
				i++
				cur.WriteByte(body[i])
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			cur.WriteByte(ch)
			continue
		}
		if ch == ';' || ch == '{' || ch == '}' {
			s := strings.TrimSpace(cur.String())
			if s != "" {
				out = append(out, s)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

func stripComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	var quote byte
	inComment := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inComment {
			if ch == '\n' {
				inComment = false
				b.WriteByte(ch)
			}
			continue
		}
		if quote != 0 {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			b.WriteByte(ch)
			continue
		}
		if ch == '#' {
			inComment = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func findMatchingBrace(s string, openIdx int) int {
	depth := 0
	var quote byte
	for i := openIdx; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func findHTTPBlockClose(content string) int {
	// 在原文上同步扫描（跳过注释），返回 http { ... } 闭合花括号的字节索引。
	var quote byte
	inComment := false
	n := len(content)
	for i := 0; i < n; i++ {
		ch := content[i]
		if inComment {
			if ch == '\n' {
				inComment = false
			}
			continue
		}
		if quote != 0 {
			if ch == '\\' && i+1 < n {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '#' {
			inComment = true
			continue
		}
		if matchWord(content, i, "http") {
			j := i + 4
			for j < n && isSpace(content[j]) {
				j++
			}
			if j < n && content[j] == '{' {
				// 扫描配对闭合括号（同样跳过注释）
				depth := 0
				q := byte(0)
				cm := false
				for k := j; k < n; k++ {
					c2 := content[k]
					if cm {
						if c2 == '\n' {
							cm = false
						}
						continue
					}
					if q != 0 {
						if c2 == '\\' && k+1 < n {
							k++
							continue
						}
						if c2 == q {
							q = 0
						}
						continue
					}
					if c2 == '"' || c2 == '\'' {
						q = c2
						continue
					}
					if c2 == '#' {
						cm = true
						continue
					}
					if c2 == '{' {
						depth++
					} else if c2 == '}' {
						depth--
						if depth == 0 {
							return k
						}
					}
				}
			}
		}
	}
	return -1
}

func matchWord(s string, pos int, word string) bool {
	if pos+len(word) > len(s) || s[pos:pos+len(word)] != word {
		return false
	}
	if pos > 0 && isIdent(s[pos-1]) {
		return false
	}
	end := pos + len(word)
	if end < len(s) && isIdent(s[end]) {
		return false
	}
	return true
}

func isIdent(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// Package buildinfo 是 satchel-agent 二进制的构建信息：版本号、commit 与构建时间。
// 三个变量由发布流水线注入：
//
//	go build -ldflags "-X github.com/satchel/satchel-agent/internal/buildinfo.Version=1.2.3 ..."
//
// 直接 go build 时保持默认值。与主控 satchel 的 internal/base/buildinfo 同形，发布线一份 ldflags 写法通吃。
package buildinfo

var (
	// Version 是版本号，发布时注入 tag 名。
	Version = "0.0.0-dev"
	// Commit 是构建所用的 git commit。
	Commit = "unknown"
	// Date 是构建时间。
	Date = "unknown"
)

// Info 是三项的快照，字段名就是 JSON 输出的字段名。
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Get 返回当前二进制的构建信息。
func Get() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

//go:build falsification

package kernel_test

import "time"

// 完整版：完全按技术方案第 13 章的口径——30 秒时间窗、100 / 60 / 40 / 30 / 20 MB（改动多久生效见 applyWait，两档一样）。
var prof = profile{
	name:   "完整版",
	warmup: 2 * time.Second,
	window: 30 * time.Second,
	mib:    1 << 20,
}

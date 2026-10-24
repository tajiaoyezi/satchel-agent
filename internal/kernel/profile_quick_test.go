//go:build !falsification

package kernel_test

import "time"

// 快速版：查行为对不对，时间窗与数据量都缩小，CI 每次提交都跑。结论以完整版（-tags falsification）为准。
var prof = profile{
	name:   "快速版",
	warmup: time.Second,
	window: 3 * time.Second,
	mib:    1 << 20 / 10,
}

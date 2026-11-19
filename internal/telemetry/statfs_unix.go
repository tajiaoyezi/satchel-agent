//go:build unix

package telemetry

import "golang.org/x/sys/unix"

func defaultStatFS(path string) (total, avail int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = int64(st.Blocks * bsize)
	avail = int64(st.Bavail * bsize)
	return total, avail, nil
}

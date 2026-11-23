//go:build !windows

package execctl

import (
	"os/exec"
	"syscall"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func currentPGID() int {
	return syscall.Getpgrp()
}

func pgidAlive(pgid int) bool {
	if pgid <= 1 || pgid == currentPGID() {
		return false
	}
	err := syscall.Kill(-pgid, 0)
	return err == nil || err == syscall.EPERM
}

func killProcessGroup(pgid int) {
	if pgid <= 1 || pgid == currentPGID() {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !pgidAlive(pgid) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

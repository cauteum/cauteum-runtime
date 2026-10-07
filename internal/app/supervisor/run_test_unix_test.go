//go:build !windows

package supervisor

import (
	"os"
	"syscall"
)

func terminateSupervisorProcess() error {
	return syscall.Kill(os.Getpid(), syscall.SIGTERM)
}

func checkProcessGone(pid int) error {
	err := syscall.Kill(pid, 0)
	if err == syscall.ESRCH {
		return nil
	}
	if err == nil {
		return syscall.EEXIST
	}
	return err
}

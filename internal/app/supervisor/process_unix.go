//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"os"
	"syscall"
)

func enableChildSubreaper() error { return nil }

func signalWorkloadGroup(pid int, signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return syscall.EINVAL
	}
	return syscall.Kill(-pid, sig)
}

func processGroupExists(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || err == syscall.EPERM
}

func reapAdoptedChildren(int) {}

//go:build linux

package supervisor

import (
	"syscall"
	"testing"
)

func enableTestSubreaper(t *testing.T) {
	t.Helper()
	const prSetChildSubreaper = 36
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatalf("enable test child subreaper: %v", errno)
	}
}

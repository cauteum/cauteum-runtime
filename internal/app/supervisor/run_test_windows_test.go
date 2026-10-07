//go:build windows

package supervisor

import "testing"

func terminateSupervisorProcess() error { return nil }

func checkProcessGone(int) error { return nil }

func enableTestSubreaper(*testing.T) {}

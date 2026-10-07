//go:build windows

package supervisor

func terminateSupervisorProcess() error { return nil }

func checkProcessGone(int) error { return nil }

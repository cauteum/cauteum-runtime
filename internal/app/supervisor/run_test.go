package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/whaleshell/whaleshell-runtime/supervisorcontrol"
)

func TestRunReportsAndFinalizesNaturalMainProcessExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	var operations []string
	var operationsMu sync.Mutex
	server, err := supervisorcontrol.Start(ctx, path, func(_ context.Context, request supervisorcontrol.Request) supervisorcontrol.Response {
		operationsMu.Lock()
		operations = append(operations, request.Operation)
		defer operationsMu.Unlock()
		switch request.Operation {
		case supervisorcontrol.OperationBegin:
			return supervisorcontrol.Response{InstanceID: "process-instance"}
		case supervisorcontrol.OperationReport:
			if request.InstanceID != "process-instance" || request.ExitCode != 7 {
				return supervisorcontrol.Response{Error: "incorrect report"}
			}
		case supervisorcontrol.OperationFinalize:
			if len(operations) < 3 || operations[1] != supervisorcontrol.OperationReport {
				return supervisorcontrol.Response{Error: "finalized before report"}
			}
		default:
			return supervisorcontrol.Response{Error: "unexpected operation"}
		}
		return supervisorcontrol.Response{InstanceID: "process-instance"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	t.Setenv("WHALESHELL_SUPERVISOR_CONTROL_SOCKET", path)
	code, err := Run([]string{"sh", "-c", "exit 7"})
	if err != nil || code != 7 {
		t.Fatalf("Run=(%d,%v), want (7,nil)", code, err)
	}
	want := []string{supervisorcontrol.OperationBegin, supervisorcontrol.OperationReport, supervisorcontrol.OperationFinalize}
	operationsMu.Lock()
	defer operationsMu.Unlock()
	if !slices.Equal(operations, want) {
		t.Fatalf("lifecycle operations=%v, want %v", operations, want)
	}
}

func TestParseArgsRequiresSeparatorAndPreservesArgv(t *testing.T) {
	if _, err := ParseArgs([]string{"sh", "-c", "echo unsafe"}); err == nil {
		t.Fatal("command without explicit separator was accepted")
	}
	got, err := ParseArgs([]string{"--", "sh", "-c", "printf '%s'", "a b"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sh", "-c", "printf '%s'", "a b"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv=%q, want %q", got, want)
	}
}

func TestRunForwardsTerminationSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group signal forwarding is Unix-specific")
	}
	done := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := Run([]string{"sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"})
		done <- struct {
			code int
			err  error
		}{code, err}
	}()
	time.Sleep(100 * time.Millisecond)
	if err := terminateSupervisorProcess(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 0 {
			t.Fatalf("Run()=(%d,%v), want graceful child exit", result.code, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("workload did not exit after supervisor received SIGTERM")
	}
}

func TestRunKillsOrphanedWorkloadDescendants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("orphan process groups are Unix-specific")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	done := make(chan struct {
		code int
		err  error
	}, 1)
	command := fmt.Sprintf("(trap '' TERM; exec sleep 30) & echo $! > %q; trap 'exit 0' TERM; wait", pidFile)
	go func() {
		code, err := Run([]string{"sh", "-c", command})
		done <- struct {
			code int
			err  error
		}{code, err}
	}()

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidFile); err == nil {
			childPID, _ = strconv.Atoi(string(bytes.TrimSpace(data)))
			if childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("workload child did not publish its pid")
	}
	if err := terminateSupervisorProcess(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 0 {
			t.Fatalf("Run()=(%d,%v), want graceful main process exit", result.code, result.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Run did not finish after terminating the workload process group")
	}

	if err := checkProcessGone(childPID); err != nil {
		t.Fatalf("orphaned workload child pid %d remains: %v", childPID, err)
	}
}

func TestRunReturnsWorkloadExitCode(t *testing.T) {
	code, err := Run([]string{"sh", "-c", "exit 17"})
	if err != nil || code != 17 {
		t.Fatalf("Run()=(%d,%v), want (17,nil)", code, err)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	if code, err := Run(nil); err == nil || code != 2 {
		t.Fatalf("Run(nil)=(%d,%v), want usage error", code, err)
	}
}

package supervisorcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func TestCallRoundTripsAndServerRemovesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocketPath(t)
	server, err := Start(ctx, path, func(_ context.Context, request Request) Response {
		if request.Operation != OperationReport || request.InstanceID != "instance-a" || request.ExitCode != 7 {
			return Response{Error: "unexpected lifecycle request"}
		}
		return Response{InstanceID: "instance-a"}
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("socket mode/stat=(%v,%v); want 0600", info, err)
	}
	response, err := Call(context.Background(), path, Request{Operation: OperationReport, InstanceID: "instance-a", ExitCode: 7})
	if err != nil || response.InstanceID != "instance-a" {
		t.Fatalf("Call=(%+v,%v)", response, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Close error=%v; want not-exist", err)
	}
}

func TestStartRejectsActiveAndNonSocketPaths(t *testing.T) {
	path := testSocketPath(t)
	server, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} }); err == nil {
		t.Fatal("Start replaced an active control socket")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} }); err == nil {
		t.Fatal("Start replaced a non-socket path")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "keep" {
		t.Fatalf("non-socket path content=%q err=%v", body, err)
	}
}

func TestCallHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocketPath(t)
	server, err := Start(ctx, path, func(ctx context.Context, _ Request) Response {
		<-ctx.Done()
		return Response{Error: "cancelled"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = server.Close() }()
	callCtx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	if _, err := Call(callCtx, path, Request{Operation: OperationBegin}); err == nil {
		t.Fatal("Call unexpectedly ignored its deadline")
	}
}

// Package supervisorcontrol provides a private Unix-socket bridge between the
// sandbox PID 1 and the authenticated proxy-sidecar supervisor client.
package supervisorcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	OperationBegin    = "begin"
	OperationReport   = "report_main_process_exit"
	OperationFinalize = "finalize_main_process_exit"
	maxMessageBytes   = 8 << 10
)

// Request is the versioned-by-operation local lifecycle contract. It carries
// no gateway bearer token; authentication remains in the proxy sidecar.
type Request struct {
	Operation  string `json:"operation"`
	InstanceID string `json:"instance_id,omitempty"`
	ExitCode   int32  `json:"exit_code,omitempty"`
}

// Response returns the sidecar's current process instance or RPC result.
type Response struct {
	InstanceID string `json:"instance_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Handler executes one request from PID 1.
type Handler func(context.Context, Request) Response

// Server serves lifecycle requests on an owner-only Unix socket.
type Server struct {
	listener *net.UnixListener
	path     string
	fileInfo os.FileInfo
	once     sync.Once
	done     chan struct{}
}

// Start binds the socket synchronously, then accepts requests until ctx ends.
func Start(ctx context.Context, path string, handler Handler) (*Server, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || handler == nil {
		return nil, errors.New("supervisorcontrol: an absolute clean socket path and handler are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("supervisorcontrol: create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("supervisorcontrol: refusing to replace a non-socket path")
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("supervisorcontrol: another control server is already listening")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("supervisorcontrol: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("supervisorcontrol: inspect socket path: %w", err)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("supervisorcontrol: restrict socket permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("supervisorcontrol: inspect bound socket: %w", err)
	}
	server := &Server{listener: listener, path: path, fileInfo: info, done: make(chan struct{})}
	go server.serve(ctx, handler)
	return server, nil
}

func (s *Server) serve(ctx context.Context, handler Handler) {
	defer close(s.done)
	semaphore := make(chan struct{}, 16)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-s.done:
		}
	}()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer conn.Close()
				s.handle(ctx, conn, handler)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn, handler Handler) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(io.LimitReader(conn, maxMessageBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxMessageBytes {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid or oversized request"})
		return
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	response := handler(ctx, request)
	_ = json.NewEncoder(conn).Encode(response)
}

// Close stops accepting requests and removes only this server's socket inode.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		closeErr = s.listener.Close()
		<-s.done
		if info, err := os.Lstat(s.path); err == nil && os.SameFile(info, s.fileInfo) {
			if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && closeErr == nil {
				closeErr = removeErr
			}
		}
	})
	return closeErr
}

// Call sends one request and waits for its response using ctx for dial and I/O
// deadlines. A response-level error is returned as a Go error.
func Call(ctx context.Context, path string, request Request) (Response, error) {
	var response Response
	if strings.TrimSpace(path) == "" {
		return response, errors.New("supervisorcontrol: socket path is required")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

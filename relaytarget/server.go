// Package relaytarget provides sandbox-side loopback dialing for the proxy
// sidecar's gateway relay. The Unix socket lives in the shared SSH volume.
package relaytarget

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cautem/cauteum-core/relayproto"
	"github.com/cautem/slogx"
)

const maxTargetLine = 4096

type Server struct {
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	log      *slog.Logger
}

// Listen binds a private Unix socket and begins serving validated loopback
// TCP requests. Call Close when the sandbox supervisor exits.
func Listen(socketPath string) (*Server, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || filepath.Dir(socketPath) == "/" {
		return nil, errors.New("relaytarget: socket path must be a clean absolute path below a directory")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("relaytarget: create socket directory: %w", err)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("relaytarget: refusing to replace non-socket path")
		}
		probe, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return nil, errors.New("relaytarget: another server already owns the socket")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("relaytarget: existing socket cannot be safely replaced: %w", dialErr)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("relaytarget: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("relaytarget: inspect socket path: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("relaytarget: listen: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("relaytarget: secure socket: %w", err)
	}
	log := slog.Default().With(slog.String("component", "relaytarget"), slog.String("op", "relaytarget.listen"))
	s := &Server{listener: listener, done: make(chan struct{}), conns: make(map[net.Conn]struct{}), log: log}
	log.Info("relay target listener started", slog.String("socket", socketPath))
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.log.Error("relay target accept failed", slogx.Err(err))
			return
		}
		s.wg.Add(1)
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.serve(conn)
		}()
	}
}

func (s *Server) serve(local net.Conn) {
	defer local.Close()
	_ = local.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(local, maxTargetLine).ReadSlice('\n')
	if err != nil || len(line) > maxTargetLine {
		s.log.Debug("relay target request rejected", slog.String("reason", "invalid request"))
		_, _ = io.WriteString(local, "ERR invalid target\n")
		return
	}
	target, err := validateTarget(strings.TrimSuffix(string(line), "\n"))
	if err != nil {
		s.log.Debug("relay target request rejected", slog.String("reason", "target is not allowed"))
		_, _ = io.WriteString(local, "ERR invalid target\n")
		return
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	remote, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	if err != nil {
		s.log.Warn("sandbox relay target dial failed", slog.String("target", target), slogx.Err(err))
		_, _ = io.WriteString(local, "ERR target unavailable\n")
		return
	}
	defer remote.Close()
	if _, err := io.WriteString(local, "OK\n"); err != nil {
		s.log.Debug("relay target client disconnected before ready", slogx.Err(err))
		return
	}
	_ = local.SetDeadline(time.Time{})
	s.log.Debug("relay target connected", slog.String("target", target))
	if err := relayproto.Pipe(local, remote); err != nil {
		s.log.Warn("relay target stream ended with error", slog.String("target", target), slogx.Err(err))
	}
}

func validateTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("unsupported target")
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", errors.New("unsupported target")
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portText, 10, 16)
	if ip == nil || !ip.IsLoopback() || err != nil || port == 0 {
		return "", errors.New("target must be loopback TCP")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), nil
}

// Close stops new requests, waits for active target streams, and removes the
// socket only if it still refers to this server's filesystem entry.
func (s *Server) Close() error {
	var closeErr error
	s.once.Do(func() {
		close(s.done)
		closeErr = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if addr := s.listener.Addr(); addr != nil {
			if info, err := os.Lstat(addr.String()); err == nil && info.Mode()&os.ModeSocket != 0 {
				if err := os.Remove(addr.String()); closeErr == nil && err != nil {
					closeErr = err
				}
			}
		}
	})
	return closeErr
}

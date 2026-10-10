// Package supervisor runs a sandbox workload as the container's PID 1.
//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cauteum-haven/cauteum-runtime/relaytarget"
	"github.com/cauteum-haven/cauteum-runtime/supervisorcontrol"
)

// Run starts a parsed workload argv, forwards termination signals to its
// process group, reaps adopted children, and returns the workload exit code.
func Run(args []string) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: cauteum-supervisor -- <command> [args...]")
	}
	var targetServer *relaytarget.Server
	if socketPath := strings.TrimSpace(os.Getenv("CAUTEUM_RELAY_TARGET_SOCKET")); socketPath != "" {
		var err error
		targetServer, err = relaytarget.Listen(socketPath)
		if err != nil {
			return 125, fmt.Errorf("cauteum-supervisor: start TCP target relay: %w", err)
		}
		defer func() {
			if err := targetServer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "cauteum-supervisor: stop TCP target relay: %v\n", err)
			}
		}()
	}
	controlSocket := strings.TrimSpace(os.Getenv("CAUTEUM_SUPERVISOR_CONTROL_SOCKET"))
	instanceID := ""
	if controlSocket != "" {
		var err error
		instanceID, err = beginProcessInstance(controlSocket)
		if err != nil {
			return 125, fmt.Errorf("cauteum-supervisor: begin OpenShell process instance: %w", err)
		}
	}
	command := exec.Command(args[0], args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := enableChildSubreaper(); err != nil {
		return 125, fmt.Errorf("cauteum-supervisor: enable child reaping: %w", err)
	}
	if err := command.Start(); err != nil {
		return 127, fmt.Errorf("cauteum-supervisor: start workload: %w", err)
	}

	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	shutdownRequested := false

	for {
		select {
		case signal := <-signals:
			if signal == syscall.SIGCHLD {
				reapAdoptedChildren(command.Process.Pid)
				continue
			}
			shutdownRequested = true
			if err := signalWorkloadGroup(command.Process.Pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
				fmt.Fprintf(os.Stderr, "cauteum-supervisor: forward %s: %v\n", signal, err)
			}
		case err := <-result:
			stopWorkloadGroup(command.Process.Pid)
			for {
				select {
				case signal := <-signals:
					if signal != syscall.SIGCHLD {
						shutdownRequested = true
					}
				default:
					goto signalsDrained
				}
			}
		signalsDrained:
			code, waitErr := workloadExitCode(err)
			if controlSocket != "" && instanceID != "" && !shutdownRequested && waitErr == nil {
				if err := reportProcessExitUntilAck(controlSocket, instanceID, int32(code)); err != nil {
					return 125, err
				}
				if err := finalizeProcessExitUntilAck(controlSocket, instanceID); err != nil {
					return 125, err
				}
			}
			return code, waitErr
		}
	}
}

func workloadExitCode(err error) (int, error) {
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok {
				if status.Signaled() {
					return 128 + int(status.Signal()), nil
				}
				return status.ExitStatus(), nil
			}
		}
		return 125, fmt.Errorf("cauteum-supervisor: wait for workload: %w", err)
	}
	return 0, nil
}

func beginProcessInstance(socket string) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	delay := 100 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		response, err := supervisorcontrol.Call(ctx, socket, supervisorcontrol.Request{Operation: supervisorcontrol.OperationBegin})
		cancel()
		if err == nil && response.InstanceID != "" {
			return response.InstanceID, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("sidecar returned an empty instance id")
			}
			return "", err
		}
		time.Sleep(delay)
		if delay < time.Second {
			delay *= 2
		}
	}
}

func reportProcessExitUntilAck(socket, instanceID string, exitCode int32) error {
	return lifecycleUntilAck(socket, supervisorcontrol.Request{Operation: supervisorcontrol.OperationReport, InstanceID: instanceID, ExitCode: exitCode}, "report main process exit")
}

func finalizeProcessExitUntilAck(socket, instanceID string) error {
	return lifecycleUntilAck(socket, supervisorcontrol.Request{Operation: supervisorcontrol.OperationFinalize, InstanceID: instanceID}, "finalize main process exit")
}

func lifecycleUntilAck(socket string, request supervisorcontrol.Request, operation string) error {
	delay := 250 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		_, err := supervisorcontrol.Call(ctx, socket, request)
		cancel()
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "cauteum-supervisor: %s failed; retrying: %v\n", operation, err)
		time.Sleep(delay)
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

// ParseArgs accepts only an explicit separator, preserving workload argv
// boundaries and ensuring supervisor flags cannot be confused with payload.
func ParseArgs(args []string) ([]string, error) {
	for i, arg := range args {
		if arg == "--" {
			if i+1 == len(args) {
				return nil, fmt.Errorf("cauteum-supervisor: command after -- is empty")
			}
			return args[i+1:], nil
		}
	}
	return nil, fmt.Errorf("cauteum-supervisor: expected -- before workload command")
}

const shutdownGrace = 2 * time.Second

func stopWorkloadGroup(pid int) {
	_ = signalWorkloadGroup(pid, syscall.SIGTERM)
	deadline := time.NewTimer(shutdownGrace)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for processGroupExists(pid) {
		select {
		case <-ticker.C:
			reapAdoptedChildren(pid)
		case <-deadline.C:
			_ = signalWorkloadGroup(pid, syscall.SIGKILL)
			for processGroupExists(pid) {
				reapAdoptedChildren(pid)
				time.Sleep(10 * time.Millisecond)
			}
			return
		}
	}
}

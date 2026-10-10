// Package wsinit is the composition root for cauteum-init.
package wsinit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cauteum-haven/cauteum-core/policy"
	"github.com/cauteum-haven/cauteum-runtime/internal/harden"
)

func Run(args []string) error {
	policyPath := os.Getenv("CAUTEUM_POLICY")
	mode := harden.Mode("")
	probe := false
	noDrop := false
	var cmd []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i >= len(args) {
				return fmt.Errorf("cauteum-init: --policy needs a value")
			}
			policyPath = args[i]
		case "--mode":
			i++
			if i >= len(args) {
				return fmt.Errorf("cauteum-init: --mode needs a value")
			}
			mode = harden.Mode(args[i])
		case "--probe":
			probe = true
		case "--no-drop":
			noDrop = true
		case "--":
			cmd = args[i+1:]
			i = len(args)
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: cauteum-init [--probe] [--policy PATH] [--mode best_effort|required] [--no-drop] -- <cmd>...\n")
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("cauteum-init: unknown flag %q", args[i])
			}
			cmd = args[i:]
			i = len(args)
		}
	}

	if probe {
		res := harden.Probe()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.LandlockABI == 0 && res.LandlockError != "" {
			os.Exit(2)
		}
		return nil
	}

	var doc policy.Document
	if policyPath != "" {
		abs, err := filepath.Abs(policyPath)
		if err != nil {
			return err
		}
		doc, err = policy.Load(abs)
		if err != nil {
			return fmt.Errorf("cauteum-init: policy: %w", err)
		}
		if err := doc.Validate(); err != nil {
			return fmt.Errorf("cauteum-init: policy: %w", err)
		}
	} else {
		doc = policy.Document{Version: 1}
	}
	if mode == "" {
		mode = harden.ModeFromPolicy(doc)
	}

	res, err := harden.Apply(context.Background(), harden.Options{
		Doc:    doc,
		Mode:   mode,
		Log:    os.Stderr,
		NoDrop: noDrop,
	})
	if err != nil {
		return err
	}
	_ = res

	if len(cmd) == 0 {
		return fmt.Errorf("cauteum-init: missing command (use -- <cmd>...)")
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		bin = cmd[0]
	}
	return syscall.Exec(bin, cmd, workloadEnvironment(os.Environ()))
}

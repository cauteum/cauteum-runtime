// Package harden applies Landlock, privilege drop, and related guest restrictions.
package harden

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/whaleshell/whaleshell-core/policy"
)

// Mode controls fail-closed vs loud best-effort.
type Mode string

const (
	ModeBestEffort Mode = "best_effort"
	ModeRequired   Mode = "required"
)

// Options configure one harden pass before exec.
type Options struct {
	Doc    policy.Document
	Mode   Mode
	Log    io.Writer // default stderr
	NoDrop bool      // skip uid/gid drop (debug)
}

// Result describes what was applied (for probes / health).
type Result struct {
	LandlockABI     int
	LandlockApplied bool
	LandlockError   string
	DropApplied     bool
	DropError       string
	SeccompNote     string
}

// SeccompNote documents the MVP seccomp / capability posture.
func SeccompNote() string {
	return "docker-default + no-new-privileges + CapDrop=NET_RAW (in-process filter later)"
}

// ModeFromPolicy maps filesystem.mode to harden Mode.
func ModeFromPolicy(doc policy.Document) Mode {
	switch doc.HardenMode() {
	case "required":
		return ModeRequired
	default:
		return ModeBestEffort
	}
}

// Apply runs Landlock + drop privileges according to opts.
func Apply(ctx context.Context, opts Options) (Result, error) {
	if opts.Log == nil {
		opts.Log = os.Stderr
	}
	if opts.Mode == "" {
		opts.Mode = ModeFromPolicy(opts.Doc)
	}
	res := Result{
		SeccompNote: SeccompNote(),
	}

	abi, err := landlockABI()
	res.LandlockABI = abi
	verbose := os.Getenv("WHALESHELL_HARDEN_VERBOSE") == "1"
	if err != nil {
		res.LandlockError = err.Error()
		msg := fmt.Sprintf("whaleshell-init: landlock unavailable: %v", err)
		if opts.Mode == ModeRequired {
			fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
			return res, fmt.Errorf("harden: landlock required: %w", err)
		}
		fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
	} else {
		if err := applyLandlock(opts.Doc); err != nil {
			res.LandlockError = err.Error()
			msg := fmt.Sprintf("whaleshell-init: landlock apply failed: %v", err)
			if opts.Mode == ModeRequired {
				fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
				return res, fmt.Errorf("harden: landlock: %w", err)
			}
			fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
		} else {
			res.LandlockApplied = true
			if verbose {
				fmt.Fprintf(opts.Log, "whaleshell-init: landlock applied (abi≥%d)\n", abi)
			}
		}
	}

	if !opts.NoDrop && shouldDrop(opts.Doc) {
		if err := dropPrivileges(); err != nil {
			res.DropError = err.Error()
			msg := fmt.Sprintf("whaleshell-init: privilege drop failed: %v", err)
			if opts.Mode == ModeRequired {
				fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
				return res, fmt.Errorf("harden: drop: %w", err)
			}
			fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
		} else {
			res.DropApplied = true
			if verbose {
				fmt.Fprintln(opts.Log, "whaleshell-init: privileges dropped")
			}
		}
	}

	_ = ctx
	return res, nil
}

func shouldDrop(doc policy.Document) bool {
	if os.Getenv("WHALESHELL_DROP") == "1" {
		return true
	}
	return doc.ProcessUser() != "" || doc.ProcessGroup() != ""
}

// Probe reports Landlock ABI without applying a full policy.
func Probe() Result {
	res := Result{SeccompNote: SeccompNote()}
	abi, err := landlockABI()
	res.LandlockABI = abi
	if err != nil {
		res.LandlockError = err.Error()
	}
	return res
}

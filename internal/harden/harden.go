// Package harden applies Landlock, privilege drop, and related guest restrictions.
package harden

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cauteum/cauteum-core/policy"
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
func Apply(_ context.Context, opts Options) (Result, error) {
	if opts.Log == nil {
		opts.Log = os.Stderr
	}
	if opts.Mode == "" {
		opts.Mode = ModeFromPolicy(opts.Doc)
	}
	res := Result{
		SeccompNote: SeccompNote(),
	}
	if err := prepareReadWritePaths(opts.Doc); err != nil {
		return res, fmt.Errorf("harden: prepare filesystem policy: %w", err)
	}
	noFS := noFilesystemGrants(opts.Doc)
	if noFS {
		if opts.Mode == ModeRequired {
			return res, fmt.Errorf("harden: landlock.compatibility is hard_requirement but no filesystem paths are configured")
		}
	}

	// Resolve and drop identity before Landlock restricts reads from account
	// files such as /etc/passwd and /etc/group. Writable path preflight above
	// still runs while the supervisor has the privileges needed to prepare them.
	if !opts.NoDrop && shouldDrop(opts.Doc) {
		if err := dropPrivileges(opts.Doc); err != nil {
			res.DropError = err.Error()
			msg := fmt.Sprintf("cauteum-init: privilege drop failed: %v", err)
			fmt.Fprintln(opts.Log, msg+" (refusing to launch with the wrong process identity)")
			return res, fmt.Errorf("harden: drop: %w", err)
		}
		res.DropApplied = true
		if os.Getenv("CAUTEUM_HARDEN_VERBOSE") == "1" {
			fmt.Fprintln(opts.Log, "cauteum-init: privileges dropped")
		}
	}
	if noFS {
		return res, nil
	}

	abi, err := landlockABI()
	res.LandlockABI = abi
	verbose := os.Getenv("CAUTEUM_HARDEN_VERBOSE") == "1"
	if err != nil {
		res.LandlockError = err.Error()
		msg := fmt.Sprintf("cauteum-init: landlock unavailable: %v", err)
		if opts.Mode == ModeRequired {
			fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
			return res, fmt.Errorf("harden: landlock required: %w", err)
		}
		fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
	} else {
		if err := applyLandlock(opts.Doc); err != nil {
			res.LandlockError = err.Error()
			msg := fmt.Sprintf("cauteum-init: landlock apply failed: %v", err)
			if opts.Mode == ModeRequired {
				fmt.Fprintln(opts.Log, msg+" (mode=required → fail)")
				return res, fmt.Errorf("harden: landlock: %w", err)
			}
			fmt.Fprintln(opts.Log, msg+" (mode=best_effort → continue)")
		} else {
			res.LandlockApplied = true
			if verbose {
				fmt.Fprintf(opts.Log, "cauteum-init: landlock applied (abi≥%d)\n", abi)
			}
		}
	}

	return res, nil
}

func noFilesystemGrants(doc policy.Document) bool {
	fs := doc.FilesystemPolicy
	if fs == nil || fs.IncludeWorkdirEnabled() || len(fs.ReadOnly) != 0 || len(fs.ReadWrite) != 0 {
		return false
	}
	return doc.Display == nil || !strings.EqualFold(doc.Display.Mode, "novnc")
}

func shouldDrop(doc policy.Document) bool {
	return doc.ProcessUser() != "" || doc.ProcessGroup() != "" ||
		os.Getenv("OPENSHELL_SANDBOX_UID") != "" || os.Getenv("OPENSHELL_SANDBOX_GID") != "" || runningAsRoot()
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

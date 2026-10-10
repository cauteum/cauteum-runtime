//go:build linux

package harden

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/cautem-core/policy"
)

func TestLandlockDefaultRuntimeBaseline(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_DEFAULT_BASELINE_CHILD"
	if os.Getenv(childEnv) == "1" {
		if err := applyLandlock(policy.Document{}); err != nil {
			t.Fatal(err)
		}
		probe := filepath.Join(os.TempDir(), "cautem-landlock-default-baseline")
		defer os.Remove(probe)
		cmd := exec.Command("/bin/sh", "-c", `printf baseline > "$1" && test -r /proc/self/cmdline`, "sh", probe)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("default runtime baseline blocked image userland: %v\n%s", err, output)
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	coverageDir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockDefaultRuntimeBaseline$", "-test.gocoverdir="+coverageDir)
	cmd.Env = landlockChildEnv(childEnv + "=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("default runtime baseline child failed: %v\n%s", err, strings.TrimSpace(string(output)))
	}
}

func TestLandlockExplicitPolicyEnforcement(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		allowed := os.Getenv("CAUTEM_LANDLOCK_TEST_ALLOWED")
		coverageDir := os.Getenv("CAUTEM_LANDLOCK_TEST_COVERAGE_DIR")
		doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
			ReadOnly:          []string{filepath.Dir(allowed)},
			ReadWrite:         []string{coverageDir},
			IncludeWorkdir:    false,
			IncludeWorkdirSet: true,
		}}
		if err := applyLandlock(doc); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(allowed); err != nil {
			t.Fatalf("explicitly allowed file is not readable: %v", err)
		}
		if _, err := os.ReadFile("/etc/passwd"); err == nil {
			t.Fatal("unlisted /etc/passwd remained readable under explicit filesystem policy")
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	allowed := filepath.Join(t.TempDir(), "allowed.txt")
	if err := os.WriteFile(allowed, []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	coverageDir := filepath.Join(t.TempDir(), "coverage")
	if err := os.Mkdir(coverageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockExplicitPolicyEnforcement$", "-test.gocoverdir="+coverageDir)
	cmd.Env = landlockChildEnv(childEnv+"=1", "CAUTEM_LANDLOCK_TEST_ALLOWED="+allowed, "CAUTEM_LANDLOCK_TEST_COVERAGE_DIR="+coverageDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Landlock child failed: %v\n%s", err, output)
	}
}

func TestLandlockFilesystemWriteGrantsEnforcement(t *testing.T) {
	const childEnv = "CAUTEM_LANDLOCK_WRITE_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		mode := os.Getenv("CAUTEM_LANDLOCK_WRITE_TEST_MODE")
		root := os.Getenv("CAUTEM_LANDLOCK_WRITE_TEST_ROOT")
		workdir := filepath.Join(root, "work")
		outside := filepath.Join(root, "outside")
		var doc policy.Document
		switch mode {
		case "active-workdir":
			if err := os.Chdir(workdir); err != nil {
				t.Fatal(err)
			}
			doc.FilesystemPolicy = &policy.FilesystemPolicy{}
		case "explicit-read-write":
			doc.FilesystemPolicy = &policy.FilesystemPolicy{
				IncludeWorkdir:    false,
				IncludeWorkdirSet: true,
				ReadWrite:         []string{workdir},
			}
		default:
			t.Fatalf("unknown write test mode %q", mode)
		}
		if err := applyLandlock(doc); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workdir, "allowed.txt"), []byte("allowed"), 0o600); err != nil {
			t.Fatalf("write inside granted path: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outside, "denied.txt"), []byte("denied"), 0o600); err == nil {
			t.Fatal("write outside filesystem grants unexpectedly succeeded")
		}
		return
	}
	if _, err := landlockABI(); err != nil {
		t.Skipf("Landlock unavailable in test environment: %v", err)
	}
	for _, mode := range []string{"active-workdir", "explicit-read-write"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"work", "outside"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			coverageDir := filepath.Join(root, "work")
			cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockFilesystemWriteGrantsEnforcement$", "-test.gocoverdir="+coverageDir)
			cmd.Env = landlockChildEnv(childEnv+"=1", "CAUTEM_LANDLOCK_WRITE_TEST_MODE="+mode, "CAUTEM_LANDLOCK_WRITE_TEST_ROOT="+root)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Landlock %s child failed: %v\n%s", mode, err, output)
			}
		})
	}
}

func landlockChildEnv(values ...string) []string {
	keys := make(map[string]struct{}, len(values)+1)
	keys["GOCOVERDIR"] = struct{}{}
	for _, value := range values {
		key, _, _ := strings.Cut(value, "=")
		keys[key] = struct{}{}
	}
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if _, replace := keys[key]; !replace {
			env = append(env, value)
		}
	}
	return append(env, values...)
}

func TestLandlockOpenShellDefaultGrantsOnlyWorkdir(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{}, "/workspace")
	if len(reads) != 0 || len(writes) != 1 || writes[0] != "/workspace" {
		t.Fatalf("default Landlock paths = reads %v, writes %v; want only /workspace", reads, writes)
	}
}

func TestLandlockCompatibilityModesWithNoFilesystemGrants(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdir:    false,
		IncludeWorkdirSet: true,
	}}
	if err := applyLandlock(doc); err != nil {
		t.Fatalf("best_effort with no configured paths: %v", err)
	}
	doc.Landlock = &policy.Landlock{Compatibility: "hard_requirement"}
	if err := applyLandlock(doc); err == nil {
		t.Fatal("hard_requirement with no configured paths unexpectedly succeeded")
	}
}

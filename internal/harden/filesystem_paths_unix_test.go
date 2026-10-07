//go:build !windows

package harden

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/whaleshell/whaleshell-core/policy"
)

func TestPrepareReadWritePathsCreatesAndOwnsMissingDirectory(t *testing.T) {
	setWritableTestIdentity(t)
	path := filepath.Join(t.TempDir(), "created", "writable")
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{path}}}
	if err := prepareReadWritePaths(doc); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("read_write path type = %s, want directory", info.Mode())
	}
}

func TestPrepareReadWritePathsPreservesExistingDirectory(t *testing.T) {
	setWritableTestIdentity(t)
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(path, 0o711); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{path}}}
	if err := prepareReadWritePaths(doc); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("existing directory changed: before=%v after=%v", before, after)
	}
}

func setWritableTestIdentity(t *testing.T) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 65534, 65534
	}
	t.Setenv("OPENSHELL_SANDBOX_UID", strconv.Itoa(uid))
	t.Setenv("OPENSHELL_SANDBOX_GID", strconv.Itoa(gid))
}

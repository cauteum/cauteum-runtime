package harden

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"

	"github.com/whaleshell/whaleshell-core/policy"
)

func TestPrepareReadWritePathsCreatesAndOwnsMissingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix UID/GID ownership")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix UID/GID ownership")
	}
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

func TestPrepareReadWritePathsRejectsSymlink(t *testing.T) {
	setWritableTestIdentity(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{link}}}
	if err := prepareReadWritePaths(doc); err == nil {
		t.Fatal("symlink read_write path accepted")
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

func TestFilesystemPathsPreservesExplicitOpenShellGrants(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdirSet: true,
		ReadOnly:          []string{"/opt/tools"},
		ReadWrite:         []string{"/workspace/cache"},
	}}
	reads, writes := filesystemPaths(doc, "/workspace")
	if !reflect.DeepEqual(reads, []string{"/opt/tools"}) {
		t.Fatalf("read grants = %v, want only explicit read_only paths", reads)
	}
	if !reflect.DeepEqual(writes, []string{"/workspace/cache"}) {
		t.Fatalf("write grants = %v, want only explicit read_write paths", writes)
	}
}

func TestFilesystemPathsIncludesWorkdirOnlyWhenRequested(t *testing.T) {
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{IncludeWorkdir: true}}
	reads, writes := filesystemPaths(doc, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("paths = reads %v, writes %v; want no reads and writable /workspace", reads, writes)
	}
}

func TestFilesystemPathsEmptySectionUsesOpenShellWorkdirDefault(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{}}, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("empty filesystem_policy paths: reads=%v writes=%v, want default /workspace", reads, writes)
	}
}

func TestFilesystemPathsOmittedSectionUsesOpenShellDefaults(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{}, "/workspace")
	if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspace"}) {
		t.Fatalf("omitted filesystem_policy paths: reads=%v writes=%v, want default /workspace", reads, writes)
	}
}

func TestFilesystemPathsExplicitFalseOmitsWorkdir(t *testing.T) {
	reads, writes := filesystemPaths(policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdirSet: true,
	}}, "/workspace")
	if len(reads) != 0 || len(writes) != 0 {
		t.Fatalf("explicit include_workdir=false paths: reads=%v writes=%v", reads, writes)
	}
}

func TestFilesystemPathsUsesActiveNonDefaultWorkdir(t *testing.T) {
	for _, doc := range []policy.Document{
		{},
		{FilesystemPolicy: &policy.FilesystemPolicy{}},
		{FilesystemPolicy: &policy.FilesystemPolicy{IncludeWorkdir: true}},
	} {
		reads, writes := filesystemPaths(doc, "/workspaces/project")
		if len(reads) != 0 || !reflect.DeepEqual(writes, []string{"/workspaces/project"}) {
			t.Fatalf("active workdir paths: reads=%v writes=%v", reads, writes)
		}
	}
}

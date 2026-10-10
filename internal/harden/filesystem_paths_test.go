package harden

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cauteum-haven/cauteum-core/policy"
)

func TestPrepareReadWritePathsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	doc := policy.Document{FilesystemPolicy: &policy.FilesystemPolicy{ReadWrite: []string{link}}}
	if err := prepareReadWritePaths(doc); err == nil {
		t.Fatal("symlink read_write path accepted")
	}
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

package harden

import (
	"fmt"
	"os"
	"runtime"
	"slices"

	"github.com/whaleshell/whaleshell-core/policy"
)

// filesystemPaths translates OpenShell filesystem_policy defaults and explicit
// grants. OpenShell defaults to no system-path grants and includes /workspace.
func filesystemPaths(doc policy.Document, workdir string) (reads, writes []string) {
	if doc.FilesystemPolicy == nil {
		return nil, []string{workdir}
	}
	reads = slices.Clone(doc.FilesystemPolicy.ReadOnly)
	writes = slices.Clone(doc.FilesystemPolicy.ReadWrite)
	if doc.FilesystemPolicy.IncludeWorkdirEnabled() {
		writes = append(writes, workdir)
	}
	return reads, writes
}

// prepareReadWritePaths matches the supervisor's startup behavior: create
// missing writable directories and chown only directories created by us.
// Existing image/workspace paths retain their configured ownership.
func prepareReadWritePaths(doc policy.Document) error {
	if doc.FilesystemPolicy == nil {
		return nil
	}
	uid, gid := 0, 0
	identityResolved := false
	for _, p := range doc.FilesystemPolicy.ReadWrite {
		info, err := os.Lstat(p)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("read_write path %q is a symlink; refusing to change ownership", p)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect read_write path %q: %w", p, err)
		}
		if runtime.GOOS != "windows" && !identityResolved {
			uid, gid, err = targetFilesystemIDs(doc)
			if err != nil {
				return err
			}
			identityResolved = true
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return fmt.Errorf("create read_write path %q: %w", p, err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chown(p, uid, gid); err != nil {
				return fmt.Errorf("set owner on new read_write path %q: %w", p, err)
			}
		}
	}
	return nil
}

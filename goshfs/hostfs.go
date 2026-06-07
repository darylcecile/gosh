package goshfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/darylcecile/gosh"
)

// NewHostReadOnlyFS mounts a real host directory as a read-only gosh.FileSystem.
//
// SECURITY: this is the only adapter that bridges the sandbox to host disk, so it
// is deliberately conservative and opt-in. The returned FileSystem:
//
//   - serves files only from within root (the canonical, symlink-resolved
//     absolute path of the supplied directory);
//   - resolves every path through the OS and rejects any access whose fully
//     resolved real path escapes root (defeating symlink-escape), returning
//     fs.ErrNotExist rather than leaking that a target exists;
//   - denies every mutation (Open with a write flag, Mkdir, Remove, Rename,
//     Symlink, Link, Chmod, …) with fs.ErrPermission.
//
// To allow scripts to "write" while keeping host disk pristine, compose it as
// the lower layer of an overlay:
//
//	host, _ := goshfs.NewHostReadOnlyFS("/path/to/project")
//	overlay := goshfs.NewOverlayFS(host, gosh.NewInMemoryFS(clock, maxFile, maxTotal))
//	sh := std.Shell(gosh.WithFS(overlay))
//
// Reads fall through to the host; writes land in the discarded in-memory upper.
//
// Residual risks the OPERATOR is responsible for (documented in THREAT_MODEL.md):
//   - TOCTOU: confinement is checked then the file is opened as two steps. The
//     sandboxed script can never write host disk, so only a separate host process
//     could race a path swap. Do not point root at a tree that untrusted host
//     processes can mutate during execution.
//   - Hardlinks: a hardlink inside root to a file outside root shares an inode
//     and is not resolved by symlink checks. Do not mount trees containing
//     attacker-controlled hardlinks.
//   - Directory listings (ReadDir/Lstat) reveal the names of entries that are
//     symlinks escaping root, even though their contents remain unreadable.
func NewHostReadOnlyFS(root string) (gosh.FileSystem, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, pathErr("mount", root, errNotDir)
	}
	// Wrap in readOnlyFS for defense-in-depth: a second, independent layer of
	// name validation and write-flag rejection in front of the host bridge.
	return NewReadOnlyFS(&hostReadOnlyFS{root: canonical}), nil
}

var errNotDir = fs.ErrInvalid

// hostReadOnlyFS serves a confined, read-only view of a host directory subtree.
type hostReadOnlyFS struct {
	root string
}

// mapPath converts a virtual absolute path into a lexical host path under root.
// The caller is responsible for resolving symlinks and confirming containment.
func (h *hostReadOnlyFS) mapPath(name string) (string, error) {
	clean, err := validateName(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(h.root, filepath.FromSlash(clean)), nil
}

// contained reports whether a fully-resolved host path is inside root.
func (h *hostReadOnlyFS) contained(resolved string) bool {
	rel, err := filepath.Rel(h.root, resolved)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

// resolveFull fully resolves name (following all symlinks) and confirms the
// real path stays within root. Used where the target itself must be read.
func (h *hostReadOnlyFS) resolveFull(op, name string) (string, error) {
	host, err := h.mapPath(name)
	if err != nil {
		return "", pathErr(op, name, err)
	}
	real, err := filepath.EvalSymlinks(host)
	if err != nil {
		return "", pathErr(op, name, fs.ErrNotExist)
	}
	if !h.contained(real) {
		return "", pathErr(op, name, fs.ErrNotExist)
	}
	return real, nil
}

// resolveParent resolves the parent directory (following symlinks) and confirms
// containment, then re-attaches the final element WITHOUT following it. Used for
// Lstat/Readlink where the final symlink must not be dereferenced.
func (h *hostReadOnlyFS) resolveParent(op, name string) (string, error) {
	host, err := h.mapPath(name)
	if err != nil {
		return "", pathErr(op, name, err)
	}
	if host == h.root {
		return h.root, nil
	}
	parent := filepath.Dir(host)
	base := filepath.Base(host)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", pathErr(op, name, fs.ErrNotExist)
	}
	if !h.contained(realParent) {
		return "", pathErr(op, name, fs.ErrNotExist)
	}
	full := filepath.Join(realParent, base)
	// The joined path must still be within root (base could be "..", though
	// validateName already rejects that).
	if full != h.root && !h.contained(full) {
		return "", pathErr(op, name, fs.ErrNotExist)
	}
	return full, nil
}

func (h *hostReadOnlyFS) Open(name string, flag int, perm fs.FileMode) (gosh.File, error) {
	if isWriteFlag(flag) {
		return nil, permission("open", name)
	}
	real, err := h.resolveFull("open", name)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(real, os.O_RDONLY, 0)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	return &hostFile{f: f, name: name}, nil
}

func (h *hostReadOnlyFS) Stat(name string) (fs.FileInfo, error) {
	real, err := h.resolveFull("stat", name)
	if err != nil {
		return nil, err
	}
	return os.Stat(real)
}

func (h *hostReadOnlyFS) Lstat(name string) (fs.FileInfo, error) {
	p, err := h.resolveParent("lstat", name)
	if err != nil {
		return nil, err
	}
	return os.Lstat(p)
}

func (h *hostReadOnlyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	real, err := h.resolveFull("readdir", name)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(real)
}

func (h *hostReadOnlyFS) Readlink(name string) (string, error) {
	p, err := h.resolveParent("readlink", name)
	if err != nil {
		return "", err
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	resolveBase := target
	if !filepath.IsAbs(target) {
		resolveBase = filepath.Join(filepath.Dir(p), target)
	}
	realTarget, err := filepath.EvalSymlinks(resolveBase)
	if err != nil || !h.contained(realTarget) {
		return "", pathErr("readlink", name, fs.ErrNotExist)
	}
	rel, err := filepath.Rel(h.root, realTarget)
	if err != nil {
		return "", pathErr("readlink", name, fs.ErrNotExist)
	}
	if rel == "." {
		return "/", nil
	}
	return "/" + filepath.ToSlash(rel), nil
}

func (h *hostReadOnlyFS) Mkdir(name string, perm fs.FileMode) error { return permission("mkdir", name) }
func (h *hostReadOnlyFS) MkdirAll(name string, perm fs.FileMode) error {
	return permission("mkdir", name)
}
func (h *hostReadOnlyFS) Remove(name string) error                  { return permission("remove", name) }
func (h *hostReadOnlyFS) RemoveAll(name string) error               { return permission("removeall", name) }
func (h *hostReadOnlyFS) Rename(oldpath, newpath string) error      { return permission("rename", oldpath) }
func (h *hostReadOnlyFS) Symlink(target, link string) error         { return permission("symlink", link) }
func (h *hostReadOnlyFS) Link(target, link string) error            { return permission("link", link) }
func (h *hostReadOnlyFS) Chmod(name string, mode fs.FileMode) error { return permission("chmod", name) }

// hostFile is a read-only File backed by an *os.File. Write/Truncate are denied.
type hostFile struct {
	f    *os.File
	name string
}

func (h *hostFile) Read(p []byte) (int, error)                { return h.f.Read(p) }
func (h *hostFile) Seek(off int64, whence int) (int64, error) { return h.f.Seek(off, whence) }
func (h *hostFile) Close() error                              { return h.f.Close() }
func (h *hostFile) Stat() (fs.FileInfo, error)                { return h.f.Stat() }
func (h *hostFile) Write(p []byte) (int, error)               { return 0, permission("write", h.name) }
func (h *hostFile) Truncate(size int64) error                 { return permission("truncate", h.name) }

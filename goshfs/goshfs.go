// Package goshfs provides composable FileSystem adapters for gosh.
package goshfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/darylcecile/gosh"
)

var errCrossFilesystem = errors.New("operation cannot span filesystems")

func pathErr(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func permission(op, name string) error {
	return pathErr(op, name, fs.ErrPermission)
}

func isWriteFlag(flag int) bool {
	return flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
}

func validateName(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path")
	}
	if strings.Contains(name, "\\") {
		return "", errors.New("windows paths are not supported")
	}
	if len(name) >= 2 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':' {
		return "", errors.New("windows drive paths are not supported")
	}
	if strings.HasPrefix(name, "//") {
		return "", errors.New("UNC paths are not supported")
	}
	if !strings.HasPrefix(name, "/") {
		return "", errors.New("path must be absolute")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", errors.New("path traversal is not allowed")
		}
	}
	clean := path.Clean(name)
	if clean != name {
		return "", errors.New("path must be clean")
	}
	return clean, nil
}

func validateSymlinkTarget(target string) error {
	if target == "" {
		return errors.New("empty symlink target")
	}
	if strings.Contains(target, "\\") {
		return errors.New("windows paths are not supported")
	}
	if len(target) >= 2 && ((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z')) && target[1] == ':' {
		return errors.New("windows drive paths are not supported")
	}
	if strings.HasPrefix(target, "//") {
		return errors.New("UNC paths are not supported")
	}
	for _, part := range strings.Split(target, "/") {
		if part == ".." {
			return errors.New("symlink target traversal is not allowed")
		}
	}
	if path.Clean(target) != target {
		return errors.New("symlink target must be clean")
	}
	return nil
}

// NewReadOnlyFS wraps inner with a FileSystem that permits reads and rejects all mutations.
func NewReadOnlyFS(inner gosh.FileSystem) gosh.FileSystem {
	return readOnlyFS{inner: inner}
}

type readOnlyFS struct {
	inner gosh.FileSystem
}

func (r readOnlyFS) Open(name string, flag int, perm fs.FileMode) (gosh.File, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	if isWriteFlag(flag) {
		return nil, permission("open", name)
	}
	return r.inner.Open(name, flag, perm)
}

func (r readOnlyFS) Stat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	return r.inner.Stat(name)
}

func (r readOnlyFS) Lstat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	return r.inner.Lstat(name)
}

func (r readOnlyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	return r.inner.ReadDir(name)
}

func (r readOnlyFS) Mkdir(name string, perm fs.FileMode) error    { return permission("mkdir", name) }
func (r readOnlyFS) MkdirAll(name string, perm fs.FileMode) error { return permission("mkdir", name) }
func (r readOnlyFS) Remove(name string) error                     { return permission("remove", name) }
func (r readOnlyFS) RemoveAll(name string) error                  { return permission("removeall", name) }
func (r readOnlyFS) Rename(oldpath, newpath string) error         { return permission("rename", oldpath) }
func (r readOnlyFS) Symlink(target, link string) error            { return permission("symlink", link) }
func (r readOnlyFS) Link(target, link string) error               { return permission("link", link) }
func (r readOnlyFS) Readlink(name string) (string, error) {
	name, err := validateName(name)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return r.inner.Readlink(name)
}
func (r readOnlyFS) Chmod(name string, mode fs.FileMode) error { return permission("chmod", name) }

// NewReadWriteFS wraps inner with a pass-through FileSystem adapter.
func NewReadWriteFS(inner gosh.FileSystem) gosh.FileSystem {
	return readWriteFS{inner: inner}
}

type readWriteFS struct {
	inner gosh.FileSystem
}

func (r readWriteFS) Open(name string, flag int, perm fs.FileMode) (gosh.File, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	return r.inner.Open(name, flag, perm)
}
func (r readWriteFS) Stat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	return r.inner.Stat(name)
}
func (r readWriteFS) Lstat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	return r.inner.Lstat(name)
}
func (r readWriteFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	return r.inner.ReadDir(name)
}
func (r readWriteFS) Mkdir(name string, perm fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	return r.inner.Mkdir(name, perm)
}
func (r readWriteFS) MkdirAll(name string, perm fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	return r.inner.MkdirAll(name, perm)
}
func (r readWriteFS) Remove(name string) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	return r.inner.Remove(name)
}
func (r readWriteFS) RemoveAll(name string) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("removeall", name, err)
	}
	return r.inner.RemoveAll(name)
}
func (r readWriteFS) Rename(oldpath, newpath string) error {
	oldpath, err := validateName(oldpath)
	if err != nil {
		return pathErr("rename", oldpath, err)
	}
	newpath, err = validateName(newpath)
	if err != nil {
		return pathErr("rename", newpath, err)
	}
	return r.inner.Rename(oldpath, newpath)
}
func (r readWriteFS) Symlink(target, link string) error {
	if err := validateSymlinkTarget(target); err != nil {
		return pathErr("symlink", target, err)
	}
	link, err := validateName(link)
	if err != nil {
		return pathErr("symlink", link, err)
	}
	return r.inner.Symlink(target, link)
}
func (r readWriteFS) Link(target, link string) error {
	target, err := validateName(target)
	if err != nil {
		return pathErr("link", target, err)
	}
	link, err = validateName(link)
	if err != nil {
		return pathErr("link", link, err)
	}
	return r.inner.Link(target, link)
}
func (r readWriteFS) Readlink(name string) (string, error) {
	name, err := validateName(name)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return r.inner.Readlink(name)
}
func (r readWriteFS) Chmod(name string, mode fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("chmod", name, err)
	}
	return r.inner.Chmod(name, mode)
}

// NewOverlayFS returns a copy-on-write FileSystem that reads from upper first, then lower.
func NewOverlayFS(lower, upper gosh.FileSystem) gosh.FileSystem {
	return &OverlayFS{lower: lower, upper: upper, whiteouts: make(map[string]struct{})}
}

// OverlayFS is a copy-on-write FileSystem with lower and upper layers.
type OverlayFS struct {
	mu        sync.Mutex
	lower     gosh.FileSystem
	upper     gosh.FileSystem
	whiteouts map[string]struct{}
}

func (o *OverlayFS) whiteoutedLocked(name string) bool {
	for {
		if _, ok := o.whiteouts[name]; ok {
			return true
		}
		if name == "/" {
			return false
		}
		name = path.Dir(name)
	}
}

func (o *OverlayFS) clearWhiteoutLocked(name string) {
	delete(o.whiteouts, name)
}

func (o *OverlayFS) addWhiteoutLocked(name string) {
	if name != "/" {
		o.whiteouts[name] = struct{}{}
	}
}

func (o *OverlayFS) existsUpper(name string) bool {
	_, err := o.upper.Lstat(name)
	return err == nil
}

func (o *OverlayFS) existsLower(name string) bool {
	_, err := o.lower.Lstat(name)
	return err == nil
}

func (o *OverlayFS) ensureParent(name string) error {
	parent := path.Dir(name)
	if parent == "/" {
		return nil
	}
	if _, err := o.upper.Stat(parent); err == nil {
		return nil
	}
	if _, err := o.lower.Stat(parent); err == nil {
		return o.copyUp(parent)
	}
	return o.upper.MkdirAll(parent, 0o755)
}

func (o *OverlayFS) copyUp(name string) error {
	if _, err := o.upper.Lstat(name); err == nil {
		return nil
	}
	info, err := o.lower.Lstat(name)
	if err != nil {
		return err
	}
	if err := o.ensureParent(name); err != nil {
		return err
	}
	mode := info.Mode()
	if mode&fs.ModeSymlink != 0 {
		target, err := o.lower.Readlink(name)
		if err != nil {
			return err
		}
		return o.upper.Symlink(target, name)
	}
	if info.IsDir() {
		if err := o.upper.Mkdir(name, mode.Perm()); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		return o.upper.Chmod(name, mode.Perm())
	}
	src, err := o.lower.Open(name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := o.upper.Open(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, mode.Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return o.upper.Chmod(name, mode.Perm())
}

func (o *OverlayFS) Open(name string, flag int, perm fs.FileMode) (gosh.File, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) && !isWriteFlag(flag) {
		return nil, pathErr("open", name, fs.ErrNotExist)
	}
	if isWriteFlag(flag) {
		if flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0 {
			if !o.whiteoutedLocked(name) && (o.existsUpper(name) || o.existsLower(name)) {
				return nil, pathErr("open", name, fs.ErrExist)
			}
		} else if !o.existsUpper(name) && !o.whiteoutedLocked(name) && o.existsLower(name) {
			if err := o.copyUp(name); err != nil {
				return nil, err
			}
		}
		if err := o.ensureParent(name); err != nil {
			return nil, err
		}
		o.clearWhiteoutLocked(name)
		return o.upper.Open(name, flag, perm)
	}
	if f, err := o.upper.Open(name, flag, perm); err == nil {
		return f, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return o.lower.Open(name, flag, perm)
}

func (o *OverlayFS) Stat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) {
		return nil, pathErr("stat", name, fs.ErrNotExist)
	}
	if info, err := o.upper.Stat(name); err == nil {
		return info, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return o.lower.Stat(name)
}

func (o *OverlayFS) Lstat(name string) (fs.FileInfo, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) {
		return nil, pathErr("lstat", name, fs.ErrNotExist)
	}
	if info, err := o.upper.Lstat(name); err == nil {
		return info, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return o.lower.Lstat(name)
}

func (o *OverlayFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name, err := validateName(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) {
		return nil, pathErr("readdir", name, fs.ErrNotExist)
	}
	upperInfo, upperErr := o.upper.Lstat(name)
	if upperErr == nil && !upperInfo.IsDir() {
		return o.upper.ReadDir(name)
	}
	entries := map[string]fs.DirEntry{}
	if lowerEntries, err := o.lower.ReadDir(name); err == nil {
		for _, ent := range lowerEntries {
			child := path.Join(name, ent.Name())
			if !o.whiteoutedLocked(child) {
				entries[ent.Name()] = ent
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) || upperErr != nil {
		if upperErr != nil && errors.Is(upperErr, fs.ErrNotExist) {
			return nil, err
		}
	}
	if upperEntries, err := o.upper.ReadDir(name); err == nil {
		for _, ent := range upperEntries {
			child := path.Join(name, ent.Name())
			if !o.whiteoutedLocked(child) {
				entries[ent.Name()] = ent
			}
		}
	} else if upperErr == nil || !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(entries) == 0 && upperErr != nil {
		if _, err := o.lower.Lstat(name); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, entries[n])
	}
	return out, nil
}

func (o *OverlayFS) Mkdir(name string, perm fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.whiteoutedLocked(name) && (o.existsUpper(name) || o.existsLower(name)) {
		return pathErr("mkdir", name, fs.ErrExist)
	}
	if err := o.ensureParent(name); err != nil {
		return err
	}
	o.clearWhiteoutLocked(name)
	return o.upper.Mkdir(name, perm)
}

func (o *OverlayFS) MkdirAll(name string, perm fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.clearWhiteoutLocked(name)
	return o.upper.MkdirAll(name, perm)
}

func (o *OverlayFS) Remove(name string) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	upperExists := o.existsUpper(name)
	lowerExists := !o.whiteoutedLocked(name) && o.existsLower(name)
	if !upperExists && !lowerExists {
		return pathErr("remove", name, fs.ErrNotExist)
	}
	if upperExists {
		if err := o.upper.Remove(name); err != nil {
			return err
		}
	}
	if lowerExists {
		o.addWhiteoutLocked(name)
	}
	return nil
}

func (o *OverlayFS) RemoveAll(name string) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("removeall", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_ = o.upper.RemoveAll(name)
	if !o.whiteoutedLocked(name) && o.existsLower(name) {
		o.addWhiteoutLocked(name)
	}
	return nil
}

func (o *OverlayFS) Rename(oldpath, newpath string) error {
	oldpath, err := validateName(oldpath)
	if err != nil {
		return pathErr("rename", oldpath, err)
	}
	newpath, err = validateName(newpath)
	if err != nil {
		return pathErr("rename", newpath, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	oldLower := !o.whiteoutedLocked(oldpath) && o.existsLower(oldpath)
	if !o.existsUpper(oldpath) {
		if !oldLower {
			return pathErr("rename", oldpath, fs.ErrNotExist)
		}
		if err := o.copyUp(oldpath); err != nil {
			return err
		}
	}
	if err := o.ensureParent(newpath); err != nil {
		return err
	}
	newLower := !o.whiteoutedLocked(newpath) && o.existsLower(newpath)
	o.clearWhiteoutLocked(newpath)
	if err := o.upper.Rename(oldpath, newpath); err != nil {
		return err
	}
	if oldLower {
		o.addWhiteoutLocked(oldpath)
	}
	if newLower {
		o.addWhiteoutLocked(newpath)
	}
	return nil
}

func (o *OverlayFS) Symlink(target, link string) error {
	if err := validateSymlinkTarget(target); err != nil {
		return pathErr("symlink", target, err)
	}
	link, err := validateName(link)
	if err != nil {
		return pathErr("symlink", link, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.whiteoutedLocked(link) && (o.existsUpper(link) || o.existsLower(link)) {
		return pathErr("symlink", link, fs.ErrExist)
	}
	if err := o.ensureParent(link); err != nil {
		return err
	}
	o.clearWhiteoutLocked(link)
	return o.upper.Symlink(target, link)
}

func (o *OverlayFS) Link(target, link string) error {
	target, err := validateName(target)
	if err != nil {
		return pathErr("link", target, err)
	}
	link, err = validateName(link)
	if err != nil {
		return pathErr("link", link, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.whiteoutedLocked(link) && (o.existsUpper(link) || o.existsLower(link)) {
		return pathErr("link", link, fs.ErrExist)
	}
	if o.whiteoutedLocked(target) {
		return pathErr("link", target, fs.ErrNotExist)
	}
	if !o.existsUpper(target) {
		if !o.existsLower(target) {
			return pathErr("link", target, fs.ErrNotExist)
		}
		if err := o.copyUp(target); err != nil {
			return err
		}
	}
	if err := o.ensureParent(link); err != nil {
		return err
	}
	o.clearWhiteoutLocked(link)
	return o.upper.Link(target, link)
}

func (o *OverlayFS) Readlink(name string) (string, error) {
	name, err := validateName(name)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) {
		return "", pathErr("readlink", name, fs.ErrNotExist)
	}
	if target, err := o.upper.Readlink(name); err == nil {
		return target, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return o.lower.Readlink(name)
}

func (o *OverlayFS) Chmod(name string, mode fs.FileMode) error {
	name, err := validateName(name)
	if err != nil {
		return pathErr("chmod", name, err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.whiteoutedLocked(name) {
		return pathErr("chmod", name, fs.ErrNotExist)
	}
	if !o.existsUpper(name) {
		if !o.existsLower(name) {
			return pathErr("chmod", name, fs.ErrNotExist)
		}
		if err := o.copyUp(name); err != nil {
			return err
		}
	}
	return o.upper.Chmod(name, mode)
}

// NewMountableFS returns a FileSystem that routes paths to mounted FileSystems by longest prefix.
func NewMountableFS(root gosh.FileSystem) gosh.FileSystem {
	return &MountableFS{root: root, mounts: make(map[string]gosh.FileSystem)}
}

// MountableFS composes a root FileSystem with non-overlapping mounted FileSystems.
type MountableFS struct {
	mu     sync.RWMutex
	root   gosh.FileSystem
	mounts map[string]gosh.FileSystem
}

// Mount attaches fsys at prefix. Prefix must be absolute, clean, non-root, and non-overlapping.
func (m *MountableFS) Mount(prefix string, fsys gosh.FileSystem) error {
	prefix, err := validateName(prefix)
	if err != nil {
		return pathErr("mount", prefix, err)
	}
	if prefix == "/" {
		return pathErr("mount", prefix, errors.New("mount prefix cannot be root"))
	}
	if fsys == nil {
		return pathErr("mount", prefix, errors.New("nil filesystem"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for existing := range m.mounts {
		if existing == prefix || hasPathPrefix(existing, prefix) || hasPathPrefix(prefix, existing) {
			return pathErr("mount", prefix, fmt.Errorf("mount prefix overlaps %s", existing))
		}
	}
	m.mounts[prefix] = fsys
	return nil
}

// Unmount detaches any FileSystem mounted at prefix.
func (m *MountableFS) Unmount(prefix string) {
	prefix, err := validateName(prefix)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mounts, prefix)
}

type mountRoute struct {
	prefix string
	fsys   gosh.FileSystem
	name   string
}

func hasPathPrefix(name, prefix string) bool {
	return name == prefix || strings.HasPrefix(name, prefix+"/")
}

func translate(prefix, name string) string {
	if name == prefix {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(name, prefix+"/"))
}

func (m *MountableFS) route(name string) (mountRoute, error) {
	name, err := validateName(name)
	if err != nil {
		return mountRoute{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	best := ""
	for prefix := range m.mounts {
		if hasPathPrefix(name, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return mountRoute{fsys: m.root, name: name}, nil
	}
	translated := translate(best, name)
	if _, err := validateName(translated); err != nil {
		return mountRoute{}, err
	}
	return mountRoute{prefix: best, fsys: m.mounts[best], name: translated}, nil
}

func (m *MountableFS) routePair(op, a, b string) (mountRoute, mountRoute, error) {
	ra, err := m.route(a)
	if err != nil {
		return mountRoute{}, mountRoute{}, pathErr(op, a, err)
	}
	rb, err := m.route(b)
	if err != nil {
		return mountRoute{}, mountRoute{}, pathErr(op, b, err)
	}
	if ra.fsys != rb.fsys || ra.prefix != rb.prefix {
		return mountRoute{}, mountRoute{}, pathErr(op, a, errCrossFilesystem)
	}
	return ra, rb, nil
}

func (m *MountableFS) translateSymlinkTarget(linkRoute mountRoute, target string) (string, error) {
	if err := validateSymlinkTarget(target); err != nil {
		return "", err
	}
	if !strings.HasPrefix(target, "/") {
		return target, nil
	}
	targetRoute, err := m.route(target)
	if err != nil {
		return "", err
	}
	if targetRoute.prefix != linkRoute.prefix {
		return "", errCrossFilesystem
	}
	return targetRoute.name, nil
}

type mountInfo struct{ name string }

func (i mountInfo) Name() string       { return i.name }
func (i mountInfo) Size() int64        { return 0 }
func (i mountInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (i mountInfo) ModTime() time.Time { return time.Time{} }
func (i mountInfo) IsDir() bool        { return true }
func (i mountInfo) Sys() any           { return nil }

type mountDirEntry struct{ info fs.FileInfo }

func (d mountDirEntry) Name() string               { return d.info.Name() }
func (d mountDirEntry) IsDir() bool                { return true }
func (d mountDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (d mountDirEntry) Info() (fs.FileInfo, error) { return d.info, nil }

func mountChild(prefix, parent string) (string, bool) {
	var rest string
	switch {
	case parent == "/":
		rest = strings.TrimPrefix(prefix, "/")
	case hasPathPrefix(prefix, parent) && prefix != parent:
		rest = strings.TrimPrefix(strings.TrimPrefix(prefix, parent), "/")
	default:
		return "", false
	}
	child, _, _ := strings.Cut(rest, "/")
	return child, child != ""
}

func (m *MountableFS) virtualMountChildLocked(name string) (string, bool) {
	for prefix := range m.mounts {
		if child, ok := mountChild(prefix, name); ok {
			return child, true
		}
	}
	return "", false
}

func (m *MountableFS) Open(name string, flag int, perm fs.FileMode) (gosh.File, error) {
	r, err := m.route(name)
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	return r.fsys.Open(r.name, flag, perm)
}
func (m *MountableFS) Stat(name string) (fs.FileInfo, error) {
	r, err := m.route(name)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	info, err := r.fsys.Stat(r.name)
	if err == nil || r.prefix != "" || !errors.Is(err, fs.ErrNotExist) {
		return info, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if child, ok := m.virtualMountChildLocked(r.name); ok {
		if r.name == "/" {
			return mountInfo{name: child}, nil
		}
		return mountInfo{name: path.Base(r.name)}, nil
	}
	return nil, err
}
func (m *MountableFS) Lstat(name string) (fs.FileInfo, error) {
	r, err := m.route(name)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	info, err := r.fsys.Lstat(r.name)
	if err == nil || r.prefix != "" || !errors.Is(err, fs.ErrNotExist) {
		return info, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if child, ok := m.virtualMountChildLocked(r.name); ok {
		if r.name == "/" {
			return mountInfo{name: child}, nil
		}
		return mountInfo{name: path.Base(r.name)}, nil
	}
	return nil, err
}
func (m *MountableFS) ReadDir(name string) ([]fs.DirEntry, error) {
	r, err := m.route(name)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	entries, err := r.fsys.ReadDir(r.name)
	if r.prefix != "" {
		return entries, err
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	byName := make(map[string]fs.DirEntry, len(entries))
	for _, ent := range entries {
		byName[ent.Name()] = ent
	}
	m.mu.RLock()
	for prefix := range m.mounts {
		if child, ok := mountChild(prefix, r.name); ok {
			byName[child] = mountDirEntry{info: mountInfo{name: child}}
		}
	}
	m.mu.RUnlock()
	if len(byName) == 0 && err != nil {
		return nil, err
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out, nil
}
func (m *MountableFS) Mkdir(name string, perm fs.FileMode) error {
	r, err := m.route(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	return r.fsys.Mkdir(r.name, perm)
}
func (m *MountableFS) MkdirAll(name string, perm fs.FileMode) error {
	r, err := m.route(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	return r.fsys.MkdirAll(r.name, perm)
}
func (m *MountableFS) Remove(name string) error {
	r, err := m.route(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	return r.fsys.Remove(r.name)
}
func (m *MountableFS) RemoveAll(name string) error {
	r, err := m.route(name)
	if err != nil {
		return pathErr("removeall", name, err)
	}
	return r.fsys.RemoveAll(r.name)
}
func (m *MountableFS) Rename(oldpath, newpath string) error {
	ra, rb, err := m.routePair("rename", oldpath, newpath)
	if err != nil {
		return err
	}
	return ra.fsys.Rename(ra.name, rb.name)
}
func (m *MountableFS) Symlink(target, link string) error {
	r, err := m.route(link)
	if err != nil {
		return pathErr("symlink", link, err)
	}
	translated, err := m.translateSymlinkTarget(r, target)
	if err != nil {
		return pathErr("symlink", target, err)
	}
	return r.fsys.Symlink(translated, r.name)
}
func (m *MountableFS) Link(target, link string) error {
	ra, rb, err := m.routePair("link", target, link)
	if err != nil {
		return err
	}
	return ra.fsys.Link(ra.name, rb.name)
}
func (m *MountableFS) Readlink(name string) (string, error) {
	r, err := m.route(name)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return r.fsys.Readlink(r.name)
}
func (m *MountableFS) Chmod(name string, mode fs.FileMode) error {
	r, err := m.route(name)
	if err != nil {
		return pathErr("chmod", name, err)
	}
	return r.fsys.Chmod(r.name, mode)
}

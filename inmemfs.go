package gosh

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxSymlinkHops bounds symlink resolution to defend against cycles and
// pathological chains (S5). Exceeding it yields an ELOOP-style error rather
// than hanging.
const maxSymlinkHops = 40

// imNode is a single in-memory inode. Regular files, directories, and symlinks
// are distinguished by mode. Hard links are modeled by multiple directory
// entries referencing the same *imNode; links counts those references so file
// bytes are freed (and uncounted) only when the last link is removed.
type imNode struct {
	mode    fs.FileMode
	modTime time.Time
	data    []byte             // regular-file contents (shared across hard links)
	target  string             // symlink target (when mode&ModeSymlink != 0)
	entries map[string]*imNode // directory children (when IsDir)
	links   int                // number of directory references to this inode
}

func (n *imNode) isDir() bool     { return n.mode&fs.ModeDir != 0 }
func (n *imNode) isSymlink() bool { return n.mode&fs.ModeSymlink != 0 }

// InMemoryFS is the default, fully in-memory FileSystem. It has no host
// backing (S3), confines all access within its virtual root (S4), bounds
// symlink resolution (S5), and enforces per-file and total size caps (S7). It
// is safe for concurrent use; the owning Shell additionally serializes runs.
type InMemoryFS struct {
	mu           sync.Mutex
	root         *imNode
	clock        Clock
	maxFileBytes int64
	maxTotal     int64
	total        int64
}

// NewInMemoryFS creates an empty in-memory filesystem with a root directory.
// clock supplies modification timestamps; maxFileBytes and maxTotalBytes apply
// the S7 size caps (a non-positive value disables that particular cap).
func NewInMemoryFS(clock Clock, maxFileBytes, maxTotalBytes int64) *InMemoryFS {
	if clock == nil {
		clock = NewVirtualClock(Epoch)
	}
	now := clock.Now()
	return &InMemoryFS{
		root: &imNode{
			mode:    fs.ModeDir | 0o755,
			modTime: now,
			entries: make(map[string]*imNode),
			links:   1,
		},
		clock:        clock,
		maxFileBytes: maxFileBytes,
		maxTotal:     maxTotalBytes,
	}
}

// --- errors (rendered to virtual paths via the engine's error sanitizer) ---

func pathErr(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

var errLoop = errors.New("too many levels of symbolic links")
var errNotDir = errors.New("not a directory")
var errIsDir = errors.New("is a directory")
var errExist = fs.ErrExist
var errNotExist = fs.ErrNotExist

// cleanAbs normalizes name to an absolute, POSIX, cleaned path rooted at "/".
// Because path.Clean collapses any leading "../" against the root, no path can
// address anything above the virtual root (S4).
func cleanAbs(name string) string {
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	return path.Clean(name)
}

// splitParent returns the cleaned parent directory and final element of abs.
func splitParent(abs string) (dir, leaf string) {
	abs = cleanAbs(abs)
	if abs == "/" {
		return "/", ""
	}
	dir, leaf = path.Split(abs)
	dir = path.Clean(dir)
	return dir, leaf
}

// resolve walks abs to a node, following intermediate symlinks always and the
// final element only when followFinal is true. It enforces the symlink hop cap.
func (m *InMemoryFS) resolve(abs string, followFinal bool, hops int) (*imNode, error) {
	if hops > maxSymlinkHops {
		return nil, errLoop
	}
	abs = cleanAbs(abs)
	if abs == "/" {
		return m.root, nil
	}
	dir, leaf := splitParent(abs)
	parent, err := m.resolveDir(dir, hops)
	if err != nil {
		return nil, err
	}
	child, ok := parent.entries[leaf]
	if !ok {
		return nil, errNotExist
	}
	if child.isSymlink() && followFinal {
		next := child.target
		if path.IsAbs(next) {
			next = cleanAbs(next)
		} else {
			next = cleanAbs(path.Join(dir, next))
		}
		return m.resolve(next, true, hops+1)
	}
	return child, nil
}

// resolveDir resolves abs to a directory node, following symlinks.
func (m *InMemoryFS) resolveDir(abs string, hops int) (*imNode, error) {
	n, err := m.resolve(abs, true, hops)
	if err != nil {
		return nil, err
	}
	if !n.isDir() {
		return nil, errNotDir
	}
	return n, nil
}

// parentAndLeaf resolves the parent directory of abs (following symlinks) and
// returns it with the final element name, for create/remove/link operations.
func (m *InMemoryFS) parentAndLeaf(abs string) (*imNode, string, error) {
	dir, leaf := splitParent(abs)
	if leaf == "" {
		return nil, "", errExist // operating on root
	}
	parent, err := m.resolveDir(dir, 0)
	if err != nil {
		return nil, "", err
	}
	return parent, leaf, nil
}

func (m *InMemoryFS) now() time.Time { return m.clock.Now() }

// --- FileSystem implementation ---

// Open implements FileSystem.Open.
func (m *InMemoryFS) Open(name string, flag int, perm fs.FileMode) (File, error) {
	// Use the host os flag constants (which vary by platform) for correct
	// interpretation of the flags mvdan/sh passes. Importing os is permitted;
	// only os/exec and net are banned in the sandbox core (S27).
	const (
		oWRONLY = os.O_WRONLY
		oRDWR   = os.O_RDWR
		oCREATE = os.O_CREATE
		oEXCL   = os.O_EXCL
		oTRUNC  = os.O_TRUNC
		oAPPEND = os.O_APPEND
	)
	m.mu.Lock()
	defer m.mu.Unlock()

	node, err := m.resolve(name, true, 0)
	switch {
	case err == nil:
		if flag&oCREATE != 0 && flag&oEXCL != 0 {
			return nil, pathErr("open", name, errExist)
		}
		if node.isDir() {
			if flag&(oWRONLY|oRDWR|oTRUNC|oCREATE) != 0 {
				return nil, pathErr("open", name, errIsDir)
			}
		}
	case errors.Is(err, errNotExist):
		if flag&oCREATE == 0 {
			return nil, pathErr("open", name, errNotExist)
		}
		parent, leaf, perr := m.parentAndLeaf(name)
		if perr != nil {
			return nil, pathErr("open", name, perr)
		}
		node = &imNode{mode: perm & fs.ModePerm, modTime: m.now(), links: 1}
		parent.entries[leaf] = node
		parent.modTime = m.now()
	default:
		return nil, pathErr("open", name, err)
	}

	if flag&oTRUNC != 0 && !node.isDir() {
		m.total -= int64(len(node.data))
		node.data = node.data[:0]
		node.modTime = m.now()
	}

	f := &imFile{
		fsys:   m,
		node:   node,
		name:   cleanAbs(name),
		read:   flag&oWRONLY == 0, // O_RDONLY or O_RDWR
		write:  flag&(oWRONLY|oRDWR) != 0,
		append: flag&oAPPEND != 0,
	}
	if f.append {
		f.offset = int64(len(node.data))
	}
	return f, nil
}

// Stat implements FileSystem.Stat (follows symlinks).
func (m *InMemoryFS) Stat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true, 0)
	if err != nil {
		return nil, pathErr("stat", name, err)
	}
	return newFileInfo(path.Base(cleanAbs(name)), node), nil
}

// Lstat implements FileSystem.Lstat (does not follow a final symlink).
func (m *InMemoryFS) Lstat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, false, 0)
	if err != nil {
		return nil, pathErr("lstat", name, err)
	}
	return newFileInfo(path.Base(cleanAbs(name)), node), nil
}

// ReadDir implements FileSystem.ReadDir.
func (m *InMemoryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true, 0)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	if !node.isDir() {
		return nil, pathErr("readdir", name, errNotDir)
	}
	names := make([]string, 0, len(node.entries))
	for n := range node.entries {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, fs.FileInfoToDirEntry(newFileInfo(n, node.entries[n])))
	}
	return out, nil
}

// Mkdir implements FileSystem.Mkdir.
func (m *InMemoryFS) Mkdir(name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, leaf, err := m.parentAndLeaf(name)
	if err != nil {
		return pathErr("mkdir", name, err)
	}
	if _, ok := parent.entries[leaf]; ok {
		return pathErr("mkdir", name, errExist)
	}
	parent.entries[leaf] = &imNode{
		mode:    fs.ModeDir | (perm & fs.ModePerm),
		modTime: m.now(),
		entries: make(map[string]*imNode),
		links:   1,
	}
	parent.modTime = m.now()
	return nil
}

// MkdirAll implements FileSystem.MkdirAll.
func (m *InMemoryFS) MkdirAll(name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	abs := cleanAbs(name)
	if abs == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	cur := m.root
	acc := ""
	for _, p := range parts {
		acc += "/" + p
		child, ok := cur.entries[p]
		if !ok {
			child = &imNode{
				mode:    fs.ModeDir | (perm & fs.ModePerm),
				modTime: m.now(),
				entries: make(map[string]*imNode),
				links:   1,
			}
			cur.entries[p] = child
			cur.modTime = m.now()
		} else if child.isSymlink() {
			// A symlink encountered mid-path: follow it and require that it
			// resolves to a directory before continuing.
			resolved, err := m.resolve(acc, true, 0)
			if err != nil || !resolved.isDir() {
				return pathErr("mkdir", name, errNotDir)
			}
			child = resolved
		} else if !child.isDir() {
			return pathErr("mkdir", name, errNotDir)
		}
		cur = child
	}
	return nil
}

// Remove implements FileSystem.Remove (file or empty directory).
func (m *InMemoryFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, leaf, err := m.parentAndLeaf(name)
	if err != nil {
		return pathErr("remove", name, err)
	}
	child, ok := parent.entries[leaf]
	if !ok {
		return pathErr("remove", name, errNotExist)
	}
	if child.isDir() && len(child.entries) > 0 {
		return pathErr("remove", name, errors.New("directory not empty"))
	}
	m.unlink(child)
	delete(parent.entries, leaf)
	parent.modTime = m.now()
	return nil
}

// RemoveAll implements FileSystem.RemoveAll.
func (m *InMemoryFS) RemoveAll(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	abs := cleanAbs(name)
	if abs == "/" {
		// Clear the root rather than delete it.
		for k, v := range m.root.entries {
			m.freeTree(v)
			delete(m.root.entries, k)
		}
		return nil
	}
	dir, leaf := splitParent(abs)
	parent, err := m.resolveDir(dir, 0)
	if err != nil {
		if errors.Is(err, errNotExist) {
			return nil // RemoveAll of a missing path is a no-op
		}
		return pathErr("removeall", name, err)
	}
	child, ok := parent.entries[leaf]
	if !ok {
		return nil
	}
	m.freeTree(child)
	delete(parent.entries, leaf)
	parent.modTime = m.now()
	return nil
}

// Rename implements FileSystem.Rename.
func (m *InMemoryFS) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	oParent, oLeaf, err := m.parentAndLeaf(oldpath)
	if err != nil {
		return pathErr("rename", oldpath, err)
	}
	node, ok := oParent.entries[oLeaf]
	if !ok {
		return pathErr("rename", oldpath, errNotExist)
	}
	nParent, nLeaf, err := m.parentAndLeaf(newpath)
	if err != nil {
		return pathErr("rename", newpath, err)
	}
	if existing, ok := nParent.entries[nLeaf]; ok {
		if existing.isDir() && len(existing.entries) > 0 {
			return pathErr("rename", newpath, errors.New("directory not empty"))
		}
		m.unlink(existing)
	}
	delete(oParent.entries, oLeaf)
	nParent.entries[nLeaf] = node
	oParent.modTime = m.now()
	nParent.modTime = m.now()
	return nil
}

// Symlink implements FileSystem.Symlink. The target is stored verbatim and only
// resolved (with confinement) at access time.
func (m *InMemoryFS) Symlink(target, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, leaf, err := m.parentAndLeaf(link)
	if err != nil {
		return pathErr("symlink", link, err)
	}
	if _, ok := parent.entries[leaf]; ok {
		return pathErr("symlink", link, errExist)
	}
	parent.entries[leaf] = &imNode{
		mode:    fs.ModeSymlink | 0o777,
		modTime: m.now(),
		target:  target,
		links:   1,
	}
	parent.modTime = m.now()
	return nil
}

// Link implements FileSystem.Link (hard link). Directories cannot be hard
// linked.
func (m *InMemoryFS) Link(target, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(target, true, 0)
	if err != nil {
		return pathErr("link", target, err)
	}
	if node.isDir() {
		return pathErr("link", target, errors.New("hard link not allowed for directory"))
	}
	parent, leaf, err := m.parentAndLeaf(link)
	if err != nil {
		return pathErr("link", link, err)
	}
	if _, ok := parent.entries[leaf]; ok {
		return pathErr("link", link, errExist)
	}
	node.links++
	parent.entries[leaf] = node
	parent.modTime = m.now()
	return nil
}

// Readlink implements FileSystem.Readlink.
func (m *InMemoryFS) Readlink(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, false, 0)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	if !node.isSymlink() {
		return "", pathErr("readlink", name, errors.New("not a symlink"))
	}
	return node.target, nil
}

// Chmod implements FileSystem.Chmod.
func (m *InMemoryFS) Chmod(name string, mode fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, err := m.resolve(name, true, 0)
	if err != nil {
		return pathErr("chmod", name, err)
	}
	node.mode = (node.mode &^ fs.ModePerm) | (mode & fs.ModePerm)
	node.modTime = m.now()
	return nil
}

// unlink decrements a node's link count and frees its bytes when it reaches 0.
func (m *InMemoryFS) unlink(n *imNode) {
	n.links--
	if n.links <= 0 && !n.isDir() {
		m.total -= int64(len(n.data))
		n.data = nil
	}
}

// freeTree recursively frees a subtree's accounted bytes.
func (m *InMemoryFS) freeTree(n *imNode) {
	if n.isDir() {
		for _, c := range n.entries {
			m.freeTree(c)
		}
		return
	}
	n.links--
	if n.links <= 0 {
		m.total -= int64(len(n.data))
		n.data = nil
	}
}

// snapshot deep-copies the entire tree, used by Shell.Snapshot.
func (m *InMemoryFS) snapshot() *InMemoryFS {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := &InMemoryFS{
		clock:        m.clock,
		maxFileBytes: m.maxFileBytes,
		maxTotal:     m.maxTotal,
		total:        m.total,
	}
	cp.root = copyNode(m.root)
	return cp
}

func copyNode(n *imNode) *imNode {
	c := &imNode{
		mode:    n.mode,
		modTime: n.modTime,
		target:  n.target,
		links:   n.links,
	}
	if n.isDir() {
		c.entries = make(map[string]*imNode, len(n.entries))
		for k, v := range n.entries {
			c.entries[k] = copyNode(v)
		}
	} else {
		c.data = append([]byte(nil), n.data...)
	}
	return c
}

// --- file info / dir entry ---

type imFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func newFileInfo(name string, n *imNode) fs.FileInfo {
	return imFileInfo{
		name:    name,
		size:    int64(len(n.data)),
		mode:    n.mode,
		modTime: n.modTime,
		isDir:   n.isDir(),
	}
}

func (fi imFileInfo) Name() string       { return fi.name }
func (fi imFileInfo) Size() int64        { return fi.size }
func (fi imFileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi imFileInfo) ModTime() time.Time { return fi.modTime }
func (fi imFileInfo) IsDir() bool        { return fi.isDir }
func (fi imFileInfo) Sys() any           { return nil }

// --- open file handle ---

type imFile struct {
	fsys   *InMemoryFS
	node   *imNode
	name   string
	offset int64
	read   bool
	write  bool
	append bool
	closed bool
}

// Read implements io.Reader against the file's current contents.
func (f *imFile) Read(p []byte) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.closed {
		return 0, pathErr("read", f.name, fs.ErrClosed)
	}
	if f.node.isDir() {
		return 0, pathErr("read", f.name, errIsDir)
	}
	if f.offset >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.node.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

// Write implements io.Writer, enforcing the S7 per-file and total size caps.
func (f *imFile) Write(p []byte) (int, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.closed {
		return 0, pathErr("write", f.name, fs.ErrClosed)
	}
	if !f.write {
		return 0, pathErr("write", f.name, errors.New("file not opened for writing"))
	}
	if f.append {
		f.offset = int64(len(f.node.data))
	}
	end := f.offset + int64(len(p))
	if f.fsys.maxFileBytes > 0 && end > f.fsys.maxFileBytes {
		return 0, &LimitError{Kind: LimitFileBytes, Limit: f.fsys.maxFileBytes}
	}
	delta := end - int64(len(f.node.data))
	if delta < 0 {
		delta = 0
	}
	if f.fsys.maxTotal > 0 && f.fsys.total+delta > f.fsys.maxTotal {
		return 0, &LimitError{Kind: LimitTotalFSBytes, Limit: f.fsys.maxTotal}
	}
	if end > int64(len(f.node.data)) {
		grown := make([]byte, end)
		copy(grown, f.node.data)
		f.node.data = grown
		f.fsys.total += delta
	}
	copy(f.node.data[f.offset:], p)
	f.offset = end
	f.node.modTime = f.fsys.now()
	return len(p), nil
}

// Seek implements io.Seeker.
func (f *imFile) Seek(offset int64, whence int) (int64, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.closed {
		return 0, pathErr("seek", f.name, fs.ErrClosed)
	}
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = f.offset
	case io.SeekEnd:
		base = int64(len(f.node.data))
	default:
		return 0, pathErr("seek", f.name, errors.New("invalid whence"))
	}
	np := base + offset
	if np < 0 {
		return 0, pathErr("seek", f.name, errors.New("negative position"))
	}
	f.offset = np
	return np, nil
}

// Truncate implements File.Truncate, enforcing the per-file size cap.
func (f *imFile) Truncate(size int64) error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.closed {
		return pathErr("truncate", f.name, fs.ErrClosed)
	}
	if size < 0 {
		return pathErr("truncate", f.name, errors.New("negative size"))
	}
	if f.fsys.maxFileBytes > 0 && size > f.fsys.maxFileBytes {
		return &LimitError{Kind: LimitFileBytes, Limit: f.fsys.maxFileBytes}
	}
	old := int64(len(f.node.data))
	delta := size - old
	if f.fsys.maxTotal > 0 && delta > 0 && f.fsys.total+delta > f.fsys.maxTotal {
		return &LimitError{Kind: LimitTotalFSBytes, Limit: f.fsys.maxTotal}
	}
	grown := make([]byte, size)
	copy(grown, f.node.data)
	f.node.data = grown
	f.fsys.total += delta
	f.node.modTime = f.fsys.now()
	return nil
}

// Stat implements File.Stat.
func (f *imFile) Stat() (fs.FileInfo, error) {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	return newFileInfo(path.Base(f.name), f.node), nil
}

// Close implements io.Closer.
func (f *imFile) Close() error {
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	if f.closed {
		return pathErr("close", f.name, fs.ErrClosed)
	}
	f.closed = true
	return nil
}

package gosh

import (
	"io"
	"io/fs"
)

// File is a handle to an open file in a FileSystem. It is satisfied by the
// default in-memory implementation and must be implemented by custom backends.
// The handle composes the standard streaming interfaces so that commands can
// read, write, seek, and truncate uniformly.
type File interface {
	io.Reader
	io.Writer
	io.Seeker
	io.Closer
	// Stat returns metadata for the open file.
	Stat() (fs.FileInfo, error)
	// Truncate changes the size of the file, zero-padding on growth.
	Truncate(size int64) error
}

// FileSystem is the storage backend for a Shell. The default is an in-memory,
// host-free implementation (S3); hosts may supply read-only, overlay, or
// mounted backends via WithFS.
//
// Path contract: every name passed to a FileSystem method is an absolute,
// POSIX, path.Clean-ed path rooted at "/". The Shell resolves cwd-relative
// paths to absolute before calling the FileSystem, and command authors should
// use CommandContext.ResolvePath to obtain such paths. Implementations must
// confine all access within their virtual root and must never follow paths out
// to the host filesystem (S4).
type FileSystem interface {
	// Open opens name with the given flags (os.O_* constants) and permission
	// bits, creating it when O_CREATE is set. It follows symlinks in the path.
	Open(name string, flag int, perm fs.FileMode) (File, error)
	// Stat returns metadata for name, following symlinks.
	Stat(name string) (fs.FileInfo, error)
	// Lstat returns metadata for name without following a final symlink.
	Lstat(name string) (fs.FileInfo, error)
	// ReadDir lists the entries of the directory name, sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)
	// Mkdir creates a single directory.
	Mkdir(name string, perm fs.FileMode) error
	// MkdirAll creates name and any missing parents.
	MkdirAll(name string, perm fs.FileMode) error
	// Remove removes a single file or empty directory.
	Remove(name string) error
	// RemoveAll removes name and any children it contains.
	RemoveAll(name string) error
	// Rename moves oldpath to newpath within the same FileSystem.
	Rename(oldpath, newpath string) error
	// Symlink creates a symbolic link at link pointing to target.
	Symlink(target, link string) error
	// Link creates a hard link at link referring to the same file as target.
	Link(target, link string) error
	// Readlink returns the target of the symbolic link name.
	Readlink(name string) (string, error)
	// Chmod changes the permission bits of name.
	Chmod(name string, mode fs.FileMode) error
}

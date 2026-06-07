package importcheck

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedDirect lists import paths no first-party gosh package may import
// directly. os/exec would allow spawning host processes; net would allow raw
// host network egress. (net/http is permitted only for the NetworkPolicy type
// shape; the gated curl command and its egress live in a separate, opt-in
// package built later.)
var bannedDirect = map[string]bool{
	"os/exec": true,
	"net":     true,
}

// moduleRoot returns the repository root (two levels up from this test's
// package directory: internal/importcheck -> module root).
func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// TestNoBannedDirectImports walks every directory in the module that contains
// Go source and asserts that none of the first-party packages directly import a
// banned path (S27).
func TestNoBannedDirectImports(t *testing.T) {
	root := moduleRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if path != root && (base == ".git" || base == "testdata" || strings.HasPrefix(base, "_")) {
			return filepath.SkipDir
		}

		pkg, ierr := build.ImportDir(path, build.ImportComment)
		if ierr != nil {
			return nil
		}

		all := append([]string{}, pkg.Imports...)
		all = append(all, pkg.TestImports...)
		all = append(all, pkg.XTestImports...)

		for _, imp := range all {
			if bannedDirect[imp] {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("package %q (%s) directly imports banned path %q (S27)", pkg.Name, rel, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

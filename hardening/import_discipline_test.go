package hardening_test

import "testing"

// TestImportDisciplineS27 documents the S27 import-boundary sanity check. The
// repository's internal/importcheck package owns the full audited import walk.
func TestImportDisciplineS27(t *testing.T) {
	t.Skip("S27 os/exec import discipline is covered by internal/importcheck; hardening avoids duplicating it.")
}

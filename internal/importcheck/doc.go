package importcheck

// This package hosts the S27 import-allow-list test. It walks every first-party
// Go package in the module and asserts none of them DIRECTLY import os/exec or
// net, which would create a path from a script to host process execution or
// network egress. Third-party dependencies (notably mvdan.cc/sh, which uses
// os/exec internally but whose exec/FS seams gosh fully overrides) are out of
// scope: gosh's guarantee is that its OWN code never reaches for those
// capabilities, while the runtime poison-handler tests cover the override.

// Package deps exists solely to pin the third-party dependencies that the
// parallel command-group packages (built later, in separate packages) will
// rely on, so that `go mod tidy` keeps them in go.mod even before any code in
// this repository imports them directly.
//
// Those command-group agents are forbidden from editing go.mod, so every
// dependency they need must already be required here. This file references each
// module with a blank import for that single purpose; it contains no logic and
// is never executed.
package deps

import (
	// jq engine, used by the future `jq` command.
	_ "github.com/itchyny/gojq"
	// awk engine, used by the future `awk` command.
	_ "github.com/benhoyt/goawk/interp"
	_ "github.com/benhoyt/goawk/parser"
	// TOML codec, used by the future `yq`/data commands.
	_ "github.com/BurntSushi/toml"
	// YAML codec, used by the future `yq`/data commands.
	_ "gopkg.in/yaml.v3"
	// HTML parser, used by the future HTML-to-markdown helper command.
	_ "golang.org/x/net/html"
)

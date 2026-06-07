// Package textlang implements sandboxed awk and sed commands for gosh.
package textlang

import "github.com/darylcecile/gosh"

// Commands returns the text-language command group: awk and sed.
func Commands() []gosh.Command {
	return []gosh.Command{awkCommand{}, sedCommand{}}
}

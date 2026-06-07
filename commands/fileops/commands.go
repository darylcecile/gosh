package fileops

import "github.com/darylcecile/gosh"

// Commands returns the file operation command group for gosh.
func Commands() []gosh.Command {
	return []gosh.Command{
		catCommand(),
		cpCommand(),
		mvCommand(),
		rmCommand(),
		rmdirCommand(),
		mkdirCommand(),
		lsCommand(),
		lnCommand(),
		readlinkCommand(),
		statCommand(),
		touchCommand(),
		treeCommand(),
		fileCommand(),
	}
}

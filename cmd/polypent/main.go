// Command polypent is the operator CLI for the PolyPent platform.
//
// Phase 0: --version only. Behavior arrives in later phases per
// docs/migration-plan.md.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/silvance/polypent/internal/version"
)

const binaryName = "polypent"

func main() {
	fs := flag.NewFlagSet(binaryName, flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println(version.String(binaryName))
		return
	}

	fmt.Fprintln(os.Stderr, binaryName+": not implemented yet (Phase 0 scaffolding)")
	os.Exit(1)
}

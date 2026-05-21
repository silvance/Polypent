// Package version exposes build metadata shared by the polypent binaries.
//
// Values are overridable at link time via -ldflags:
//
//	go build -ldflags "-X github.com/silvance/polypent/internal/version.Version=v0.1.0
//	                   -X github.com/silvance/polypent/internal/version.Commit=$(git rev-parse HEAD)
//	                   -X github.com/silvance/polypent/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a single-line, human-readable version banner.
func String(binary string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", binary, Version, Commit, Date)
}

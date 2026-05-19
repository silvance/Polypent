package version

import (
	"strings"
	"testing"
)

func TestStringContainsBinaryAndVersion(t *testing.T) {
	got := String("polypentd")
	if !strings.HasPrefix(got, "polypentd ") {
		t.Fatalf("expected banner to start with binary name, got %q", got)
	}
	if !strings.Contains(got, Version) {
		t.Fatalf("expected banner to contain Version=%q, got %q", Version, got)
	}
}

func TestDefaultsArePlaceholders(t *testing.T) {
	// Phase 0 ships with placeholder defaults; CI builds will override via ldflags.
	for name, v := range map[string]string{"Version": Version, "Commit": Commit, "Date": Date} {
		if v == "" {
			t.Errorf("%s must not be empty even before ldflags injection", name)
		}
	}
}

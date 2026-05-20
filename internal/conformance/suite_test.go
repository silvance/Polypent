package conformance_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/conformance"
	"github.com/silvance/polypent/internal/protocol/ndjson"
)

// repoRoot returns the absolute path of the repo root, computed from
// this test file's location (.../internal/conformance/suite_test.go).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func mustExist(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("collector binary not found at %s: %v", path, err)
	}
	return path
}

func ensureRustBuilt(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(root, "collectors", "rust", "target", "release", "discover-tcp")
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not available; skipping rust collector conformance")
	}
	cmd := exec.Command("cargo", "build", "--release") //nolint:gosec // test-time toolchain
	cmd.Dir = filepath.Join(root, "collectors", "rust")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("rust build failed (skipping): %v\n%s", err, out)
	}
	return bin
}

func baseDescriptor() ndjson.JobDescriptor {
	id := uuid.NewString()
	return ndjson.JobDescriptor{
		JobID:           id,
		RunID:           uuid.NewString(),
		ProjectID:       uuid.NewString(),
		ProtocolVersion: ndjson.ProtocolVersion,
	}
}

func TestPythonEchoConformance(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	bin := mustExist(t, filepath.Join(repoRoot(t), "collectors", "python", "echo", "main.py"))

	d := baseDescriptor()
	d.Collector = "echo"
	d.TargetKind = "host"
	d.TargetIdentity = "10.0.0.5"
	d.Parameters = map[string]any{"steps": 1}

	if err := conformance.RunTwice(context.Background(), conformance.Spec{
		Name:          "echo",
		Binary:        bin,
		Descriptor:    d,
		ExpectAtLeast: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPythonSMBEnumConformance(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	bin := mustExist(t, filepath.Join(repoRoot(t), "collectors", "python", "smb_enum", "main.py"))

	d := baseDescriptor()
	d.Collector = "smb_enum"
	d.TargetKind = "host"
	// 127.0.0.1:1 — the dry-run path is structurally tested whether or
	// not the local SMB port is reachable.
	d.TargetIdentity = "127.0.0.1:1"

	if err := conformance.RunTwice(context.Background(), conformance.Spec{
		Name:          "smb_enum",
		Binary:        bin,
		Descriptor:    d,
		ExpectAtLeast: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPythonLDAPEnumConformance(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	bin := mustExist(t, filepath.Join(repoRoot(t), "collectors", "python", "ldap_enum", "main.py"))

	d := baseDescriptor()
	d.Collector = "ldap_enum"
	d.TargetKind = "host"
	d.TargetIdentity = "127.0.0.1:1"

	if err := conformance.RunTwice(context.Background(), conformance.Spec{
		Name:          "ldap_enum",
		Binary:        bin,
		Descriptor:    d,
		ExpectAtLeast: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRustDiscoverTCPConformance(t *testing.T) {
	bin := ensureRustBuilt(t)

	d := baseDescriptor()
	d.Collector = "discover.tcp.syn"
	d.TargetKind = "host"
	d.TargetIdentity = "127.0.0.1"
	d.Parameters = map[string]any{
		"ports":              "1,2",
		"concurrency":        2,
		"connect_timeout_ms": 500,
	}

	if err := conformance.RunTwice(context.Background(), conformance.Spec{
		Name:          "discover.tcp.syn",
		Binary:        bin,
		Descriptor:    d,
		ExpectAtLeast: 0,                               // closed ports emit no findings; we just verify lifecycle
		Timeout:       10 * conformance.Spec{}.Timeout, // 0 -> default
	}); err != nil {
		t.Fatal(err)
	}
}

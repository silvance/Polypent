package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("POLYPENT_DATABASE_URL", "postgres://localhost/p")
	t.Setenv("POLYPENT_AUDIT_SIGNING_KEY", "test-key-32-bytes-aaaaaaaaaaaaaa")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "127.0.0.1:8080" {
		t.Errorf("default addr = %q", cfg.Server.Addr)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default log level = %q", cfg.Log.Level)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	t.Setenv("POLYPENT_DATABASE_URL", "postgres://localhost/p")
	t.Setenv("POLYPENT_AUDIT_SIGNING_KEY", "k")
	p := writeTempYAML(t, "server:\n  bogus: 1\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error on unknown YAML key, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should mention offending key, got: %v", err)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	_ = os.Unsetenv("POLYPENT_DATABASE_URL")
	t.Setenv("POLYPENT_AUDIT_SIGNING_KEY", "k")
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "database.url") {
		t.Fatalf("expected database.url error, got: %v", err)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	p := writeTempYAML(t, "server:\n  addr: 127.0.0.1:9000\ndatabase:\n  url: postgres://x\naudit:\n  signing_key: k\n")
	t.Setenv("POLYPENT_SERVER_ADDR", "0.0.0.0:1234")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "0.0.0.0:1234" {
		t.Errorf("expected env override; got %q", cfg.Server.Addr)
	}
}

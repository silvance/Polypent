// Package config loads and validates the polypentd configuration.
//
// Source precedence (highest first):
//   - POLYPENT_* environment variables for explicitly-supported overrides
//   - YAML configuration file path passed at startup
//
// Unknown keys are rejected so typos in the YAML file fail loudly.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full daemon configuration.
type Config struct {
	Server   Server   `yaml:"server"`
	Database Database `yaml:"database"`
	Audit    Audit    `yaml:"audit"`
	Log      Log      `yaml:"log"`
	Queue    Queue    `yaml:"queue"`
	Storage  Storage  `yaml:"storage"`
}

type Storage struct {
	// ArtifactsDir is the root directory for the local artifact store.
	ArtifactsDir string `yaml:"artifacts_dir"`
}

type Queue struct {
	Workers       int           `yaml:"workers"`
	LeaseDuration time.Duration `yaml:"lease_duration"`
	PollInterval  time.Duration `yaml:"poll_interval"`
}

type Server struct {
	Addr            string        `yaml:"addr"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type Database struct {
	URL string `yaml:"url"`
}

type Audit struct {
	// SigningKey is the HMAC key for the audit event chain. Must be at
	// least 32 bytes of high-entropy material in production.
	SigningKey string `yaml:"signing_key"`
	// ManifestSigningKey is the HMAC key for signed run manifests. Kept
	// separate from SigningKey so that compromise of the audit key does
	// not let an attacker forge manifests (and vice versa). When unset,
	// it falls back to SigningKey with a one-time warning at boot —
	// this is acceptable in development, NOT in production.
	ManifestSigningKey string `yaml:"manifest_signing_key"`
}

type Log struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is "text" or "json".
	Format string `yaml:"format"`
}

// Default returns a Config with safe defaults applied.
func Default() Config {
	return Config{
		Server: Server{
			Addr:            "127.0.0.1:8080",
			ShutdownTimeout: 10 * time.Second,
		},
		Log: Log{Level: "info", Format: "text"},
		Queue: Queue{
			Workers:       4,
			LeaseDuration: 2 * time.Minute,
			PollInterval:  500 * time.Millisecond,
		},
		Storage: Storage{
			ArtifactsDir: "./var/polypent/artifacts",
		},
	}
}

// Load reads a YAML file at path and applies env-var overrides.
// If path is empty, defaults plus env overrides are used.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied at startup
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnv(&cfg)

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	if v, ok := os.LookupEnv("POLYPENT_SERVER_ADDR"); ok {
		c.Server.Addr = v
	}
	if v, ok := os.LookupEnv("POLYPENT_DATABASE_URL"); ok {
		c.Database.URL = v
	}
	if v, ok := os.LookupEnv("POLYPENT_AUDIT_SIGNING_KEY"); ok {
		c.Audit.SigningKey = v
	}
	if v, ok := os.LookupEnv("POLYPENT_LOG_LEVEL"); ok {
		c.Log.Level = v
	}
	if v, ok := os.LookupEnv("POLYPENT_LOG_FORMAT"); ok {
		c.Log.Format = v
	}
}

func (c Config) validate() error {
	if c.Database.URL == "" {
		return errors.New("database.url is required")
	}
	if c.Audit.SigningKey == "" {
		return errors.New("audit.signing_key is required")
	}
	if c.Server.Addr == "" {
		return errors.New("server.addr is required")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: unsupported value %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format: unsupported value %q", c.Log.Format)
	}
	return nil
}

// Package telemetry wires up structured logging for polypentd.
//
// We standardize on log/slog from the stdlib. Handlers are picked from
// configuration; everything else in the codebase just uses slog directly.
package telemetry

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// NewLogger returns a *slog.Logger configured per the provided level and
// format strings. Caller is responsible for choosing the writer (os.Stderr in
// production, a buffer in tests).
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
	return slog.New(h), nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// Package conformance is a black-box harness that validates an external
// collector against the NDJSON wire protocol defined in
// docs/collector-protocol.md.
//
// A collector is "conformant" if, given a valid JobDescriptor on stdin,
// it:
//
//  1. Emits a hello event first, carrying a name, version, and matching
//     protocol_version string.
//  2. Emits a terminal done (or error+exit-non-zero) event.
//  3. Every finding event carries a non-empty dedup_key.
//  4. The same JobDescriptor produces the same set of finding dedup_keys
//     on a second run — determinism is the contract that makes dedup
//     work platform-wide.
//
// The harness is intentionally process-driven: it spawns the collector
// binary, writes the descriptor on stdin, and parses stdout. It does
// not link the collector as a library.
package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"time"

	"github.com/silvance/polypent/internal/protocol/ndjson"
)

// Spec describes one collector under test.
type Spec struct {
	Name           string   // expected `hello.name`
	Binary         string   // absolute path to the executable
	Args           []string // extra args; usually empty
	Descriptor     ndjson.JobDescriptor
	ExpectAtLeast  int           // minimum findings expected on a run (>=0)
	ExpectExitCode int           // 0 unless the spec is exercising an error path
	Timeout        time.Duration // per-run wall clock; 0 = 15s
}

// Result is what one Run() call produces.
type Result struct {
	Events   []ndjson.Envelope
	Stderr   string
	ExitCode int
}

// Run executes spec once and returns the parsed event stream.
func Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Binary == "" {
		return Result{}, errors.New("conformance: empty binary path")
	}
	timeout := spec.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Binary, spec.Args...) //nolint:gosec // operator-configured

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, fmt.Errorf("stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("stdout: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start: %w", err)
	}
	if err := ndjson.WriteDescriptor(stdin, spec.Descriptor); err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		return Result{}, fmt.Errorf("write descriptor: %w", err)
	}
	_ = stdin.Close()

	rdr := ndjson.NewReader(stdout, 0)
	var events []ndjson.Envelope
	for {
		ev, err := rdr.Next(runCtx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return Result{}, fmt.Errorf("read: %w (stderr=%s)", err, stderr.String())
		}
		events = append(events, ev)
		if ev.Type == ndjson.EventDone {
			break
		}
	}

	waitErr := cmd.Wait()
	code := 0
	if exitErr := (&exec.ExitError{}); errors.As(waitErr, &exitErr) {
		code = exitErr.ExitCode()
	} else if waitErr != nil {
		return Result{Events: events, Stderr: stderr.String()},
			fmt.Errorf("wait: %w (stderr=%s)", waitErr, stderr.String())
	}

	return Result{Events: events, Stderr: stderr.String(), ExitCode: code}, nil
}

// Check applies the protocol-conformance assertions to one Result.
// Returns nil on success; a non-nil error describes the first failure.
func Check(spec Spec, res Result) error {
	if len(res.Events) == 0 {
		return errors.New("no events emitted")
	}
	hello := res.Events[0]
	if hello.Type != ndjson.EventHello {
		return fmt.Errorf("first event = %q, want %q", hello.Type, ndjson.EventHello)
	}
	var hp ndjson.HelloPayload
	if err := ndjson.DecodePayload(hello, &hp); err != nil {
		return fmt.Errorf("decode hello: %w", err)
	}
	if hp.Name != spec.Name {
		return fmt.Errorf("hello.name = %q, want %q", hp.Name, spec.Name)
	}
	if hp.ProtocolVersion == "" {
		return errors.New("hello.protocol_version is empty")
	}

	// Must end on `done` unless we expected an error-path exit.
	last := res.Events[len(res.Events)-1]
	if spec.ExpectExitCode == 0 && last.Type != ndjson.EventDone {
		return fmt.Errorf("terminal event = %q, want %q", last.Type, ndjson.EventDone)
	}

	// Every finding must carry a non-empty dedup_key.
	findings := 0
	for _, ev := range res.Events {
		if ev.Type != ndjson.EventFinding {
			continue
		}
		var fp ndjson.FindingPayload
		if err := ndjson.DecodePayload(ev, &fp); err != nil {
			return fmt.Errorf("decode finding: %w", err)
		}
		if fp.DedupKey == "" {
			return fmt.Errorf("finding %q has empty dedup_key", fp.Title)
		}
		findings++
	}
	if findings < spec.ExpectAtLeast {
		return fmt.Errorf("found %d findings, expected >= %d", findings, spec.ExpectAtLeast)
	}

	if res.ExitCode != spec.ExpectExitCode {
		return fmt.Errorf("exit code = %d, want %d", res.ExitCode, spec.ExpectExitCode)
	}

	return nil
}

// DedupKeys returns the sorted set of dedup_keys from a Result.
// Two runs of the same spec must produce identical slices.
func DedupKeys(res Result) ([]string, error) {
	var keys []string
	for _, ev := range res.Events {
		if ev.Type != ndjson.EventFinding {
			continue
		}
		var fp ndjson.FindingPayload
		if err := ndjson.DecodePayload(ev, &fp); err != nil {
			return nil, err
		}
		if fp.DedupKey != "" {
			keys = append(keys, fp.DedupKey)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// RunTwice runs the spec twice and asserts dedup_keys match. This is
// the determinism contract — without it, the platform's dedup
// machinery cannot rely on a collector's "same input → same key"
// guarantee.
func RunTwice(ctx context.Context, spec Spec) error {
	a, err := Run(ctx, spec)
	if err != nil {
		return fmt.Errorf("first run: %w", err)
	}
	if err := Check(spec, a); err != nil {
		return fmt.Errorf("first run: %w", err)
	}
	b, err := Run(ctx, spec)
	if err != nil {
		return fmt.Errorf("second run: %w", err)
	}
	if err := Check(spec, b); err != nil {
		return fmt.Errorf("second run: %w", err)
	}
	ka, err := DedupKeys(a)
	if err != nil {
		return err
	}
	kb, err := DedupKeys(b)
	if err != nil {
		return err
	}
	if !sliceEq(ka, kb) {
		return fmt.Errorf("non-deterministic dedup_keys: %v vs %v", ka, kb)
	}
	return nil
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

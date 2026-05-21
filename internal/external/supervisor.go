// Package external implements the supervisor that runs a child-process
// collector over the NDJSON wire protocol from internal/protocol/ndjson.
//
// A Supervisor adapts an external binary into something the in-process
// worker can call: it implements collector.Collector, spawns the binary,
// writes a JobDescriptor on stdin, parses NDJSON events on stdout, and
// captures stderr into a capped buffer that becomes a log event when the
// job finishes (good or bad).
package external

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/protocol/ndjson"
	"github.com/silvance/polypent/internal/queue"
)

// MaxStderrBytes caps captured stderr.
const MaxStderrBytes = 1 << 20

// Supervisor wraps one external collector binary.
type Supervisor struct {
	name    string
	binary  string
	args    []string
	timeout time.Duration
}

// NewSupervisor constructs a Supervisor.
// `timeout` is an absolute wall-clock cap on the child; a zero value
// means "honor the job's deadline only".
func NewSupervisor(name, binary string, args []string, timeout time.Duration) *Supervisor {
	return &Supervisor{name: name, binary: binary, args: args, timeout: timeout}
}

func (s *Supervisor) Name() string { return s.name }

// Execute satisfies collector.Collector.
func (s *Supervisor) Execute(ctx context.Context, job queue.Job, emit collector.Emit) error {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, s.binary, s.args...) //nolint:gosec // operator-configured binary path
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("external: stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("external: stdout: %w", err)
	}
	stderrBuf := &cappedBuffer{cap: MaxStderrBytes}
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("external: start: %w", err)
	}

	desc := ndjson.JobDescriptor{
		JobID:          job.ID.String(),
		RunID:          job.RunID.String(),
		ProjectID:      job.ProjectID.String(),
		Collector:      s.name,
		TargetKind:     job.TargetKind,
		TargetIdentity: job.TargetIdentity,
		Parameters:     job.Parameters,
	}
	if job.Deadline != nil {
		desc.DeadlineUnixSec = job.Deadline.Unix()
	}
	if err := ndjson.WriteDescriptor(stdin, desc); err != nil {
		_ = stdin.Close()
		s.kill(cmd)
		return fmt.Errorf("external: write descriptor: %w", err)
	}
	_ = stdin.Close()

	rdr := ndjson.NewReader(stdout, 0)
	var parseErr error
	for {
		env, err := rdr.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			parseErr = err
			break
		}
		var payload map[string]any
		if len(env.Payload) > 0 {
			if err := json.Unmarshal(env.Payload, &payload); err != nil {
				parseErr = fmt.Errorf("external: decode payload: %w", err)
				break
			}
		}
		if err := emit(ctx, collector.Event{Kind: string(env.Type), Payload: payload}); err != nil {
			parseErr = err
			break
		}
		if env.Type == ndjson.EventDone {
			break
		}
	}

	waitErr := s.waitOrKill(ctx, cmd, parseErr)

	if stderrBuf.Len() > 0 {
		_ = emit(context.Background(), collector.Event{
			Kind: "log",
			Payload: map[string]any{
				"level":   "info",
				"message": "captured stderr",
				"stderr":  stderrBuf.String(),
			},
		})
	}

	if parseErr != nil {
		return parseErr
	}
	return waitErr
}

func (s *Supervisor) waitOrKill(ctx context.Context, cmd *exec.Cmd, parseErr error) error {
	if parseErr != nil || ctx.Err() != nil {
		s.kill(cmd)
	}
	err := cmd.Wait()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && parseErr == nil {
		return fmt.Errorf("external: exited non-zero: %w", err)
	}
	if errors.As(err, &exitErr) {
		return parseErr
	}
	return err
}

func (s *Supervisor) kill(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	} else {
		_ = cmd.Process.Kill()
	}
}

// cappedBuffer retains the first cap bytes and drops the rest.
type cappedBuffer struct {
	buf bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remain := c.cap - c.buf.Len()
	if remain <= 0 {
		return len(p), nil
	}
	if remain >= len(p) {
		return c.buf.Write(p)
	}
	_, _ = c.buf.Write(p[:remain])
	return len(p), nil
}

func (c *cappedBuffer) Len() int       { return c.buf.Len() }
func (c *cappedBuffer) String() string { return c.buf.String() }

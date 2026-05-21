// Package ndjson implements the line-delimited JSON wire protocol used
// between polypentd and external collectors.
//
// One JSON object per line, UTF-8, terminated by '\n'. Each line carries a
// `type` discriminator that names the event:
//
//	hello              collector announces itself
//	ack                collector acknowledges the job descriptor
//	progress           {"done":N,"total":M,"stage":"..."}
//	log                {"level":"info","message":"..."}
//	target_discovered  proposes a target (scope-checked at ingestion)
//	finding            structured finding payload
//	artifact_ref       collector points at a file on disk to ingest
//	error              recoverable error with context
//	done               terminal event with summary
//
// Phase 4 deliberately does not add artifact.begin/chunk/end inline
// streaming; artifact_ref is enough for the reference Python collector
// and keeps the protocol small while collectors are still settling.
package ndjson

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// EventType is the discriminator string written to the wire.
type EventType string

const (
	EventHello            EventType = "hello"
	EventAck              EventType = "ack"
	EventProgress         EventType = "progress"
	EventLog              EventType = "log"
	EventTargetDiscovered EventType = "target_discovered"
	EventFinding          EventType = "finding"
	EventArtifactRef      EventType = "artifact_ref"
	EventError            EventType = "error"
	EventDone             EventType = "done"
)

// ProtocolVersion the core understands. Collectors should announce the
// same string in their hello event.
const ProtocolVersion = "polypent-ndjson/1"

// Envelope is the parsed line. Payload is the raw JSON object after the
// `type` field has been split out; callers convert it to a typed struct.
type Envelope struct {
	Type    EventType
	Raw     json.RawMessage // entire line (for re-emission to job_events)
	Payload json.RawMessage // payload field, if present
}

// HelloPayload is what the collector announces.
type HelloPayload struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocol_version"`
}

// ProgressPayload is `progress`.
type ProgressPayload struct {
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Stage string `json:"stage,omitempty"`
}

// LogPayload is `log`.
type LogPayload struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// TargetDiscoveredPayload is `target_discovered`.
type TargetDiscoveredPayload struct {
	Kind       string         `json:"kind"`
	Identity   string         `json:"identity"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// FindingPayload is `finding`.
//
// dedup_key is required and is the collector's deterministic identity for
// the finding: re-running the same collector against the same target with
// the same finding produces the same dedup_key.
//
// evidence_refs are labels the collector previously used in artifact_ref
// events within the same job; the supervisor resolves them to sha256s.
type FindingPayload struct {
	Kind         string         `json:"kind"`
	Severity     string         `json:"severity"`
	Title        string         `json:"title"`
	Description  string         `json:"description,omitempty"`
	CVSS         string         `json:"cvss,omitempty"`
	DedupKey     string         `json:"dedup_key"`
	EvidenceRefs []string       `json:"evidence_refs,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
}

// ArtifactRefPayload is `artifact_ref`.
//
// Label is a stable name the collector uses elsewhere in the same job to
// reference this artifact in evidence_refs.
type ArtifactRefPayload struct {
	Path  string `json:"path"`
	Mime  string `json:"mime,omitempty"`
	Label string `json:"label,omitempty"`
}

// ErrorPayload is `error`.
type ErrorPayload struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Fatal   bool   `json:"fatal,omitempty"`
}

// DonePayload is `done`.
type DonePayload struct {
	Summary map[string]any `json:"summary,omitempty"`
}

// Reader parses lines from r as NDJSON events.
type Reader struct {
	br      *bufio.Reader
	maxLine int
}

// NewReader wraps r. lineLimit caps individual line length (1 MiB by
// default) so a malicious or buggy collector can't OOM the worker.
func NewReader(r io.Reader, lineLimit int) *Reader {
	if lineLimit <= 0 {
		lineLimit = 1 << 20
	}
	return &Reader{br: bufio.NewReaderSize(r, 64<<10), maxLine: lineLimit}
}

// Next blocks until one event is decoded or the underlying reader ends.
// It honors ctx by checking before each read; for hard cancellation, the
// caller should close the underlying reader.
func (r *Reader) Next(ctx context.Context) (Envelope, error) {
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	line, err := r.readLine()
	if err != nil {
		return Envelope{}, err
	}
	if len(line) == 0 {
		// blank line, try again
		return r.Next(ctx)
	}
	var head struct {
		Type    EventType       `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return Envelope{}, fmt.Errorf("ndjson: parse: %w", err)
	}
	if head.Type == "" {
		return Envelope{}, errors.New("ndjson: missing type")
	}
	return Envelope{Type: head.Type, Raw: append(json.RawMessage(nil), line...), Payload: head.Payload}, nil
}

func (r *Reader) readLine() ([]byte, error) {
	// We can't use ReadBytes('\n') with an unbounded buffer; instead we
	// read in segments and enforce maxLine ourselves.
	var buf []byte
	for {
		seg, isPrefix, err := r.br.ReadLine()
		if err != nil {
			return nil, err
		}
		buf = append(buf, seg...)
		if len(buf) > r.maxLine {
			return nil, fmt.Errorf("ndjson: line exceeds %d bytes", r.maxLine)
		}
		if !isPrefix {
			break
		}
	}
	return buf, nil
}

// DecodePayload unmarshals env.Payload into v.
func DecodePayload(env Envelope, v any) error {
	if len(env.Payload) == 0 {
		return errors.New("ndjson: empty payload")
	}
	return json.Unmarshal(env.Payload, v)
}

// JobDescriptor is what the supervisor writes on the collector's stdin as
// one JSON object terminated by '\n' before sending EOF.
//
// Collectors should treat the descriptor as authoritative: the targets
// listed here have already been scope-clamped at plan time and again at
// dispatch time, so the collector must not range beyond them.
type JobDescriptor struct {
	JobID           string         `json:"job_id"`
	RunID           string         `json:"run_id"`
	ProjectID       string         `json:"project_id"`
	Collector       string         `json:"collector"`
	TargetKind      string         `json:"target_kind"`
	TargetIdentity  string         `json:"target_identity"`
	Parameters      map[string]any `json:"parameters,omitempty"`
	DeadlineUnixSec int64          `json:"deadline_unix_sec,omitempty"`
	ProtocolVersion string         `json:"protocol_version"`
}

// WriteDescriptor serializes the descriptor as a single line.
func WriteDescriptor(w io.Writer, d JobDescriptor) error {
	if d.ProtocolVersion == "" {
		d.ProtocolVersion = ProtocolVersion
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

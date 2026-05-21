package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
)

type runCreateTarget struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	URL      string `json:"url,omitempty"`
}

type runCreateInput struct {
	Capabilities    []string          `json:"capabilities"`
	Targets         []runCreateTarget `json:"targets"`
	Parameters      map[string]any    `json:"parameters,omitempty"`
	Priority        int               `json:"priority,omitempty"`
	DeadlineSeconds int               `json:"deadline_seconds,omitempty"`
	// SecretKeys lists project-scoped secrets to make available to the
	// collector at exec time. The plaintext values are resolved by the
	// worker in-memory; the key names persist in jobs.parameters.
	SecretKeys []string `json:"secret_keys,omitempty"`
}

func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	pr, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// operator, owner, or admin
	switch pr.Role {
	case auth.RoleAdmin:
	case auth.RoleOwner, auth.RoleOperator, auth.RoleAutomation:
		if pr.ProjectID == nil || *pr.ProjectID != projectID {
			writeError(w, http.StatusForbidden, "not your project")
			return
		}
	default:
		writeError(w, http.StatusForbidden, "insufficient role")
		return
	}

	var in runCreateInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Capabilities) == 0 {
		writeError(w, http.StatusBadRequest, "capabilities required")
		return
	}
	if len(in.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "targets required")
		return
	}
	for _, capName := range in.Capabilities {
		if _, ok := s.deps.Collectors.Get(capName); !ok {
			writeError(w, http.StatusBadRequest, "unknown collector: "+capName)
			return
		}
	}

	var deadline *time.Time
	if in.DeadlineSeconds > 0 {
		t := time.Now().Add(time.Duration(in.DeadlineSeconds) * time.Second)
		deadline = &t
	}

	targets := make([]scope.Target, 0, len(in.Targets))
	for _, t := range in.Targets {
		targets = append(targets, scope.Target{
			Kind:     scope.TargetKind(t.Kind),
			Identity: t.Identity,
			Host:     t.Host,
			Port:     t.Port,
			URL:      t.URL,
		})
	}

	runID, kept, dropped, err := s.deps.Planner.Plan(r.Context(), run.PlanInput{
		ProjectID:    projectID,
		RequestedBy:  &pr.TokenID,
		Capabilities: in.Capabilities,
		Parameters:   in.Parameters,
		Targets:      targets,
		Priority:     in.Priority,
		JobDeadline:  deadline,
		SecretKeys:   in.SecretKeys,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "run.create",
		TargetKind:   "run",
		TargetID:     runID.String(),
		Metadata: map[string]any{
			"capabilities": in.Capabilities,
			"kept":         kept,
			"dropped":      dropped,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": runID, "kept_targets": kept, "dropped_targets": dropped,
	})
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	rn, err := s.deps.Runs.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, run.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		return
	}
	if !s.authorizeProjectRead(w, r, rn.ProjectID) {
		return
	}
	writeJSON(w, http.StatusOK, rn)
}

func (s *Server) handleListRunJobs(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	rn, err := s.deps.Runs.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, run.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		return
	}
	if !s.authorizeProjectRead(w, r, rn.ProjectID) {
		return
	}
	jobs, err := s.deps.Runs.ListJobs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list jobs failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	rn, err := s.deps.Runs.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, run.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get failed")
		return
	}
	if !s.authorizeScopeWrite(w, r, rn.ProjectID) {
		return
	}
	n, err := s.deps.Queue.CancelRun(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cancel failed")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &rn.ProjectID,
		ActorTokenID: &pr.TokenID,
		Action:       "run.cancel",
		TargetKind:   "run",
		TargetID:     id.String(),
		Metadata:     map[string]any{"cancelled_jobs": n},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cancelled_jobs": n})
}

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/scope"
)

type scopeRuleInput struct {
	Order         int        `json:"order"`
	Effect        string     `json:"effect"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	PortMin       int        `json:"port_min,omitempty"`
	PortMax       int        `json:"port_max,omitempty"`
	WindowStart   *time.Time `json:"window_start,omitempty"`
	WindowEnd     *time.Time `json:"window_end,omitempty"`
	MaxConcurrent int        `json:"max_concurrent,omitempty"`
	MaxRPS        float64    `json:"max_rps,omitempty"`
	Note          string     `json:"note,omitempty"`
}

type scopeRuleOutput struct {
	ID            uuid.UUID  `json:"id"`
	Order         int        `json:"order"`
	Effect        string     `json:"effect"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	PortMin       int        `json:"port_min,omitempty"`
	PortMax       int        `json:"port_max,omitempty"`
	WindowStart   *time.Time `json:"window_start,omitempty"`
	WindowEnd     *time.Time `json:"window_end,omitempty"`
	MaxConcurrent int        `json:"max_concurrent,omitempty"`
	MaxRPS        float64    `json:"max_rps,omitempty"`
	Note          string     `json:"note,omitempty"`
}

func ruleToOutput(r scope.Rule) scopeRuleOutput {
	out := scopeRuleOutput{
		ID:            r.ID,
		Order:         r.Order,
		Effect:        string(r.Effect),
		Kind:          string(r.Kind),
		Value:         r.Value,
		PortMin:       r.PortMin,
		PortMax:       r.PortMax,
		MaxConcurrent: r.MaxConcurrent,
		MaxRPS:        r.MaxRPS,
		Note:          r.Note,
	}
	if !r.Window.Start.IsZero() {
		s := r.Window.Start
		out.WindowStart = &s
	}
	if !r.Window.End.IsZero() {
		e := r.Window.End
		out.WindowEnd = &e
	}
	return out
}

func (s *Server) handleCreateScopeRule(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeScopeWrite(w, r, projectID) {
		return
	}

	var in scopeRuleInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule := scope.Rule{
		Order:         in.Order,
		Effect:        scope.Effect(in.Effect),
		Kind:          scope.Kind(in.Kind),
		Value:         in.Value,
		PortMin:       in.PortMin,
		PortMax:       in.PortMax,
		MaxConcurrent: in.MaxConcurrent,
		MaxRPS:        in.MaxRPS,
		Note:          in.Note,
	}
	if in.WindowStart != nil {
		rule.Window.Start = *in.WindowStart
	}
	if in.WindowEnd != nil {
		rule.Window.End = *in.WindowEnd
	}
	if err := rule.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pr, _ := auth.FromContext(r.Context())
	created, err := s.deps.Scope.Create(r.Context(), projectID, rule)
	if err != nil {
		if errors.Is(err, scope.ErrOrderConflict) {
			writeError(w, http.StatusConflict, "rule order already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "scope.rule.create",
		TargetKind:   "scope_rule",
		TargetID:     created.ID.String(),
		Metadata: map[string]any{
			"effect": string(created.Effect),
			"kind":   string(created.Kind),
			"value":  created.Value,
			"order":  created.Order,
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	writeJSON(w, http.StatusCreated, ruleToOutput(created))
}

func (s *Server) handleListScopeRules(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeProjectRead(w, r, projectID) {
		return
	}
	rules, err := s.deps.Scope.List(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]scopeRuleOutput, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleToOutput(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (s *Server) handleDeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeScopeWrite(w, r, projectID) {
		return
	}
	ruleID, ok := parseUUIDPath(r, "rule_id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	if err := s.deps.Scope.Delete(r.Context(), projectID, ruleID); err != nil {
		if errors.Is(err, scope.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	pr, _ := auth.FromContext(r.Context())
	if _, err := s.deps.Audit.Append(r.Context(), audit.Event{
		ProjectID:    &projectID,
		ActorTokenID: &pr.TokenID,
		Action:       "scope.rule.delete",
		TargetKind:   "scope_rule",
		TargetID:     ruleID.String(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit append failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type scopeCheckInput struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	URL      string `json:"url,omitempty"`
}

type scopeCheckOutput struct {
	Effect string           `json:"effect"`
	Rule   *scopeRuleOutput `json:"rule,omitempty"`
	Reason string           `json:"reason"`
	Caps   scope.RateCaps   `json:"caps,omitempty"`
}

func (s *Server) handleScopeCheck(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseUUIDPath(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	if !s.authorizeProjectRead(w, r, projectID) {
		return
	}
	var in scopeCheckInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rules, err := s.deps.Scope.List(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list rules failed")
		return
	}
	tg := scope.Target{
		Kind:     scope.TargetKind(in.Kind),
		Identity: in.Identity,
		Host:     in.Host,
		Port:     in.Port,
		URL:      in.URL,
	}
	res := scope.Evaluate(tg, rules, time.Now())
	out := scopeCheckOutput{Effect: string(res.Effect), Reason: res.Reason, Caps: res.Caps}
	if res.Rule != nil {
		ro := ruleToOutput(*res.Rule)
		out.Rule = &ro
	}
	writeJSON(w, http.StatusOK, out)
}

// authorizeScopeWrite permits admin globally and owner for their own project.
func (s *Server) authorizeScopeWrite(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) bool {
	pr, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	switch pr.Role {
	case auth.RoleAdmin:
		return true
	case auth.RoleOwner:
		if pr.ProjectID != nil && *pr.ProjectID == projectID {
			return true
		}
	}
	writeError(w, http.StatusForbidden, "admin or project owner required")
	return false
}

// authorizeProjectRead permits admin globally, and any project-scoped role
// for its own project.
func (s *Server) authorizeProjectRead(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) bool {
	pr, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	if pr.Role == auth.RoleAdmin {
		return true
	}
	if pr.ProjectID != nil && *pr.ProjectID == projectID {
		return true
	}
	writeError(w, http.StatusForbidden, "not your project")
	return false
}

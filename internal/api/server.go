// Package api hosts the polypentd HTTP API. Handlers, middleware, and the
// embedded OpenAPI spec live here. The package depends on the domain stores
// (project, auth, audit) but does not import any collector or queue code —
// those wire in during later phases.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/silvance/polypent/internal/artifact"
	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/catalog"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/finding"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	"github.com/silvance/polypent/internal/target"
)

// Deps is the explicit dependency set the API needs.
type Deps struct {
	Logger       *slog.Logger
	Projects     *project.Store
	Tokens       *auth.Store
	Audit        *audit.Logger
	AuditKey     []byte // signing key, reused for manifest signatures
	Scope        *scope.Store
	Targets      *target.Store
	Planner      *run.Planner
	Runs         *run.Store
	Queue        *queue.Queue
	Collectors   *collector.Registry
	Findings     *finding.Store
	Artifacts    artifact.Store
	ArtifactMeta *artifact.MetaStore
	Catalog      *catalog.Store
}

// Server wraps an *http.Server with PolyPent's handler tree.
type Server struct {
	*http.Server
	deps Deps
}

// New builds the HTTP server.
func New(addr string, shutdownTimeout time.Duration, deps Deps) *Server {
	mux := http.NewServeMux()
	s := &Server{deps: deps}

	// Unauthenticated endpoints.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)

	// Authenticated endpoints, mounted under a sub-mux so the auth
	// middleware applies only to them.
	authed := http.NewServeMux()
	authed.HandleFunc("POST /v1/projects", s.handleCreateProject)
	authed.HandleFunc("GET /v1/projects", s.handleListProjects)
	authed.HandleFunc("GET /v1/projects/{id}", s.handleGetProject)
	authed.HandleFunc("PATCH /v1/projects/{id}", s.handleUpdateProject)
	authed.HandleFunc("POST /v1/tokens", s.handleIssueToken)
	authed.HandleFunc("GET /v1/tokens", s.handleListTokens)
	authed.HandleFunc("POST /v1/tokens/{id}/revoke", s.handleRevokeToken)

	authed.HandleFunc("POST /v1/projects/{id}/scope", s.handleCreateScopeRule)
	authed.HandleFunc("GET /v1/projects/{id}/scope", s.handleListScopeRules)
	authed.HandleFunc("DELETE /v1/projects/{id}/scope/{rule_id}", s.handleDeleteScopeRule)
	authed.HandleFunc("POST /v1/projects/{id}/scope/check", s.handleScopeCheck)
	authed.HandleFunc("POST /v1/projects/{id}/targets", s.handleUpsertTarget)
	authed.HandleFunc("GET /v1/projects/{id}/targets", s.handleListTargets)

	authed.HandleFunc("POST /v1/projects/{id}/runs", s.handleCreateRun)
	authed.HandleFunc("GET /v1/runs/{id}", s.handleGetRun)
	authed.HandleFunc("GET /v1/runs/{id}/jobs", s.handleListRunJobs)
	authed.HandleFunc("POST /v1/runs/{id}/cancel", s.handleCancelRun)
	authed.HandleFunc("GET /v1/runs/{id}/manifest", s.handleGetRunManifest)

	authed.HandleFunc("GET /v1/projects/{id}/findings", s.handleListFindings)
	authed.HandleFunc("GET /v1/artifacts/{sha}", s.handleGetArtifact)

	authed.HandleFunc("GET /v1/collectors", s.handleListCatalog)
	authed.HandleFunc("POST /v1/collectors", s.handleUpsertCatalog)
	authed.HandleFunc("DELETE /v1/collectors/{name}", s.handleDeleteCatalog)

	authedH := chain(authed,
		auth.Middleware(deps.Tokens),
	)
	mux.Handle("/v1/", authedH)

	root := chain(mux,
		requestIDMiddleware,
		recoveryMiddleware(deps.Logger),
		loggingMiddleware(deps.Logger),
	)

	s.Server = &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}
	_ = shutdownTimeout // honored by ListenAndServeWithShutdown
	return s
}

// ListenAndServeWithShutdown runs the server until ctx is cancelled, then
// performs a graceful shutdown bounded by shutdownTimeout.
func (s *Server) ListenAndServeWithShutdown(ctx context.Context, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		err := s.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return s.Shutdown(shutdownCtx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

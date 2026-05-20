package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey int

const principalKey ctxKey = 0

// FromContext returns the authenticated Principal attached to ctx, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// WithPrincipal returns a derived context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// Middleware authenticates requests via the Authorization: Bearer header.
// Unauthenticated requests get a 401 with no body — we deliberately don't
// disclose whether the token was unknown, expired, or revoked.
func Middleware(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := extractBearer(r.Header.Get("Authorization"))
			if tok == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="polypent"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p, err := store.Lookup(r.Context(), tok)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="polypent"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RequireRole returns 403 unless the caller's role is in allowed.
func RequireRole(allowed ...Role) func(http.Handler) http.Handler {
	allow := make(map[Role]struct{}, len(allowed))
	for _, r := range allowed {
		allow[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if _, ok := allow[p.Role]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractBearer(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

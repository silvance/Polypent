// Package scope is the pure authorization library at the heart of PolyPent.
//
// A Project carries an ordered list of Rules. Given a Target (and the
// current time), Evaluate returns a Result naming the Effect and the Rule
// that decided. The evaluator is deterministic, side-effect-free, and
// allocation-light: callers may evaluate scope on the hot path of job
// dispatch.
//
// Decision semantics
//
//   - Rules are evaluated in their declared order.
//   - First match wins. Effect of the matching rule is the verdict.
//   - If no rule matches, the verdict is OutOfScope. This is the safe
//     default for a pentesting platform: silence beats accident.
//
// Effects
//
//   - Allow:       the target is in scope and may be acted on
//   - Deny:        the target is forbidden (e.g. a vendor's bastion); a
//     scope violation MUST be raised if seen in a finding
//   - OutOfScope:  the target is not covered by the ruleset; treated as a
//     soft "ignore" with an audit trail
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Effect is the verdict a rule produces when it matches.
type Effect string

const (
	EffectAllow      Effect = "allow"
	EffectDeny       Effect = "deny"
	EffectOutOfScope Effect = "out_of_scope"
)

func (e Effect) Valid() bool {
	switch e {
	case EffectAllow, EffectDeny, EffectOutOfScope:
		return true
	}
	return false
}

// Kind enumerates the rule kinds the engine knows how to match.
type Kind string

const (
	KindCIDR        Kind = "cidr"         // IPv4/IPv6 CIDR; matches Target.Host
	KindHost        Kind = "host"         // exact IP or hostname literal
	KindDNSExact    Kind = "dns_exact"    // exact DNS name
	KindDNSWildcard Kind = "dns_wildcard" // *.example.com
	KindDNSSuffix   Kind = "dns_suffix"   // example.com (and any subdomain)
	KindURLPrefix   Kind = "url_prefix"   // https://app.example.com/api/
	KindPathGlob    Kind = "path_glob"    // /admin/* under any host
	KindVHost       Kind = "vhost"        // matches Target.Host as HTTP virtual host
	KindAccount     Kind = "account"      // exact account pattern (literal)
)

func (k Kind) Valid() bool {
	switch k {
	case KindCIDR, KindHost, KindDNSExact, KindDNSWildcard, KindDNSSuffix,
		KindURLPrefix, KindPathGlob, KindVHost, KindAccount:
		return true
	}
	return false
}

// TargetKind discriminates the Target.
type TargetKind string

const (
	TargetHost    TargetKind = "host"     // IP or hostname + optional port
	TargetDNSName TargetKind = "dns_name" // a name to be resolved
	TargetURL     TargetKind = "url"      // absolute URL
	TargetAccount TargetKind = "account"  // user/account identifier
)

// Target is what we're asking the engine about.
type Target struct {
	Kind     TargetKind
	Identity string // canonical string form: "1.2.3.4:443", "example.com", URL, etc.
	// Optional structured fields; populated where applicable.
	Host string
	Port int
	URL  string // absolute URL when Kind == TargetURL
}

// TimeWindow is an [Start, End) interval. Zero values are open-ended.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether t falls within the window. A zero Start means
// "no lower bound"; a zero End means "no upper bound".
func (w TimeWindow) Contains(t time.Time) bool {
	if !w.Start.IsZero() && t.Before(w.Start) {
		return false
	}
	if !w.End.IsZero() && !t.Before(w.End) {
		return false
	}
	return true
}

// Empty reports whether the window has no bounds.
func (w TimeWindow) Empty() bool { return w.Start.IsZero() && w.End.IsZero() }

// Rule is the unit of authorization. Rules MUST carry a stable Order so
// the evaluator's behaviour is reproducible.
type Rule struct {
	ID     uuid.UUID
	Order  int
	Effect Effect
	Kind   Kind
	Value  string // the kind-specific match pattern

	// Optional port restrictions; apply when Target.Port > 0.
	PortMin, PortMax int

	// Optional time window; the rule matches only when Now ∈ Window.
	Window TimeWindow

	// Optional advisory rate caps; the verdict alone is the contract,
	// these are passed through unchanged in the Result.
	MaxConcurrent int
	MaxRPS        float64

	// Free-form operator note ("ROE §3.1: prod cluster excluded"). Not
	// interpreted by the engine.
	Note string
}

// Validate checks structural invariants of a rule.
func (r Rule) Validate() error {
	if !r.Effect.Valid() {
		return fmt.Errorf("invalid effect %q", r.Effect)
	}
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid kind %q", r.Kind)
	}
	if r.Value == "" {
		return errors.New("value required")
	}
	if r.PortMin < 0 || r.PortMax < 0 || r.PortMin > r.PortMax {
		return errors.New("port range invalid")
	}
	if !r.Window.Empty() && !r.Window.End.IsZero() && !r.Window.Start.IsZero() && r.Window.End.Before(r.Window.Start) {
		return errors.New("time window: end before start")
	}
	switch r.Kind {
	case KindCIDR:
		if _, _, err := net.ParseCIDR(r.Value); err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
	case KindURLPrefix:
		if _, err := url.Parse(r.Value); err != nil {
			return fmt.Errorf("url_prefix: %w", err)
		}
	case KindDNSWildcard:
		if !strings.HasPrefix(r.Value, "*.") || len(r.Value) < 4 {
			return errors.New("dns_wildcard: must be of the form *.example.com")
		}
	}
	return nil
}

// Result is the engine's verdict.
type Result struct {
	Effect Effect   // EffectOutOfScope if no rule matched
	Rule   *Rule    // the rule that decided, or nil for the default
	Reason string   // human-readable explanation; stable for logging/audit
	Caps   RateCaps // advisory rate caps from the matching rule (if any)
}

// RateCaps surfaces advisory rate limits to the caller. Zero means "no cap".
type RateCaps struct {
	MaxConcurrent int     `json:"max_concurrent,omitempty"`
	MaxRPS        float64 `json:"max_rps,omitempty"`
}

// Evaluate is the engine entrypoint. Pure: no I/O, no allocation beyond
// the returned Result.
//
// `now` is injected so callers control the clock during testing.
func Evaluate(target Target, rules []Rule, now time.Time) Result {
	for i := range rules {
		r := &rules[i]
		if !r.Window.Empty() && !r.Window.Contains(now) {
			continue
		}
		if !portMatches(*r, target) {
			continue
		}
		if !valueMatches(*r, target) {
			continue
		}
		return Result{
			Effect: r.Effect,
			Rule:   r,
			Reason: fmt.Sprintf("matched rule order=%d kind=%s value=%s", r.Order, r.Kind, r.Value),
			Caps:   RateCaps{MaxConcurrent: r.MaxConcurrent, MaxRPS: r.MaxRPS},
		}
	}
	return Result{Effect: EffectOutOfScope, Reason: "no rule matched"}
}

func portMatches(r Rule, t Target) bool {
	if r.PortMin == 0 && r.PortMax == 0 {
		return true
	}
	if t.Port == 0 {
		return false
	}
	return t.Port >= r.PortMin && t.Port <= r.PortMax
}

func valueMatches(r Rule, t Target) bool {
	switch r.Kind {
	case KindCIDR:
		return cidrMatch(r.Value, hostOnly(t))
	case KindHost:
		return strings.EqualFold(r.Value, hostOnly(t))
	case KindDNSExact:
		return t.Kind == TargetDNSName && strings.EqualFold(r.Value, t.Identity)
	case KindDNSWildcard:
		// *.example.com matches a.example.com but NOT example.com
		base := r.Value[2:]
		name := strings.ToLower(t.Identity)
		if t.Kind != TargetDNSName {
			return false
		}
		return strings.HasSuffix(name, "."+strings.ToLower(base))
	case KindDNSSuffix:
		if t.Kind != TargetDNSName {
			return false
		}
		name := strings.ToLower(t.Identity)
		base := strings.ToLower(r.Value)
		return name == base || strings.HasSuffix(name, "."+base)
	case KindURLPrefix:
		if t.Kind != TargetURL {
			return false
		}
		return strings.HasPrefix(t.URL, r.Value)
	case KindPathGlob:
		if t.Kind != TargetURL {
			return false
		}
		u, err := url.Parse(t.URL)
		if err != nil {
			return false
		}
		return globMatch(r.Value, u.Path)
	case KindVHost:
		if t.Kind != TargetURL {
			return false
		}
		u, err := url.Parse(t.URL)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Value)
	case KindAccount:
		return t.Kind == TargetAccount && r.Value == t.Identity
	}
	return false
}

func hostOnly(t Target) string {
	if t.Host != "" {
		return t.Host
	}
	// strip :port if present
	if i := strings.LastIndex(t.Identity, ":"); i > 0 && !strings.Contains(t.Identity[i:], "]") {
		return t.Identity[:i]
	}
	return t.Identity
}

func cidrMatch(cidr, host string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ipnet.Contains(ip)
}

// globMatch supports a single trailing "*" wildcard. Matches "/admin/*"
// against "/admin/foo/bar" → true. "/admin" against "/admin/foo" → false.
func globMatch(pattern, s string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return pattern == s
}

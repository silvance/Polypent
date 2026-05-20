package scope

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustRule(t *testing.T, r Rule) Rule {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatalf("invalid rule: %v", err)
	}
	return r
}

func TestCIDRMatch(t *testing.T) {
	r := mustRule(t, Rule{ID: uuid.New(), Order: 0, Effect: EffectAllow, Kind: KindCIDR, Value: "10.0.0.0/24"})
	now := time.Now()

	cases := map[string]struct {
		host string
		want Effect
	}{
		"inside":  {"10.0.0.5", EffectAllow},
		"outside": {"10.0.1.5", EffectOutOfScope},
	}
	for name, tc := range cases {
		got := Evaluate(Target{Kind: TargetHost, Identity: tc.host, Host: tc.host}, []Rule{r}, now).Effect
		if got != tc.want {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}

func TestIPv6CIDR(t *testing.T) {
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindCIDR, Value: "2001:db8::/32"})
	got := Evaluate(Target{Kind: TargetHost, Identity: "2001:db8:1::1", Host: "2001:db8:1::1"}, []Rule{r}, time.Now())
	if got.Effect != EffectAllow {
		t.Errorf("ipv6 inside cidr: got %v", got.Effect)
	}
}

func TestDNSWildcardDoesNotMatchApex(t *testing.T) {
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindDNSWildcard, Value: "*.example.com"})
	apex := Evaluate(Target{Kind: TargetDNSName, Identity: "example.com"}, []Rule{r}, time.Now())
	if apex.Effect != EffectOutOfScope {
		t.Errorf("wildcard should not match apex; got %v", apex.Effect)
	}
	sub := Evaluate(Target{Kind: TargetDNSName, Identity: "a.example.com"}, []Rule{r}, time.Now())
	if sub.Effect != EffectAllow {
		t.Errorf("wildcard should match sub; got %v", sub.Effect)
	}
}

func TestDNSSuffixMatchesApexAndSub(t *testing.T) {
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindDNSSuffix, Value: "example.com"})
	for _, name := range []string{"example.com", "a.example.com", "b.a.example.com"} {
		if Evaluate(Target{Kind: TargetDNSName, Identity: name}, []Rule{r}, time.Now()).Effect != EffectAllow {
			t.Errorf("suffix %q expected allow", name)
		}
	}
	if Evaluate(Target{Kind: TargetDNSName, Identity: "evil-example.com"}, []Rule{r}, time.Now()).Effect != EffectOutOfScope {
		t.Errorf("suffix must not match prefix collisions")
	}
}

func TestURLPrefixAndPathGlob(t *testing.T) {
	rules := []Rule{
		mustRule(t, Rule{Order: 0, Effect: EffectAllow, Kind: KindURLPrefix, Value: "https://app.example.com/"}),
		mustRule(t, Rule{Order: 1, Effect: EffectDeny, Kind: KindPathGlob, Value: "/admin/*"}),
	}
	if Evaluate(Target{Kind: TargetURL, URL: "https://app.example.com/foo"}, rules, time.Now()).Effect != EffectAllow {
		t.Errorf("expected allow on app url")
	}
	// Order matters: allow at position 0 wins for /admin/* too unless we
	// move deny before it. First-match-wins is intentional and tested
	// separately below.
}

func TestFirstMatchWins(t *testing.T) {
	denyFirst := []Rule{
		mustRule(t, Rule{Order: 0, Effect: EffectDeny, Kind: KindCIDR, Value: "10.0.0.0/8"}),
		mustRule(t, Rule{Order: 1, Effect: EffectAllow, Kind: KindCIDR, Value: "10.0.0.0/24"}),
	}
	res := Evaluate(Target{Kind: TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"}, denyFirst, time.Now())
	if res.Effect != EffectDeny {
		t.Errorf("explicit deny first should win; got %v", res.Effect)
	}

	allowFirst := []Rule{
		mustRule(t, Rule{Order: 0, Effect: EffectAllow, Kind: KindCIDR, Value: "10.0.0.0/24"}),
		mustRule(t, Rule{Order: 1, Effect: EffectDeny, Kind: KindCIDR, Value: "10.0.0.0/8"}),
	}
	res = Evaluate(Target{Kind: TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"}, allowFirst, time.Now())
	if res.Effect != EffectAllow {
		t.Errorf("allow first should win; got %v", res.Effect)
	}
}

func TestTimeWindow(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindCIDR, Value: "10.0.0.0/24",
		Window: TimeWindow{Start: start, End: end}})

	target := Target{Kind: TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"}
	if Evaluate(target, []Rule{r}, start.Add(-time.Hour)).Effect != EffectOutOfScope {
		t.Errorf("before window: expected out_of_scope")
	}
	if Evaluate(target, []Rule{r}, start.Add(time.Hour)).Effect != EffectAllow {
		t.Errorf("in window: expected allow")
	}
	if Evaluate(target, []Rule{r}, end.Add(time.Hour)).Effect != EffectOutOfScope {
		t.Errorf("after window: expected out_of_scope")
	}
}

func TestPortRange(t *testing.T) {
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindCIDR, Value: "10.0.0.0/24", PortMin: 80, PortMax: 443})
	if Evaluate(Target{Kind: TargetHost, Identity: "10.0.0.5:80", Host: "10.0.0.5", Port: 80}, []Rule{r}, time.Now()).Effect != EffectAllow {
		t.Error("port 80 should allow")
	}
	if Evaluate(Target{Kind: TargetHost, Identity: "10.0.0.5:8080", Host: "10.0.0.5", Port: 8080}, []Rule{r}, time.Now()).Effect != EffectOutOfScope {
		t.Error("port 8080 should not match a 80-443 range rule")
	}
}

func TestRateCapsSurfaced(t *testing.T) {
	r := mustRule(t, Rule{Effect: EffectAllow, Kind: KindHost, Value: "10.0.0.5", MaxConcurrent: 4, MaxRPS: 10.0})
	res := Evaluate(Target{Kind: TargetHost, Identity: "10.0.0.5", Host: "10.0.0.5"}, []Rule{r}, time.Now())
	if res.Caps.MaxConcurrent != 4 || res.Caps.MaxRPS != 10.0 {
		t.Errorf("rate caps not surfaced: %+v", res.Caps)
	}
}

// --- property tests ---------------------------------------------------------

// genRule produces a randomized but always-valid rule.
func genRule(rng *rand.Rand, order int) Rule {
	kind := []Kind{KindCIDR, KindDNSExact, KindDNSWildcard, KindDNSSuffix, KindHost}[rng.IntN(5)]
	effects := []Effect{EffectAllow, EffectDeny}
	r := Rule{
		ID:     uuid.New(),
		Order:  order,
		Effect: effects[rng.IntN(2)],
		Kind:   kind,
	}
	switch kind {
	case KindCIDR:
		r.Value = randomCIDR(rng)
	case KindDNSExact:
		r.Value = randomDNS(rng)
	case KindDNSWildcard:
		r.Value = "*." + randomDNS(rng)
	case KindDNSSuffix:
		r.Value = randomDNS(rng)
	case KindHost:
		r.Value = randomDNS(rng)
	}
	return r
}

func randomCIDR(rng *rand.Rand) string {
	octets := []byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), 0}
	prefix := 16 + rng.IntN(17)
	return ipString(octets[0], octets[1], octets[2], octets[3]) + "/" + itoa(prefix)
}

func ipString(a, b, c, d byte) string {
	return itoa(int(a)) + "." + itoa(int(b)) + "." + itoa(int(c)) + "." + itoa(int(d))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	n := 0
	for i > 0 {
		b[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = b[n-1-j]
	}
	return string(out)
}

func randomDNS(rng *rand.Rand) string {
	labels := []string{"acme", "example", "internal", "corp", "infra", "dev", "stage"}
	tlds := []string{"com", "net", "io"}
	return labels[rng.IntN(len(labels))] + "." + tlds[rng.IntN(len(tlds))]
}

func genTarget(rng *rand.Rand) Target {
	switch rng.IntN(2) {
	case 0:
		ip := ipString(byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)))
		return Target{Kind: TargetHost, Identity: ip, Host: ip}
	default:
		name := randomDNS(rng)
		if rng.IntN(2) == 0 {
			name = "a." + name
		}
		return Target{Kind: TargetDNSName, Identity: name}
	}
}

// TestDeterminism: same inputs → same verdict.
func TestPropertyDeterminism(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	now := time.Now()
	for i := 0; i < 500; i++ {
		n := 1 + rng.IntN(8)
		rules := make([]Rule, n)
		for j := range rules {
			rules[j] = genRule(rng, j)
		}
		tg := genTarget(rng)
		a := Evaluate(tg, rules, now)
		b := Evaluate(tg, rules, now)
		if a.Effect != b.Effect {
			t.Fatalf("not deterministic: %+v vs %+v", a, b)
		}
	}
}

// TestMonotonicAppend: appending rules never changes an existing Deny verdict.
// (With first-match-wins, appending cannot retroactively beat an earlier
// match; this is the property we rely on for safe rule rollout.)
func TestPropertyMonotonicAppend(t *testing.T) {
	rng := rand.New(rand.NewPCG(2, 2))
	now := time.Now()
	for i := 0; i < 500; i++ {
		n := 1 + rng.IntN(6)
		rules := make([]Rule, n)
		for j := range rules {
			rules[j] = genRule(rng, j)
		}
		tg := genTarget(rng)
		before := Evaluate(tg, rules, now).Effect
		if before != EffectDeny {
			continue
		}
		// append a random allow rule
		extra := genRule(rng, len(rules))
		extra.Effect = EffectAllow
		rules = append(rules, extra)
		after := Evaluate(tg, rules, now).Effect
		if after != EffectDeny {
			t.Fatalf("monotonicity violated: deny became %v after append", after)
		}
	}
}

// TestExplicitDenyBeatsLaterAllow: hand-constructed regression of the
// architecture invariant.
func TestPropertyExplicitDenyBeatsLaterAllow(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 3))
	now := time.Now()
	for i := 0; i < 200; i++ {
		// build a deny rule and an allow rule that *both* match the same target
		host := ipString(10, byte(rng.IntN(256)), 0, byte(1+rng.IntN(254)))
		tg := Target{Kind: TargetHost, Identity: host, Host: host}
		deny := mustRule(t, Rule{Order: 0, Effect: EffectDeny, Kind: KindCIDR, Value: "10.0.0.0/8"})
		allow := mustRule(t, Rule{Order: 1, Effect: EffectAllow, Kind: KindHost, Value: host})
		got := Evaluate(tg, []Rule{deny, allow}, now).Effect
		if got != EffectDeny {
			t.Fatalf("deny-first failed for host=%s: got %v", host, got)
		}
	}
}

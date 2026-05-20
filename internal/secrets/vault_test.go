package secrets

import (
	"testing"

	"github.com/google/uuid"
)

func TestKeyShape(t *testing.T) {
	good := []string{"X", "a", "AWS_KEY", "key_1", "_underscore_ok"}
	bad := []string{"", "1leading-digit", "has space", "kebab-case", "nice🙂"}
	for _, k := range good {
		if !keyRe.MatchString(k) {
			t.Errorf("expected %q to be valid", k)
		}
	}
	for _, k := range bad {
		if keyRe.MatchString(k) {
			t.Errorf("expected %q to be invalid", k)
		}
	}
}

func TestProjectIDAdditional(t *testing.T) {
	p := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	a := projectIDAdditional(p, "k")
	b := projectIDAdditional(p, "j")
	if string(a) == string(b) {
		t.Fatal("different keys should produce different aad")
	}
}

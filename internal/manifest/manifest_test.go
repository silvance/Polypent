package manifest

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	m := Manifest{
		ManifestVersion: Version,
		PolypentVersion: "v0.1.0",
		GeneratedAt:     time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
		RunID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ProjectID:       uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		ProjectSlug:     "acme",
		Capabilities:    []string{"http.probe", "dns.passive"},
		Status:          "succeeded",
		CreatedAt:       time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC),
	}
	key := []byte("test-key-32-bytes-aaaaaaaaaaaaaaaa")
	sig, err := Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("hmac-sha256 hex must be 64 chars, got %d", len(sig))
	}
	ok, err := Verify(m, sig, key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify failed on round-trip")
	}
}

func TestSignDetectsMutation(t *testing.T) {
	m := Manifest{Status: "succeeded"}
	key := []byte("k")
	sig, _ := Sign(m, key)
	m.Status = "failed"
	ok, _ := Verify(m, sig, key)
	if ok {
		t.Fatal("verify must fail when manifest is mutated")
	}
}

func TestSignDetectsKeyChange(t *testing.T) {
	m := Manifest{Status: "succeeded"}
	sig, _ := Sign(m, []byte("k1"))
	ok, _ := Verify(m, sig, []byte("k2"))
	if ok {
		t.Fatal("verify must fail under wrong key")
	}
}

func TestSignRequiresKey(t *testing.T) {
	if _, err := Sign(Manifest{}, nil); err == nil {
		t.Fatal("expected error on empty key")
	}
}

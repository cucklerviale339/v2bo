package subscribeguard

import (
	"bytes"
	"testing"
)

func TestTokenListEncryptedRoundTripAndLegacyCompatibility(t *testing.T) {
	policy := DefaultPolicy()
	policy.TokenBlacklist = []string{"private-raw-token", "Case-Sensitive-Token"}
	if err := policy.Validate("secret"); err != nil {
		t.Fatal(err)
	}
	raw, err := encodePolicy(policy, "secret")
	if err != nil || bytes.Contains(raw, []byte("private-raw-token")) {
		t.Fatalf("plaintext persisted: %v", err)
	}
	other, _ := encodePolicy(policy, "secret")
	if bytes.Equal(raw, other) {
		t.Fatal("encryption nonce reused")
	}
	restored, err := decodePolicy(raw, "secret")
	if err != nil || len(restored.TokenBlacklist) != 2 || restored.TokenBlacklist[0] != "private-raw-token" {
		t.Fatal("cannot edit saved token list", err)
	}
	if _, err := decodePolicy(raw, "wrong-key"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := decodePolicy([]byte(`{"encrypted_tokens":"AAAA"}`), "secret"); err == nil {
		t.Fatal("malformed cipher accepted")
	}
	legacy, err := decodePolicy([]byte(`{"mode":"off","rules":[]}`), "secret")
	if err != nil || legacy.Mode != "off" || len(legacy.TokenBlacklist) != 0 {
		t.Fatal("legacy config failed")
	}
}

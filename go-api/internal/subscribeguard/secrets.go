package subscribeguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type storedPolicy struct {
	Policy
	EncryptedTokens string `json:"encrypted_tokens,omitempty"`
}

func tokenCipher(key string) (cipher.AEAD, error) {
	if key == "" {
		return nil, errors.New("missing token encryption key")
	}
	digest := sha256.Sum256([]byte("subscribe-guard:token-encryption:v1:" + key))
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encodePolicy(policy Policy, key string) ([]byte, error) {
	stored := storedPolicy{Policy: policy}
	stored.TokenBlacklist = nil
	if len(policy.TokenBlacklist) > 0 {
		box, err := tokenCipher(key)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, box.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(policy.TokenBlacklist)
		if err != nil {
			return nil, err
		}
		stored.EncryptedTokens = base64.StdEncoding.EncodeToString(box.Seal(nonce, nonce, raw, []byte("subscribe-guard:tokens:v1")))
	}
	return json.Marshal(stored)
}

func decodePolicy(raw []byte, key string) (Policy, error) {
	stored := storedPolicy{Policy: DefaultPolicy()}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return DefaultPolicy(), err
	}
	if stored.EncryptedTokens != "" {
		box, err := tokenCipher(key)
		if err != nil {
			return DefaultPolicy(), err
		}
		ciphertext, err := base64.StdEncoding.DecodeString(stored.EncryptedTokens)
		if err != nil || len(ciphertext) < box.NonceSize()+box.Overhead() {
			return DefaultPolicy(), errors.New("invalid encrypted token list")
		}
		plain, err := box.Open(nil, ciphertext[:box.NonceSize()], ciphertext[box.NonceSize():], []byte("subscribe-guard:tokens:v1"))
		if err != nil {
			return DefaultPolicy(), errors.New("cannot decrypt token list")
		}
		if err := json.Unmarshal(plain, &stored.TokenBlacklist); err != nil {
			return DefaultPolicy(), err
		}
	}
	return stored.Policy, nil
}

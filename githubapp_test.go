package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/456/access_tokens" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}

		// The JWT must be signed by the App's key and issued by the App.
		jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatalf("malformed JWT")
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Errorf("JWT signature: %v", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Iss string `json:"iss"`
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
		}
		_ = json.Unmarshal(raw, &claims)
		if claims.Iss != "123" || claims.Exp-claims.Iat > 600 || claims.Exp <= time.Now().Unix() {
			t.Errorf("bad claims %+v", claims)
		}

		// The token must be scoped down to read-only.
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for k, v := range body.Permissions {
			if v != "read" {
				t.Errorf("permission %s=%s, want read", k, v)
			}
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_test", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer srv.Close()

	a, err := newAppTokens("123", "456", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	a.apiURL = srv.URL

	for i := 0; i < 2; i++ {
		tok, err := a.Token(context.Background())
		if err != nil || tok != "ghs_test" {
			t.Fatalf("Token() = %q, %v", tok, err)
		}
	}
	if calls != 1 {
		t.Errorf("minted %d tokens, want 1 (cached)", calls)
	}
}

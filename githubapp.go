package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// appTokens mints GitHub App installation tokens for the GitHub API calls the
// script makes (attestation verification, run lookups). Tokens are scoped
// down to read-only attestations and actions, cached, and refreshed before
// they expire. The private key stays in this process; subprocesses only ever
// see the short-lived token.
type appTokens struct {
	appID          string
	installationID string
	key            *rsa.PrivateKey
	apiURL         string
	client         *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newAppTokens(appID, installationID, keyPath string) (*appTokens, error) {
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return nil, fmt.Errorf("invalid GitHub App ID %q", appID)
	}
	if _, err := strconv.ParseInt(installationID, 10, 64); err != nil {
		return nil, fmt.Errorf("invalid GitHub App installation ID %q", installationID)
	}
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App private key: %w", err)
	}
	key, err := parseRSAKey(b)
	if err != nil {
		return nil, err
	}
	return &appTokens{
		appID:          appID,
		installationID: installationID,
		key:            key,
		apiURL:         "https://api.github.com",
		client:         &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func parseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private key is not an RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key is not an RSA key")
	}
	return rk, nil
}

// Token returns a cached installation token, minting a new one when the
// cached one has less than ten minutes left.
func (a *appTokens) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.expires) > 10*time.Minute {
		return a.token, nil
	}

	jwt, err := a.jwt(time.Now())
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"permissions": map[string]string{"attestations": "read", "actions": "read", "metadata": "read"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.apiURL+"/app/installations/"+a.installationID+"/access_tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint installation token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("mint installation token: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Token == "" {
		return "", errors.New("mint installation token: invalid response")
	}
	a.token, a.expires = out.Token, out.ExpiresAt
	return a.token, nil
}

// jwt signs the short-lived JWT that authenticates as the App itself.
func (a *appTokens) jwt(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(), // allow for clock drift
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": a.appID,
	})
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

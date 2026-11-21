package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func TestCallerAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(path, []byte(`
source: ghcr.io/example
destination: docker.io/example
defaults:
  source_refs: '.*'
images:
  app:
    publishers:
      - repo: example/app
  client-image:
    publishers:
      - repo: example/builder
  shared:
    publishers:
      - repo: example/shared
      - repo: example/builder
        tags: 'branch-.*'
  heavy:
    publishers:
      - repo: example/heavy
        allow_self_hosted: true
  pinned:
    publishers:
      - repo: example/pinned
        source_refs: refs/heads/main
  locked:
    publishers:
      - repo: example/locked
        signer_workflows: [example/locked/.github/workflows/release.yaml]
        source_refs: '^refs/tags/v[0-9.]+$'
        actors: [alice]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	hosted := func(repo, ref, actor string) githubClaims {
		return githubClaims{Repository: repo, Ref: ref, RunnerEnvironment: "github-hosted", Actor: actor}
	}
	selfHosted := func(repo string) githubClaims {
		return githubClaims{Repository: repo, Ref: "refs/heads/master", RunnerEnvironment: "self-hosted"}
	}

	cases := []struct {
		name  string
		image string
		cl    githubClaims
		ok    bool
	}{
		{"listed repo", "app", hosted("example/app", "refs/heads/feature", ""), true},
		{"another repo's image", "app", hosted("example/shared", "refs/heads/master", ""), false},
		{"same-named new repo is not enough", "client", hosted("example/client", "refs/heads/master", ""), false},
		{"unlisted image", "other", hosted("example/other", "refs/heads/master", ""), false},
		{"second publisher, tag outside its pattern", "shared", hosted("example/builder", "refs/heads/master", ""), false},
		{"first publisher", "shared", hosted("example/shared", "refs/heads/master", ""), true},
		{"other org", "app", hosted("evil/app", "refs/heads/master", ""), false},
		{"self-hosted by default", "app", selfHosted("example/app"), false},
		{"self-hosted exception", "heavy", selfHosted("example/heavy"), true},
		{"builder repo's image", "client-image", hosted("example/builder", "refs/heads/master", ""), true},
		{"builder repo, unlisted image", "other", hosted("example/builder", "refs/heads/master", ""), false},
		{"locked: release tag by allowed actor", "locked", hosted("example/locked", "refs/tags/v1.2.3", "alice"), true},
		{"locked: branch build", "locked", hosted("example/locked", "refs/heads/master", "alice"), false},
		{"locked: other actor", "locked", hosted("example/locked", "refs/tags/v1.2.3", "mallory"), false},
		{"unanchored ref regex matches the whole ref", "pinned", hosted("example/pinned", "refs/heads/main", ""), true},
		{"unanchored ref regex is not a prefix", "pinned", hosted("example/pinned", "refs/heads/main-evil", ""), false},
		{"unanchored ref regex is not a suffix", "pinned", hosted("example/pinned", "refs/heads/x/refs/heads/main", ""), false},
	}
	for _, c := range cases {
		err := cfg.callerAllowed(c.image, c.cl, []string{"latest"})
		if (err == nil) != c.ok {
			t.Errorf("%s: allowed=%v, want %v (err: %v)", c.name, err == nil, c.ok, err)
		}
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(path, []byte(`
source: ghcr.io/example
destination: docker.io/example
images:
  app:
    publishers:
      - repo: example/app
        source_ref: '^refs/tags/'
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("a misspelt field (source_ref) was accepted, which would silently drop the restriction")
	}
}

// testIssuer serves a JWKS and signs tokens with its keys.
type testIssuer struct {
	t     *testing.T
	srv   *httptest.Server
	hits  atomic.Int32
	mu    sync.Mutex
	keys  map[string]*rsa.PrivateKey
	extra *rsa.PrivateKey // not published
}

func newTestIssuer(t *testing.T) *testIssuer {
	iss := &testIssuer{t: t, keys: map[string]*rsa.PrivateKey{}}
	iss.addKey("k1")
	iss.extra, _ = rsa.GenerateKey(rand.Reader, 2048)
	iss.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		iss.hits.Add(1)
		iss.mu.Lock()
		defer iss.mu.Unlock()
		var set jose.JSONWebKeySet
		for kid, k := range iss.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(iss.srv.Close)
	return iss
}

func (iss *testIssuer) addKey(kid string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		iss.t.Fatal(err)
	}
	iss.mu.Lock()
	iss.keys[kid] = k
	iss.mu.Unlock()
}

// token signs claims with key kid, or with an unpublished key if kid is not
// one of the issuer's.
func (iss *testIssuer) token(kid string, claims map[string]any) string {
	iss.mu.Lock()
	key, ok := iss.keys[kid]
	iss.mu.Unlock()
	if !ok {
		key = iss.extra
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		iss.t.Fatal(err)
	}
	body := map[string]any{"iss": githubIssuer, "aud": "image-mirror", "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		body[k] = v
	}
	payload, _ := json.Marshal(body)
	jws, err := signer.Sign(payload)
	if err != nil {
		iss.t.Fatal(err)
	}
	raw, _ := jws.CompactSerialize()
	return raw
}

func (iss *testIssuer) verifier(minRefresh time.Duration) *oidc.IDTokenVerifier {
	return newVerifier(githubIssuer, "image-mirror", &keySet{url: iss.srv.URL, client: iss.srv.Client(), minRefresh: minRefresh})
}

func TestKeySetLimitsRefetches(t *testing.T) {
	iss := newTestIssuer(t)
	v := iss.verifier(200 * time.Millisecond)
	ctx := context.Background()

	if _, err := v.Verify(ctx, iss.token("k1", nil)); err != nil {
		t.Fatal(err)
	}
	// Unauthenticated callers with made-up key IDs, or a real key ID and a
	// forged signature, must not make the service refetch the JWKS.
	for i := range 50 {
		if _, err := v.Verify(ctx, iss.token(fmt.Sprint("forged-", i), nil)); err == nil {
			t.Fatal("verified a token signed with an unknown key")
		}
	}
	iss.keys["k1"], iss.extra = iss.extra, iss.keys["k1"] // sign "k1" with the wrong key
	if _, err := v.Verify(ctx, iss.token("k1", nil)); err == nil {
		t.Fatal("verified a forged signature")
	}
	iss.keys["k1"], iss.extra = iss.extra, iss.keys["k1"]
	if got := iss.hits.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", got)
	}

	// A rotated-in key is picked up once the refresh interval has passed.
	iss.addKey("k2")
	time.Sleep(250 * time.Millisecond)
	if _, err := v.Verify(ctx, iss.token("k2", nil)); err != nil {
		t.Fatalf("new key not picked up: %v", err)
	}
	if got := iss.hits.Load(); got != 2 {
		t.Fatalf("JWKS fetched %d times, want 2", got)
	}
}

func TestMirrorEndpoint(t *testing.T) {
	iss := newTestIssuer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "images.yaml")
	script := filepath.Join(dir, "mirror.sh")
	if err := os.WriteFile(cfgPath, []byte("source: s.example\ndestination: d.example\nimages:\n  app:\n    publishers:\n      - repo: example/app\n        repo_id: 1001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("sleep 0.2; echo done\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(cfg, script, iss.verifier(time.Minute))
	s.inlineWait = 10 * time.Millisecond
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	claims := func(repo, id string) map[string]any {
		return map[string]any{"repository": repo, "repository_id": id, "ref": "refs/heads/main", "runner_environment": "github-hosted", "run_id": "1", "run_attempt": "1"}
	}
	do := func(method, path, token, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	pair := `"x@sha256:` + strings.Repeat("a", 64) + `"`
	app, other := iss.token("k1", claims("example/app", "1001")), iss.token("k1", claims("evil/app", "666"))

	// An unlisted caller learns nothing about which images are listed.
	code1, listed := do("POST", "/v1/mirror", other, `{"image":"app","tags":[`+pair+`]}`)
	code2, unlisted := do("POST", "/v1/mirror", other, `{"image":"zzz","tags":[`+pair+`]}`)
	if code1 != 403 || code2 != 403 || strings.ReplaceAll(unlisted, "zzz", "app") != listed {
		t.Fatalf("listed: %d %q; unlisted: %d %q", code1, listed, code2, unlisted)
	}
	// Same name, different repository ID: a deleted and recreated repo.
	if code, body := do("POST", "/v1/mirror", iss.token("k1", claims("example/app", "2002")), `{"image":"app","tags":[`+pair+`]}`); code != 403 {
		t.Fatalf("recreated repo: %d %s", code, body)
	}

	// An allowed caller can only queue a few jobs at a time.
	var ids []string
	for range maxJobsPerRepo {
		code, body := do("POST", "/v1/mirror", app, `{"image":"app","tags":[`+pair+`]}`)
		if code != 202 {
			t.Fatalf("POST: %d %s", code, body)
		}
		ids = append(ids, body)
	}
	if code, body := do("POST", "/v1/mirror", app, `{"image":"app","tags":[`+pair+`]}`); code != 429 {
		t.Fatalf("POST over the limit: %d %s", code, body)
	}

	// Jobs are visible only to the repository that started them.
	if code, _ := do("GET", "/v1/jobs/"+ids[0], other, ""); code != 404 {
		t.Fatalf("other repo read a job: %d", code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body := do("GET", "/v1/jobs/"+ids[len(ids)-1], app, "")
		if code == 200 && strings.HasPrefix(body, "done") {
			break
		}
		if code != 202 || time.Now().After(deadline) {
			t.Fatalf("GET job: %d %s", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, body := do("POST", "/v1/mirror", app, `{"image":"app","tags":[`+pair+`]}`); code != 202 && code != 200 {
		t.Fatalf("POST after jobs finished: %d %s", code, body)
	}
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
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

	"github.com/alicebob/miniredis/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) redis.UniversalClient {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

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
  gated:
    publishers:
      - repo: example/gated
        events: [push, workflow_dispatch]
      - repo: example/gated
        events: [pull_request_target]
        tags: 'pr-[0-9]+(-[0-9a-f]+)?'
  dev:
    publishers:
      - repo: example/dev
        tags: '[A-Za-z0-9_.-]+'
        exclude_tags: '.*latest|v?[0-9].*'
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

	event := func(e string) githubClaims {
		return githubClaims{Repository: "example/gated", Ref: "refs/heads/master", RunnerEnvironment: "github-hosted", EventName: e}
	}

	cases := []struct {
		name  string
		image string
		cl    githubClaims
		tags  []string
		ok    bool
	}{
		{"listed repo", "app", hosted("example/app", "refs/heads/feature", ""), nil, true},
		{"another repo's image", "app", hosted("example/shared", "refs/heads/master", ""), nil, false},
		{"same-named new repo is not enough", "client", hosted("example/client", "refs/heads/master", ""), nil, false},
		{"unlisted image", "other", hosted("example/other", "refs/heads/master", ""), nil, false},
		{"second publisher, tag outside its pattern", "shared", hosted("example/builder", "refs/heads/master", ""), nil, false},
		{"first publisher", "shared", hosted("example/shared", "refs/heads/master", ""), nil, true},
		{"other org", "app", hosted("evil/app", "refs/heads/master", ""), nil, false},
		{"self-hosted by default", "app", selfHosted("example/app"), nil, false},
		{"self-hosted exception", "heavy", selfHosted("example/heavy"), nil, true},
		{"builder repo's image", "client-image", hosted("example/builder", "refs/heads/master", ""), nil, true},
		{"builder repo, unlisted image", "other", hosted("example/builder", "refs/heads/master", ""), nil, false},
		{"locked: release tag by allowed actor", "locked", hosted("example/locked", "refs/tags/v1.2.3", "alice"), nil, true},
		{"locked: branch build", "locked", hosted("example/locked", "refs/heads/master", "alice"), nil, false},
		{"locked: other actor", "locked", hosted("example/locked", "refs/tags/v1.2.3", "mallory"), nil, false},
		{"unanchored ref regex matches the whole ref", "pinned", hosted("example/pinned", "refs/heads/main", ""), nil, true},
		{"unanchored ref regex is not a prefix", "pinned", hosted("example/pinned", "refs/heads/main-evil", ""), nil, false},
		{"unanchored ref regex is not a suffix", "pinned", hosted("example/pinned", "refs/heads/x/refs/heads/main", ""), nil, false},
		{"push may publish any tag", "gated", event("push"), []string{"master"}, true},
		{"labelled PR build may publish pr tags", "gated", event("pull_request_target"), []string{"pr-343", "pr-343-abc1234"}, true},
		{"labelled PR build may not publish branch tags", "gated", event("pull_request_target"), []string{"master"}, false},
		{"labelled PR build may not mix in a branch tag", "gated", event("pull_request_target"), []string{"pr-343", "master"}, false},
		{"unlisted event", "gated", event("schedule"), []string{"master"}, false},
		{"tag outside exclude_tags", "dev", hosted("example/dev", "refs/heads/feat", ""), []string{"feat-x", "feat-x-abc1234"}, true},
		{"excluded tag", "dev", hosted("example/dev", "refs/heads/feat", ""), []string{"debian-latest"}, false},
		{"excluded tag mixed in", "dev", hosted("example/dev", "refs/heads/feat", ""), []string{"feat-x", "v1.2.3"}, false},
		{"exclude_tags matches the whole tag only", "dev", hosted("example/dev", "refs/heads/feat", ""), []string{"latest-feat"}, true},
	}
	for _, c := range cases {
		tags := c.tags
		if tags == nil {
			tags = []string{"latest"}
		}
		err := cfg.callerAllowed(c.image, c.cl, tags)
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
	s := newServer(cfg, script, iss.verifier(time.Minute), newTestRedis(t))
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
	s.limits.jobsPerRepo = 3 // a non-default value, so the flag's value is what's enforced
	for range s.limits.jobsPerRepo {
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

// replicaTest runs several replicas against one Redis, each with its own
// verify-and-copy script.
type replicaTest struct {
	t     *testing.T
	iss   *testIssuer
	rdb   redis.UniversalClient
	cfg   *config
	dir   string
	token string
	pair  string
}

func newReplicaTest(t *testing.T) *replicaTest {
	rt := &replicaTest{t: t, iss: newTestIssuer(t), rdb: newTestRedis(t), dir: t.TempDir()}
	cfgPath := filepath.Join(rt.dir, "images.yaml")
	if err := os.WriteFile(cfgPath, []byte("source: s.example\ndestination: d.example\nimages:\n  app:\n    publishers:\n      - repo: example/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if rt.cfg, err = loadConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	rt.token = rt.iss.token("k1", map[string]any{"repository": "example/app", "repository_id": "1001", "ref": "refs/heads/main", "runner_environment": "github-hosted", "run_id": "1", "run_attempt": "1"})
	rt.pair = `"x@sha256:` + strings.Repeat("a", 64) + `"`
	return rt
}

// replica starts a replica whose script runs body.
func (rt *replicaTest) replica(name, body string) (*server, *httptest.Server) {
	script := filepath.Join(rt.dir, name+".sh")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		rt.t.Fatal(err)
	}
	s := newServer(rt.cfg, script, rt.iss.verifier(time.Minute), rt.rdb)
	s.inlineWait = 10 * time.Millisecond
	s.reapEvery = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go s.reapLoop(ctx)
	srv := httptest.NewServer(s.routes())
	rt.t.Cleanup(func() { cancel(); srv.Close(); s.cancelJobs(); s.jobsWG.Wait() })
	return s, srv
}

func (rt *replicaTest) do(srv *httptest.Server, method, path, body string) (int, string) {
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rt.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rt.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// wait polls the job on srv until it finishes, as the mirror-image action
// does: 202 and 5xx mean keep polling, anything else is the answer.
func (rt *replicaTest) wait(srv *httptest.Server, id string) (int, string) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body := rt.do(srv, "GET", "/v1/jobs/"+id, "")
		if (code != 202 && code < 500) || time.Now().After(deadline) {
			return code, body
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A replica that is shutting down neither loses its running jobs nor turns
// callers away: jobs it can't finish in time, and jobs it admits while
// draining, run on another replica, and any replica answers for them.
func TestDrainHandsJobsOver(t *testing.T) {
	rt := newReplicaTest(t)
	a, srvA := rt.replica("a", "sleep 30; echo from-a\n")
	rt.replica("b", "echo from-b\n")
	post := func() string {
		code, body := rt.do(srvA, "POST", "/v1/mirror", `{"image":"app","tags":[`+rt.pair+`]}`)
		if code != 202 {
			t.Fatalf("POST: %d %s", code, body)
		}
		return body
	}

	a.draining.Store(true)
	if code, body := rt.wait(srvA, post()); code != 200 || !strings.Contains(body, "from-b") {
		t.Fatalf("job admitted while draining: %d %s", code, body)
	}

	a.draining.Store(false)
	running := post()
	time.Sleep(200 * time.Millisecond) // a is running it
	a.draining.Store(true)
	a.cancelJobs() // the drain timeout passes
	if code, body := rt.wait(srvA, running); code != 200 || !strings.Contains(body, "from-b") {
		t.Fatalf("job handed over: %d %s", code, body)
	}
}

// The limits hold across replicas, not per replica.
func TestLimitsAcrossReplicas(t *testing.T) {
	rt := newReplicaTest(t)
	a, srvA := rt.replica("a", "sleep 30\n")
	b, srvB := rt.replica("b", "sleep 30\n")
	a.limits.jobsPerRepo, b.limits.jobsPerRepo = 2, 2
	for _, srv := range []*httptest.Server{srvA, srvB} {
		if code, body := rt.do(srv, "POST", "/v1/mirror", `{"image":"app","tags":[`+rt.pair+`]}`); code != 202 {
			t.Fatalf("POST: %d %s", code, body)
		}
	}
	if code, body := rt.do(srvB, "POST", "/v1/mirror", `{"image":"app","tags":[`+rt.pair+`]}`); code != 429 {
		t.Fatalf("third job across two replicas: %d %s", code, body)
	}
}

// Metrics name the repository that published each image, and count only the
// tags a run created or moved.
func TestObserveJobByRepo(t *testing.T) {
	out := "verified sha256:9d4a17160bea: Example/Builder refs/heads/master github-hosted example/builder/.github/workflows/deploy.yml\n" +
		"d.example/img:main -> sha256:9d4a17160bea (copied)\n" +
		"d.example/img:main-abc -> sha256:9d4a17160bea (already current)\n"
	observeJob("img", "poll", "", out, nil, time.Second)
	if got := testutil.ToFloat64(tagsCopied.WithLabelValues("example/builder", "img")); got != 1 {
		t.Fatalf("tags copied for the verified repo = %v, want 1", got)
	}
	observeJob("img", "publish", "example/caller", "", errors.New("refused"), time.Second)
	if got := testutil.ToFloat64(jobsFinished.WithLabelValues("example/caller", "img", "publish", "failed")); got != 1 {
		t.Fatalf("failed publish by caller = %v, want 1", got)
	}
}

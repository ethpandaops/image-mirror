package main

import (
	"os"
	"path/filepath"
	"testing"
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
        tags: '^branch-'
  heavy:
    publishers:
      - repo: example/heavy
        allow_self_hosted: true
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

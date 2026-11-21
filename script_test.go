package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run scripts/mirror.sh, which is what authorises a copy, against
// fake gh and regctl commands that serve fixtures. The rule comes from a
// config file through loadConfig, as in the service.

const fakeRegctl = `#!/usr/bin/env bash
key() { printf '%s' "$1" | tr -c 'A-Za-z0-9' _; }
case "$1 $2" in
  "registry "*|"tag ls") exit 0 ;;
  "image digest") cat "$FIX/digest/$(key "$3")" 2>/dev/null || { echo "not found: $3" >&2; exit 1; } ;;
  "manifest get") cat "$FIX/manifest/$(key "${3#*@}")" ;;
  "image copy")
    echo "$*" >> "$FIX/copies"
    for a in "$@"; do case "$a" in --*) echo "unexpected flag $a" >&2; exit 1 ;; esac; done
    printf '%s' "${3#*@}" > "$FIX/digest/$(key "$4")" ;;
  *) echo "unexpected regctl $*" >&2; exit 1 ;;
esac
`

const fakeGh = `#!/usr/bin/env bash
key() { printf '%s' "$1" | tr -c 'A-Za-z0-9' _; }
echo "$*" >> "$FIX/gh.log"
case "$1 $2" in
  "attestation verify") f="$FIX/att/$(key "${3#*@}")"; [[ -f $f ]] && cat "$f" || { echo "no attestations" >&2; exit 1; } ;;
  "api "*) jq "$4" "$FIX/api/$(key "$2")" ;;
  *) echo "unexpected gh $*" >&2; exit 1 ;;
esac
`

type fakeTools struct {
	t        *testing.T
	fix, bin string
}

func newFakeTools(t *testing.T) *fakeTools {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	dir := t.TempDir()
	f := &fakeTools{t: t, fix: filepath.Join(dir, "fix"), bin: filepath.Join(dir, "bin")}
	for _, d := range []string{f.bin, f.fix + "/digest", f.fix + "/manifest", f.fix + "/att", f.fix + "/api"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.write(f.bin+"/regctl", fakeRegctl)
	f.write(f.bin+"/gh", fakeGh)
	return f
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)

func (f *fakeTools) write(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeTools) set(kind, key string, v any) {
	b, ok := v.([]byte)
	if !ok {
		b, _ = json.Marshal(v)
	}
	f.write(filepath.Join(f.fix, kind, nonAlnum.ReplaceAllString(key, "_")), string(b))
}

func digestOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// image pushes a tag pointing at an index over the given platform manifests,
// and returns the index digest.
func (f *fakeTools) image(tag string, platforms ...string) string {
	var children []map[string]any
	for _, p := range platforms {
		d := digestOf(p)
		f.set("manifest", d, map[string]any{"schemaVersion": 2})
		children = append(children, map[string]any{"digest": d})
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": children})
	d := digestOf(string(idx))
	f.set("manifest", d, idx)
	f.set("digest", "src.example/img:"+tag, []byte(d))
	return d
}

func (f *fakeTools) attest(digest string, certs ...map[string]any) {
	var out []any
	for _, c := range certs {
		out = append(out, map[string]any{"verificationResult": map[string]any{"signature": map[string]any{"certificate": c}}})
	}
	f.set("att", digest, out)
}

// attestTree attests the index behind tag and its platform manifests.
func (f *fakeTools) attestTree(index string, platforms []string, c map[string]any) {
	f.attest(index, c)
	for _, p := range platforms {
		f.attest(digestOf(p), c)
	}
}

func cert(overrides map[string]any) map[string]any {
	c := map[string]any{
		"subjectAlternativeName":     "https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0",
		"buildSignerURI":             "https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0",
		"sourceRepositoryURI":        "https://github.com/example/app",
		"sourceRepositoryIdentifier": "1001",
		"sourceRepositoryRef":        "refs/tags/v1.0.0",
		"runnerEnvironment":          "github-hosted",
		"runInvocationURI":           "https://github.com/example/app/actions/runs/77/attempts/1",
	}
	for k, v := range overrides {
		c[k] = v
	}
	return c
}

func (f *fakeTools) run(publishers, pairs string, env ...string) (string, error) {
	path := filepath.Join(f.t.TempDir(), "images.yaml")
	f.write(path, "source: src.example\ndestination: dest.example\nimages:\n  img:\n    publishers:\n"+publishers)
	cfg, err := loadConfig(path)
	if err != nil {
		f.t.Fatal(err)
	}
	rule, _ := json.Marshal(cfg.Images["img"].Publishers)
	cmd := exec.Command("bash", "scripts/mirror.sh")
	cmd.Env = []string{
		"PATH=" + f.bin + ":" + os.Getenv("PATH"),
		"HOME=" + f.t.TempDir(),
		"FIX=" + f.fix,
		"RULE=" + string(rule),
		"SOURCE=src.example",
		"DESTINATION=dest.example",
		"IMAGE=img",
		"TAGS=" + pairs,
		"REQUEST_ID=test",
	}
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *fakeTools) copies() string {
	b, _ := os.ReadFile(filepath.Join(f.fix, "copies"))
	return string(b)
}

func TestScriptAuthorisation(t *testing.T) {
	platforms := []string{"amd64", "arm64"}
	const app = "      - repo: example/app\n"

	cases := []struct {
		name       string
		publishers string
		cert       map[string]any
		tag        string
		ok         bool
	}{
		{"attested by the publisher", app, nil, "v1.0.0", true},
		{"attested by another repo", app, map[string]any{"sourceRepositoryURI": "https://github.com/example/other"}, "v1.0.0", false},
		{"ref regex matches whole ref only", app + "        source_refs: refs/tags/v1\n", nil, "v1.0.0", false},
		{"ref regex", app + "        source_refs: 'refs/tags/v.*'\n", nil, "v1.0.0", true},
		{"tag regex matches whole tag only", app + "        tags: v1\n", nil, "v1.0.0", false},
		{"self-hosted", app, map[string]any{"runnerEnvironment": "self-hosted"}, "v1.0.0", false},
		{"self-hosted allowed", app + "        allow_self_hosted: true\n", map[string]any{"runnerEnvironment": "self-hosted"}, "v1.0.0", true},
		{"repo id matches", app + "        repo_id: 1001\n", nil, "v1.0.0", true},
		{"repo recreated under the same name", app + "        repo_id: 1001\n", map[string]any{"sourceRepositoryIdentifier": "2002"}, "v1.0.0", false},
		{"signer workflow", app + "        signer_workflows: [example/app/.github/workflows/release.yml]\n", nil, "v1.0.0", true},
		{
			"signer workflow only shares a prefix",
			app + "        signer_workflows: [example/app/.github/workflows/release.yml]\n",
			map[string]any{"subjectAlternativeName": "https://github.com/example/app/.github/workflows/release.yml.evil.yml@refs/tags/v1.0.0"},
			"v1.0.0", false,
		},
		{
			"signer in another repo by default",
			app,
			map[string]any{"subjectAlternativeName": "https://github.com/example/tools/.github/workflows/build.yml@refs/heads/main"},
			"v1.0.0", false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeTools(t)
			d := f.image(c.tag, platforms...)
			f.attestTree(d, platforms, cert(c.cert))
			out, err := f.run(c.publishers, c.tag+"@"+d)
			if (err == nil) != c.ok {
				t.Fatalf("allowed=%v, want %v\n%s", err == nil, c.ok, out)
			}
			if c.ok != strings.Contains(f.copies(), "dest.example/img:"+c.tag) {
				t.Fatalf("copies = %q", f.copies())
			}
		})
	}
}

func TestScriptRequiresEveryManifestAttested(t *testing.T) {
	f := newFakeTools(t)
	d := f.image("v1.0.0", "amd64", "arm64")
	f.attest(d, cert(nil))
	f.attest(digestOf("amd64"), cert(nil))
	f.attest(digestOf("arm64"), cert(map[string]any{"runnerEnvironment": "self-hosted"}))
	if out, err := f.run("      - repo: example/app\n", "v1.0.0@"+d); err == nil {
		t.Fatalf("copied with a self-hosted platform manifest:\n%s", out)
	}
}

func TestScriptCopiesOnlyTheImage(t *testing.T) {
	f := newFakeTools(t)
	d := f.image("v1.0.0", "amd64")
	f.attestTree(d, []string{"amd64"}, cert(nil))
	if out, err := f.run("      - repo: example/app\n", "v1.0.0@"+d); err != nil {
		t.Fatal(out)
	}
	// The fake regctl fails on any flag, so referrers and digest tags, which
	// nothing attests, are not copied.
	if got, want := strings.TrimSpace(f.copies()), "image copy src.example/img@"+d+" dest.example/img:v1.0.0"; got != want {
		t.Fatalf("copy = %q, want %q", got, want)
	}
}

// A publisher limited to events only accepts attestations from runs those
// events triggered: a labelled pull_request_target build of PR code, which
// attests as the base branch, can't use a publisher meant for pushes.
func TestScriptEvents(t *testing.T) {
	f := newFakeTools(t)
	d := f.image("master", "amd64")
	f.attestTree(d, []string{"amd64"}, cert(map[string]any{"buildTrigger": "pull_request_target", "sourceRepositoryRef": "refs/heads/master"}))

	pushOnly := "      - repo: example/app\n        events: [push]\n"
	if out, err := f.run(pushOnly, "master@"+d); err == nil || f.copies() != "" {
		t.Fatalf("a pull_request_target attestation passed a push-only publisher:\n%s", out)
	}
	prTags := "      - repo: example/app\n        events: [pull_request_target]\n        tags: 'pr-[0-9]+'\n"
	if out, err := f.run(prTags, "master@"+d); err == nil || f.copies() != "" {
		t.Fatalf("a PR build published a branch tag:\n%s", out)
	}
	f.set("digest", "src.example/img:pr-343", []byte(d))
	if out, err := f.run(prTags, "pr-343@"+d); err != nil || f.copies() == "" {
		t.Fatalf("a PR build couldn't publish its pr tag (err %v):\n%s", err, out)
	}
}

// The poller runs with FILL_ONLY: re-pointing a source tag at another attested
// digest (rolling latest back, say) must not move the destination tag.
func TestScriptFillOnlyNeverMovesTags(t *testing.T) {
	f := newFakeTools(t)
	older := f.image("latest", "amd64")
	f.attestTree(older, []string{"amd64"}, cert(nil))
	f.set("digest", "dest.example/img:latest", []byte(digestOf("current release")))

	out, err := f.run("      - repo: example/app\n", "latest@"+older, "FILL_ONLY=true")
	if err != nil || f.copies() != "" || !strings.Contains(out, "left at") {
		t.Fatalf("fill-only moved an existing tag (err %v, copies %q):\n%s", err, f.copies(), out)
	}
	// A publish request (not fill-only) does move it.
	if out, err := f.run("      - repo: example/app\n", "latest@"+older); err != nil || f.copies() == "" {
		t.Fatalf("publish request did not move the tag (err %v):\n%s", err, out)
	}
}

func TestScriptActorsUseTheAttestedAttempt(t *testing.T) {
	const pub = "      - repo: example/app\n        actors: [alice]\n"
	attempt := func(actor, triggering string) map[string]any {
		return map[string]any{"actor": map[string]any{"login": actor}, "triggering_actor": map[string]any{"login": triggering}}
	}
	cases := []struct {
		name     string
		attempts map[string]map[string]any
		ok       bool
	}{
		{"allowed actor", map[string]map[string]any{"1": attempt("alice", "alice")}, true},
		// mallory's attempt 1 is attested; alice re-running it later must
		// not bless it.
		{"re-run by an allowed actor", map[string]map[string]any{"1": attempt("mallory", "mallory"), "2": attempt("mallory", "alice")}, false},
		{"started by someone else, re-run by allowed actor", map[string]map[string]any{"1": attempt("mallory", "alice")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeTools(t)
			d := f.image("v1.0.0", "amd64")
			f.attestTree(d, []string{"amd64"}, cert(nil))
			for n, a := range c.attempts {
				f.set("api", "repos/example/app/actions/runs/77/attempts/"+n, a)
			}
			// The run itself reports its latest attempt.
			latest := c.attempts[fmt.Sprint(len(c.attempts))]
			f.set("api", "repos/example/app/actions/runs/77", latest)
			out, err := f.run(pub, "v1.0.0@"+d)
			if (err == nil) != c.ok {
				t.Fatalf("allowed=%v, want %v\n%s", err == nil, c.ok, out)
			}
		})
	}
}

func TestScriptBoundsUnverifiedManifests(t *testing.T) {
	f := newFakeTools(t)
	var platforms []string
	for i := range 100 {
		platforms = append(platforms, fmt.Sprint("p", i))
	}
	d := f.image("v1.0.0", platforms...)
	out, err := f.run("      - repo: example/app\n", "v1.0.0@"+d)
	if err == nil || !strings.Contains(out, "more than 64 manifests") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(f.fix, "gh.log")); len(b) > 0 {
		t.Fatalf("called gh before bounding the request:\n%s", b)
	}
}

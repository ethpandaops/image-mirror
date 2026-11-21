// image-mirror copies container images built by GitHub Actions from a source
// registry to a destination registry, after checking each digest's GitHub
// artifact attestation against an allowlist.
//
// Two paths share one verify-and-copy routine and a per-image lock:
//   - POST /v1/mirror, authenticated with the calling job's GitHub OIDC token,
//     which waits for the copy;
//   - a poller that mirrors any allowed source tag the destination lacks.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

// config is the allowlist.
type config struct {
	// Images are copied from <Source>/<image> to <Destination>/<image>.
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Defaults    struct {
		SourceRefs      string `yaml:"source_refs"`
		AllowSelfHosted bool   `yaml:"allow_self_hosted"`
	} `yaml:"defaults"`
	// Images lists every image the mirror may publish. Anything else is
	// refused.
	Images map[string]*image `yaml:"images"`
}

// image is one allowlisted image.
type image struct {
	// Publishers are the repos that may publish the image, each under its
	// own conditions. A request needs one publisher to allow all of it.
	Publishers []*publisher `yaml:"publishers"`
}

// publisher says which repo may publish an image, and under which conditions.
type publisher struct {
	Repo            string   `yaml:"repo" json:"repo"`
	SignerWorkflows []string `yaml:"signer_workflows" json:"signer_workflows"`
	SourceRefs      string   `yaml:"source_refs" json:"source_refs"`
	Actors          []string `yaml:"actors" json:"actors"`
	Tags            string   `yaml:"tags" json:"tags"`
	AllowSelfHosted *bool    `yaml:"allow_self_hosted" json:"allow_self_hosted"`

	sourceRefs *regexp.Regexp
	tags       *regexp.Regexp
}

// allows is the early check on the HTTP path, from the caller's OIDC claims.
// The script re-checks the same rules from the attestations, which is what
// actually authorises a copy.
func (p *publisher) allows(cl githubClaims, tags []string) bool {
	if cl.Repository != p.Repo || !p.sourceRefs.MatchString(cl.Ref) {
		return false
	}
	if cl.RunnerEnvironment != "github-hosted" && !*p.AllowSelfHosted {
		return false
	}
	if len(p.Actors) > 0 && !contains(p.Actors, cl.Actor) && !contains(p.Actors, cl.TriggeringActor) {
		return false
	}
	for _, t := range tags {
		if p.tags != nil && !p.tags.MatchString(t) {
			return false
		}
	}
	return true
}

func (c *config) callerAllowed(image string, cl githubClaims, tags []string) error {
	img, ok := c.Images[image]
	if !ok {
		return errors.New("image " + image + " is not in the mirror's allowlist")
	}
	for _, p := range img.Publishers {
		if p.allows(cl, tags) {
			return nil
		}
	}
	return fmt.Errorf("%s (ref %s, %s runner) may not publish these tags of %s", cl.Repository, cl.Ref, cl.RunnerEnvironment, image)
}

// tagAllowed reports whether any publisher of image may publish tag.
func (c *config) tagAllowed(image, tag string) bool {
	img := c.Images[image]
	if img == nil {
		return false
	}
	for _, p := range img.Publishers {
		if p.tags == nil || p.tags.MatchString(tag) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s && s != "" {
			return true
		}
	}
	return false
}

type githubClaims struct {
	Repository        string `json:"repository"`
	Actor             string `json:"actor"`
	TriggeringActor   string `json:"triggering_actor"`
	Ref               string `json:"ref"`
	RunnerEnvironment string `json:"runner_environment"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
}

type server struct {
	cfg      *config
	script   string
	verifier *oidc.IDTokenVerifier
	// tokens mints GitHub API tokens when a GitHub App is configured;
	// otherwise the script uses GH_TOKEN from the environment.
	tokens *appTokens

	jobsMu sync.Mutex
	jobs   map[string]*job

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex

	// Poller memory: source digest last mirrored (or found current) per
	// image:tag, and digests that failed verification, so a bad tag is not
	// retried every cycle.
	stateMu  sync.Mutex
	current  map[string]string
	rejected map[string]time.Time
}

var (
	imageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	tagRe       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	digestRe    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	cfgPath := flag.String("config", "images.yaml", "allowlist file")
	script := flag.String("script", "scripts/mirror.sh", "verify-and-copy script")
	audience := flag.String("audience", "image-mirror", "required OIDC audience")
	pollEvery := flag.Duration("poll-interval", 2*time.Minute, "poll interval, 0 disables polling")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	provider, err := oidc.NewProvider(context.Background(), githubIssuer)
	if err != nil {
		slog.Error("oidc provider", "err", err)
		os.Exit(1)
	}

	var tokens *appTokens
	if appID := os.Getenv("GITHUB_APP_ID"); appID != "" {
		tokens, err = newAppTokens(appID, os.Getenv("GITHUB_APP_INSTALLATION_ID"), os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE"))
		if err != nil {
			slog.Error("github app", "err", err)
			os.Exit(1)
		}
		if _, err := tokens.Token(context.Background()); err != nil {
			slog.Error("github app", "err", err)
			os.Exit(1)
		}
	} else if os.Getenv("GH_TOKEN") == "" {
		slog.Error("set GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID and GITHUB_APP_PRIVATE_KEY_FILE, or GH_TOKEN")
		os.Exit(1)
	}

	s := &server{
		tokens:   tokens,
		cfg:      cfg,
		script:   *script,
		verifier: provider.Verifier(&oidc.Config{ClientID: *audience}),
		locks:    map[string]*sync.Mutex{},
		jobs:     map[string]*job{},
		current:  map[string]string{},
		rejected: map[string]time.Time{},
	}

	if *pollEvery > 0 {
		go s.pollLoop(*pollEvery)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/mirror", s.handleMirror)
	mux.HandleFunc("GET /v1/jobs/{id}", s.handleJob)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
	}
	slog.Info("listening", "addr", *listen, "destination", cfg.Destination, "images", len(cfg.Images), "poll", pollEvery.String())
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // a misspelt restriction must fail, not be ignored
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if c.Source == "" || c.Destination == "" {
		return nil, errors.New("source and destination are required")
	}
	for name, img := range c.Images {
		if !imageNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid image name %q", name)
		}
		if img == nil || len(img.Publishers) == 0 {
			return nil, fmt.Errorf("images.%s: no publishers", name)
		}
		for _, p := range img.Publishers {
			if owner, repo, ok := strings.Cut(p.Repo, "/"); !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
				return nil, fmt.Errorf("images.%s: repo must be <owner>/<name>", name)
			}
			if p.SourceRefs == "" {
				p.SourceRefs = c.Defaults.SourceRefs
			}
			if p.SourceRefs == "" {
				p.SourceRefs = ".*"
			}
			if p.AllowSelfHosted == nil {
				v := c.Defaults.AllowSelfHosted
				p.AllowSelfHosted = &v
			}
			if p.sourceRefs, err = regexp.Compile(p.SourceRefs); err != nil {
				return nil, fmt.Errorf("images.%s.source_refs: %w", name, err)
			}
			if p.Tags != "" {
				if p.tags, err = regexp.Compile(p.Tags); err != nil {
					return nil, fmt.Errorf("images.%s.tags: %w", name, err)
				}
			}
		}
	}
	return &c, nil
}

type mirrorRequest struct {
	Image string   `json:"image"`
	Tags  []string `json:"tags"` // tag@sha256:digest
}

func (s *server) handleMirror(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	claims, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	var req mirrorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if len(req.Tags) == 0 || len(req.Tags) > 30 {
		http.Error(w, "expected 1-30 tags", http.StatusBadRequest)
		return
	}
	tags := make([]string, 0, len(req.Tags))
	for _, p := range req.Tags {
		tag, digest, ok := strings.Cut(p, "@")
		if !ok || !tagRe.MatchString(tag) || !digestRe.MatchString(digest) {
			http.Error(w, "invalid tag: "+p, http.StatusBadRequest)
			return
		}
		tags = append(tags, tag)
	}
	// Cheap early check on the caller. The script re-checks the same rules
	// from the attestations, which is what actually authorises the copy.
	if err := s.cfg.callerAllowed(req.Image, claims, tags); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	requestID := fmt.Sprintf("%s-%s-%s", claims.RunID, claims.RunAttempt, randomHex(4))
	sourceRun := fmt.Sprintf("https://github.com/%s/actions/runs/%s", claims.Repository, claims.RunID)
	log := slog.With("request", requestID, "image", req.Image, "repo", claims.Repository, "ref", claims.Ref)
	log.Info("mirror request", "tags", req.Tags)

	// The copy runs detached from the request, so a dropped connection or a
	// proxy timeout does not abort it. Short jobs answer inline; longer ones
	// answer 202 with a job ID to poll.
	id := randomHex(16)
	j := &job{repo: claims.Repository, start: start, done: make(chan struct{})}
	s.addJob(id, j)
	go func() {
		out, err := s.mirror(context.Background(), req.Image, req.Tags, requestID, sourceRun)
		j.out, j.err, j.end = out, err, time.Now()
		if err != nil {
			log.Warn("mirror failed", "err", err, "elapsed", j.end.Sub(start).Round(time.Millisecond))
		} else {
			log.Info("mirror done", "elapsed", j.end.Sub(start).Round(time.Millisecond))
		}
		close(j.done)
	}()

	select {
	case <-j.done:
		writeJob(w, j)
	case <-time.After(25 * time.Second):
		w.Header().Set("Location", "/v1/jobs/"+id)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, id)
	}
}

type job struct {
	repo       string
	start, end time.Time
	out        string
	err        error
	done       chan struct{}
}

func (s *server) addJob(id string, j *job) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	for k, old := range s.jobs {
		if !old.end.IsZero() && time.Since(old.end) > time.Hour {
			delete(s.jobs, k)
		}
	}
	s.jobs[id] = j
}

func (s *server) handleJob(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	s.jobsMu.Lock()
	j := s.jobs[r.PathValue("id")]
	s.jobsMu.Unlock()
	if j == nil || j.repo != claims.Repository {
		http.Error(w, "no such job", http.StatusNotFound)
		return
	}
	select {
	case <-j.done:
		writeJob(w, j)
	default:
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "running")
	}
}

func writeJob(w http.ResponseWriter, j *job) {
	elapsed := j.end.Sub(j.start).Round(time.Millisecond)
	if j.err != nil {
		http.Error(w, fmt.Sprintf("%smirror failed after %s", j.out, elapsed), http.StatusUnprocessableEntity)
		return
	}
	fmt.Fprintf(w, "%smirrored in %s\n", j.out, elapsed)
}

// authenticate verifies the request's GitHub OIDC token.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request) (githubClaims, bool) {
	var claims githubClaims
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return claims, false
	}
	tok, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return claims, false
	}
	if err := tok.Claims(&claims); err != nil {
		http.Error(w, "invalid token claims", http.StatusUnauthorized)
		return claims, false
	}
	return claims, true
}

// mirror runs the verify-and-copy script with the per-image lock held.
func (s *server) mirror(ctx context.Context, image string, pairs []string, requestID, sourceRun string) (string, error) {
	lock := s.lock(image)
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	rule, err := json.Marshal(s.cfg.Images[image].Publishers)
	if err != nil {
		return "", err
	}
	env := os.Environ()
	if s.tokens != nil {
		tok, err := s.tokens.Token(ctx)
		if err != nil {
			return err.Error(), err
		}
		env = append(env, "GH_TOKEN="+tok) // the last value of a duplicate key wins
	}
	cmd := exec.CommandContext(ctx, "bash", s.script)
	cmd.Env = append(env,
		"RULE="+string(rule),
		"SOURCE="+s.cfg.Source,
		"DESTINATION="+s.cfg.Destination,
		"IMAGE="+image,
		"TAGS="+strings.Join(pairs, " "),
		"REQUEST_ID="+requestID,
		"SOURCE_RUN="+sourceRun,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		s.stateMu.Lock()
		for _, p := range pairs {
			tag, digest, _ := strings.Cut(p, "@")
			s.current[image+":"+tag] = digest
		}
		s.stateMu.Unlock()
	}
	return string(out), err
}

func (s *server) lock(image string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.locks[image] == nil {
		s.locks[image] = &sync.Mutex{}
	}
	return s.locks[image]
}

func (s *server) pollLoop(every time.Duration) {
	for {
		s.pollOnce(context.Background())
		time.Sleep(every)
	}
}

// pollOnce mirrors every allowed GHCR tag whose destination differs, for
// every image in the allowlist.
func (s *server) pollOnce(ctx context.Context) {
	names := make([]string, 0, len(s.cfg.Images))
	for name := range s.cfg.Images {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		log := slog.With("image", name, "path", "poll")
		src := s.cfg.Source + "/" + name
		dest := s.cfg.Destination + "/" + name
		tags, err := regctl(ctx, "tag", "ls", src)
		if err != nil {
			continue // no GHCR package for this image (yet)
		}

		var pairs []string
		for _, tag := range strings.Fields(tags) {
			if !tagRe.MatchString(tag) || !s.cfg.tagAllowed(name, tag) {
				continue
			}
			digest, err := regctl(ctx, "image", "digest", src+":"+tag)
			if err != nil {
				log.Warn("source digest", "tag", tag, "err", err)
				continue
			}
			key := name + ":" + tag
			s.stateMu.Lock()
			known := s.current[key] == digest
			_, bad := s.rejected[name+"@"+digest]
			s.stateMu.Unlock()
			if known || bad {
				continue
			}
			if d, err := regctl(ctx, "image", "digest", dest+":"+tag); err == nil && d == digest {
				s.stateMu.Lock()
				s.current[key] = digest
				s.stateMu.Unlock()
				continue
			}
			pairs = append(pairs, tag+"@"+digest)
		}

		// Mirror tag by tag so one unverifiable tag does not block the rest.
		for _, p := range pairs {
			start := time.Now()
			out, err := s.mirror(ctx, name, []string{p}, "poll-"+randomHex(4), "")
			if err != nil {
				_, digest, _ := strings.Cut(p, "@")
				s.stateMu.Lock()
				s.rejected[name+"@"+digest] = time.Now()
				s.stateMu.Unlock()
				log.Warn("poll mirror refused; not retrying this digest", "tag", p, "output", lastLines(out, 3))
				continue
			}
			log.Info("poll mirrored", "tag", p, "elapsed", time.Since(start).Round(time.Millisecond))
		}
	}
}

func regctl(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "regctl", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

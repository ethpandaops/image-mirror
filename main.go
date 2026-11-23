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
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

// Limits on what callers can make the service do. Any GitHub Actions job can
// mint a token for the audience, so everything before the allowlist check
// must be cheap, and allowed callers share one GitHub API rate limit and one
// destination credential.
const (
	jobRetention       = 15 * time.Minute // how long a finished job can be fetched
	maxJobOutput       = 64 << 10         // bytes of script output kept per job
	rejectedRetryAfter = time.Hour        // when the poller retries a refused digest
	scriptTimeout      = 15 * time.Minute // one verify-and-copy run, after the image lock
)

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
	// Poll is whether the background poller backfills this image. Turn it off
	// for images whose tags grow without bound (a tag per commit): the poller
	// reads every source tag's digest each cycle. Publish requests still work.
	Poll *bool `yaml:"poll"`
}

// publisher says which repo may publish an image, and under which conditions.
// It is passed to the script as JSON, with SourceRefs and Tags anchored.
type publisher struct {
	Repo            string   `yaml:"repo" json:"repo"`
	RepoID          int64    `yaml:"repo_id" json:"repo_id,omitempty"`
	SignerWorkflows []string `yaml:"signer_workflows" json:"signer_workflows"`
	SourceRefs      string   `yaml:"source_refs" json:"source_refs"`
	Actors          []string `yaml:"actors" json:"actors"`
	// Events limits the events that may have triggered the attested run
	// (push, workflow_dispatch, pull_request_target, ...). Any when unset.
	Events []string `yaml:"events" json:"events"`
	Tags   string   `yaml:"tags" json:"tags"`
	// ExcludeTags refuses tags that Tags would allow, for rules RE2 can't
	// express without lookahead, such as "any tag except latest".
	ExcludeTags     string `yaml:"exclude_tags" json:"exclude_tags"`
	AllowSelfHosted *bool  `yaml:"allow_self_hosted" json:"allow_self_hosted"`

	sourceRefs  *regexp.Regexp
	tags        *regexp.Regexp
	excludeTags *regexp.Regexp
}

// allows is the early check on the HTTP path, from the caller's OIDC claims.
// The script re-checks the same rules from the attestations, which is what
// actually authorises a copy.
func (p *publisher) allows(cl githubClaims, tags []string) bool {
	if !strings.EqualFold(cl.Repository, p.Repo) || !p.sourceRefs.MatchString(cl.Ref) {
		return false
	}
	if p.RepoID != 0 && cl.RepositoryID != strconv.FormatInt(p.RepoID, 10) {
		return false
	}
	if cl.RunnerEnvironment != "github-hosted" && !*p.AllowSelfHosted {
		return false
	}
	if len(p.Actors) > 0 && !contains(p.Actors, cl.Actor) {
		return false
	}
	if len(p.Events) > 0 && !contains(p.Events, cl.EventName) {
		return false
	}
	for _, t := range tags {
		if !p.allowsTag(t) {
			return false
		}
	}
	return true
}

func (p *publisher) allowsTag(tag string) bool {
	return (p.tags == nil || p.tags.MatchString(tag)) && (p.excludeTags == nil || !p.excludeTags.MatchString(tag))
}

// callerAllowed returns the same error whether or not the image is listed, so
// callers cannot probe the allowlist.
func (c *config) callerAllowed(image string, cl githubClaims, tags []string) error {
	if img, ok := c.Images[image]; ok {
		for _, p := range img.Publishers {
			if p.allows(cl, tags) {
				return nil
			}
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
		if p.allowsTag(tag) {
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
	RepositoryID      string `json:"repository_id"`
	Actor             string `json:"actor"`
	Ref               string `json:"ref"`
	EventName         string `json:"event_name"`
	RunnerEnvironment string `json:"runner_environment"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
}

type server struct {
	cfg        *config
	script     string
	verifier   *oidc.IDTokenVerifier
	inlineWait time.Duration // how long POST /v1/mirror waits before answering 202
	limits     limits
	// tokens mints GitHub API tokens when a GitHub App is configured;
	// otherwise the script uses GH_TOKEN from the environment.
	tokens *appTokens

	rdb       redis.UniversalClient
	replica   string        // this replica's lease token
	reapEvery time.Duration // how often to look for jobs nobody holds

	// jobsCtx ends when a draining replica gives up on its running jobs;
	// jobsWG counts them and the poll cycle in progress.
	jobsCtx    context.Context
	cancelJobs context.CancelFunc
	jobsWG     sync.WaitGroup
	draining   atomic.Bool

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

	eventRe          = regexp.MustCompile(`^[a-z_]+$`)
	signerWorkflowRe = regexp.MustCompile(`^[^/@]+/[^/@]+/\.github/workflows/[^@]+$`)
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	metricsListen := flag.String("metrics-listen", ":9090", "Prometheus metrics listen address, empty to disable")
	redisAddrs := flag.String("redis-addrs", "localhost:6379", "comma-separated Redis addresses; Sentinel addresses with -redis-master")
	redisMaster := flag.String("redis-master", "", "Sentinel master name, empty for a single Redis")
	drainTimeout := flag.Duration("drain-timeout", 10*time.Minute, "on shutdown, how long running jobs may finish before they are left for another replica")
	cfgPath := flag.String("config", "images.yaml", "allowlist file")
	script := flag.String("script", "scripts/mirror.sh", "verify-and-copy script")
	audience := flag.String("audience", "image-mirror", "required OIDC audience")
	pollEvery := flag.Duration("poll-interval", 2*time.Minute, "poll interval, 0 disables polling")
	lim := defaultLimits
	flag.IntVar(&lim.jobsPerRepo, "max-jobs-per-repo", lim.jobsPerRepo, "queued or running mirror jobs per calling repository; more get 429")
	flag.IntVar(&lim.jobs, "max-jobs", lim.jobs, "queued or running mirror jobs in total; more get 429")
	flag.IntVar(&lim.pollPerImage, "poll-max-per-image", lim.pollPerImage, "tags the poller verifies per image per cycle")
	flag.Parse()
	if lim.jobsPerRepo < 1 || lim.jobs < 1 || lim.pollPerImage < 1 {
		slog.Error("limits must be at least 1")
		os.Exit(1)
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), client), githubIssuer)
	if err != nil {
		slog.Error("oidc provider", "err", err)
		os.Exit(1)
	}
	var discovery struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovery); err != nil || discovery.JWKSURL == "" {
		slog.Error("oidc provider has no jwks_uri", "err", err)
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

	// REDIS_PASSWORD authenticates to Redis and, with -redis-master, to Sentinel.
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:            strings.Split(*redisAddrs, ","),
		MasterName:       *redisMaster,
		Password:         os.Getenv("REDIS_PASSWORD"),
		SentinelPassword: os.Getenv("REDIS_PASSWORD"),
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("redis", "err", err)
		os.Exit(1)
	}

	s := newServer(cfg, *script, newVerifier(githubIssuer, *audience, &keySet{url: discovery.JWKSURL, client: client, minRefresh: time.Minute}), rdb)
	s.tokens = tokens
	s.limits = lim
	configuredLimit.WithLabelValues("jobs").Set(float64(lim.jobs))
	configuredLimit.WithLabelValues("jobs_per_repo").Set(float64(lim.jobsPerRepo))
	configuredLimit.WithLabelValues("poll_per_image").Set(float64(lim.pollPerImage))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	bg, stopBg := context.WithCancel(context.Background())
	go s.reapLoop(bg)
	if *pollEvery > 0 {
		go s.pollLoop(bg, *pollEvery)
	}
	if *metricsListen != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("GET /metrics", promhttp.Handler())
			slog.Error("metrics", "err", http.ListenAndServe(*metricsListen, mux))
		}()
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	slog.Info("listening", "addr", *listen, "destination", cfg.Destination, "images", len(cfg.Images), "poll", pollEvery.String(), "replica", s.replica)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	s.drain(*drainTimeout)
	stopBg()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}

// drain stops this replica taking work and waits for its running jobs. The
// replica stays reachable meanwhile: it still answers job status from Redis
// and admits new jobs, which other replicas run. Jobs still running after
// timeout are stopped and left for another replica to resume.
func (s *server) drain(timeout time.Duration) {
	s.draining.Store(true)
	draining.Set(1)
	slog.Info("draining", "timeout", timeout)
	done := make(chan struct{})
	go func() { s.jobsWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("drain timeout; handing running jobs over")
		s.cancelJobs()
		<-done
	}
	slog.Info("drained")
}

// limits caps the work callers and the poller can cause. Allowed callers
// share one GitHub API rate limit and one destination credential.
type limits struct {
	jobsPerRepo  int // queued or running jobs per calling repository
	jobs         int // queued or running jobs in total
	pollPerImage int // verifications per image per poll cycle
}

var defaultLimits = limits{jobsPerRepo: 4, jobs: 32, pollPerImage: 10}

func newServer(cfg *config, script string, verifier *oidc.IDTokenVerifier, rdb redis.UniversalClient) *server {
	host, _ := os.Hostname()
	jobsCtx, cancelJobs := context.WithCancel(context.Background())
	return &server{
		cfg:      cfg,
		script:   script,
		verifier: verifier,
		// Short, so callers spend the wait polling GET /v1/jobs/{id}, which
		// any replica answers, rather than holding a connection to one
		// replica that may stop.
		inlineWait: time.Second,
		limits:     defaultLimits,
		rdb:        rdb,
		replica:    host + "-" + randomHex(4),
		reapEvery:  5 * time.Second,
		jobsCtx:    jobsCtx,
		cancelJobs: cancelJobs,
		current:    map[string]string{},
		rejected:   map[string]time.Time{},
	}
}

func newVerifier(issuer, audience string, keys oidc.KeySet) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{oidc.RS256}})
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/mirror", counted("mirror", s.handleMirror))
	mux.Handle("GET /v1/jobs/{id}", counted("job", s.handleJob))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Ready while Redis answers and the replica isn't draining, so a rollout
	// moves new requests to the other replicas first.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.draining.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		if err := s.rdb.Ping(r.Context()).Err(); err != nil {
			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// keySet verifies token signatures against the issuer's JWKS. go-oidc's
// RemoteKeySet refetches the JWKS for every token it cannot verify, so anyone
// could make the service fetch it on every request with a made-up key ID or
// signature. This refetches at most once per minRefresh.
type keySet struct {
	url        string
	client     *http.Client
	minRefresh time.Duration

	mu      sync.Mutex
	keys    map[string]jose.JSONWebKey
	fetched time.Time
}

func (k *keySet) VerifySignature(_ context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	key, err := k.key(jws.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}
	return jws.Verify(key)
}

func (k *keySet) key(kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.keys[kid]; ok {
		return &key, nil
	}
	if time.Since(k.fetched) < k.minRefresh {
		return nil, fmt.Errorf("unknown key ID %q", kid)
	}
	k.fetched = time.Now()
	resp, err := k.client.Get(k.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch keys: %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode keys: %w", err)
	}
	k.keys = map[string]jose.JSONWebKey{}
	for _, key := range set.Keys {
		if key.KeyID != "" {
			k.keys[key.KeyID] = key
		}
	}
	if key, ok := k.keys[kid]; ok {
		return &key, nil
	}
	return nil, fmt.Errorf("unknown key ID %q", kid)
}

// anchor makes a config regex match whole strings: an unanchored
// source_refs of refs/heads/main must not also allow refs/heads/main-evil.
// The plain group works in RE2, jq and POSIX ERE alike.
func anchor(re string) string {
	return "^(" + re + ")$"
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
			if p.RepoID < 0 {
				return nil, fmt.Errorf("images.%s: invalid repo_id", name)
			}
			for _, e := range p.Events {
				if !eventRe.MatchString(e) {
					return nil, fmt.Errorf("images.%s: invalid event %q", name, e)
				}
			}
			for _, w := range p.SignerWorkflows {
				if !signerWorkflowRe.MatchString(w) {
					return nil, fmt.Errorf("images.%s: signer_workflows entries must be <owner>/<repo>/.github/workflows/<file>, without @ref", name)
				}
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
			p.SourceRefs = anchor(p.SourceRefs)
			if p.sourceRefs, err = regexp.Compile(p.SourceRefs); err != nil {
				return nil, fmt.Errorf("images.%s.source_refs: %w", name, err)
			}
			if p.Tags != "" {
				p.Tags = anchor(p.Tags)
				if p.tags, err = regexp.Compile(p.Tags); err != nil {
					return nil, fmt.Errorf("images.%s.tags: %w", name, err)
				}
			}
			if p.ExcludeTags != "" {
				p.ExcludeTags = anchor(p.ExcludeTags)
				if p.excludeTags, err = regexp.Compile(p.ExcludeTags); err != nil {
					return nil, fmt.Errorf("images.%s.exclude_tags: %w", name, err)
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
			http.Error(w, "invalid tag@digest pair", http.StatusBadRequest)
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
	log := slog.With("request", requestID, "image", req.Image, "repo", claims.Repository, "ref", claims.Ref)

	// The copy runs detached from the request, so a dropped connection or a
	// proxy timeout does not abort it. Short jobs answer inline; longer ones
	// answer 202 with a job ID any replica can answer for.
	id := randomHex(16)
	rec := jobRecord{
		Image: req.Image, Pairs: strings.Join(req.Tags, " "), RequestID: requestID,
		Repo: strings.ToLower(claims.Repository), RepoID: claims.RepositoryID,
		State: "running", Start: start,
	}
	// A draining replica still admits, but leaves the job to the others.
	own := !s.draining.Load()
	if err := s.admit(r.Context(), id, rec, own); err != nil {
		var busy busyError
		if errors.As(err, &busy) {
			log.Warn("mirror request refused", "err", err)
			w.Header().Set("Retry-After", "30")
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		log.Error("admitting job", "err", err)
		http.Error(w, "mirror unavailable", http.StatusServiceUnavailable)
		return
	}
	log.Info("mirror request", "job", id, "tags", req.Tags)
	if own {
		s.jobsWG.Add(1)
		go s.runJob(id, rec)
	}

	deadline := time.Now().Add(s.inlineWait)
	for {
		got, ok, err := s.loadJob(r.Context(), id)
		if err == nil && ok && got.State != "running" {
			writeJob(w, got)
			return
		}
		left := time.Until(deadline)
		if left <= 0 || r.Context().Err() != nil {
			break
		}
		time.Sleep(min(left, 200*time.Millisecond))
	}
	w.Header().Set("Location", "/v1/jobs/"+id)
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintln(w, id)
}

func (s *server) handleJob(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	rec, ok, err := s.loadJob(r.Context(), r.PathValue("id"))
	if err != nil {
		// 5xx: callers keep polling.
		http.Error(w, "mirror unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok || rec.Repo != strings.ToLower(claims.Repository) || rec.RepoID != claims.RepositoryID {
		http.Error(w, "no such job", http.StatusNotFound)
		return
	}
	if rec.State == "running" {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "running")
		return
	}
	writeJob(w, rec)
}

func writeJob(w http.ResponseWriter, rec jobRecord) {
	elapsed := rec.End.Sub(rec.Start).Round(time.Millisecond)
	if rec.State == "failed" {
		http.Error(w, fmt.Sprintf("%smirror failed after %s", rec.Out, elapsed), http.StatusUnprocessableEntity)
		return
	}
	fmt.Fprintf(w, "%smirrored in %s\n", rec.Out, elapsed)
}

// counted records each response's status code.
func counted(route string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		h(sw, r)
		httpRequests.WithLabelValues(route, strconv.Itoa(sw.code)).Inc()
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
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
	if err := tok.Claims(&claims); err != nil || claims.Repository == "" {
		http.Error(w, "invalid token claims", http.StatusUnauthorized)
		return claims, false
	}
	return claims, true
}

// mirror runs the verify-and-copy script. With fillOnly, it only creates
// destination tags that don't exist; it never moves an existing one.
func (s *server) mirror(ctx context.Context, image string, pairs []string, requestID string, fillOnly bool) (string, error) {
	ctx, unlock, err := s.lockImage(ctx, image)
	if err != nil {
		return "", err
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(ctx, scriptTimeout)
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
	out := &cappedBuffer{max: maxJobOutput}
	cmd := exec.CommandContext(ctx, "bash", s.script)
	cmd.Env = append(env,
		"RULE="+string(rule),
		"SOURCE="+s.cfg.Source,
		"DESTINATION="+s.cfg.Destination,
		"IMAGE="+image,
		"TAGS="+strings.Join(pairs, " "),
		"REQUEST_ID="+requestID,
		"FILL_ONLY="+strconv.FormatBool(fillOnly),
	)
	cmd.Stdout, cmd.Stderr = out, out
	// On timeout, kill the script's whole process group, not just bash, so
	// a hung gh or regctl cannot keep the image lock.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	if err == nil {
		s.stateMu.Lock()
		for _, p := range pairs {
			tag, digest, _ := strings.Cut(p, "@")
			s.current[image+":"+tag] = digest
		}
		s.stateMu.Unlock()
	}
	return out.String(), err
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	mu        sync.Mutex
	max       int
	b         []byte
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := min(len(p), c.max-len(c.b))
	c.b = append(c.b, p[:n]...)
	c.truncated = c.truncated || n < len(p)
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return string(c.b) + "\n[output truncated]\n"
	}
	return string(c.b)
}

// pollLoop runs the poller on one replica at a time: whichever holds the
// poller lease, which it keeps until it drains or loses Redis.
func (s *server) pollLoop(ctx context.Context, every time.Duration) {
	const key = keyPrefix + "poller"
	var lctx context.Context
	var release func()
	defer func() {
		if release != nil {
			release()
		}
		pollerLeader.Set(0)
	}()
	for {
		if lctx != nil && lctx.Err() != nil {
			release()
			lctx, release = nil, nil
			pollerLeader.Set(0)
		}
		if s.draining.Load() {
			return
		}
		if lctx == nil && s.tryAcquire(ctx, key) {
			lctx, release = s.hold(ctx, key)
			pollerLeader.Set(1)
			slog.Info("running the poller")
		}
		if lctx != nil {
			s.jobsWG.Add(1)
			start := time.Now()
			s.pollOnce(lctx)
			pollCycles.Observe(time.Since(start).Seconds())
			s.jobsWG.Done()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// pollOnce mirrors every allowed source tag whose destination differs, for
// every image in the allowlist.
func (s *server) pollOnce(ctx context.Context) {
	s.stateMu.Lock()
	for k, t := range s.rejected {
		if time.Since(t) > rejectedRetryAfter {
			delete(s.rejected, k)
		}
	}
	s.stateMu.Unlock()

	names := make([]string, 0, len(s.cfg.Images))
	for name := range s.cfg.Images {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil || s.draining.Load() {
			return
		}
		if p := s.cfg.Images[name].Poll; p != nil && !*p {
			continue
		}
		log := slog.With("image", name, "path", "poll")
		src := s.cfg.Source + "/" + name
		dest := s.cfg.Destination + "/" + name
		tags, err := regctl(ctx, "tag", "ls", src)
		if err != nil {
			continue // no source package for this image (yet)
		}

		var pairs []string
		for _, tag := range strings.Fields(tags) {
			if !tagRe.MatchString(tag) || !s.cfg.tagAllowed(name, tag) {
				continue
			}
			digest, err := regctl(ctx, "image", "digest", src+":"+tag)
			if err != nil || !digestRe.MatchString(digest) {
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
			// The poller only fills tags the destination lacks. Anyone who
			// can push to the source package can re-point a tag at another
			// attested digest (an older release, say), so moving an existing
			// destination tag needs an authenticated request from a
			// publishing job.
			d, err := regctl(ctx, "image", "digest", dest+":"+tag)
			switch {
			case err == nil:
				if d != digest {
					log.Info("destination tag differs; not moving it from the poller", "tag", tag, "source", digest, "destination", d)
				}
				s.stateMu.Lock()
				s.current[key] = digest
				s.stateMu.Unlock()
				continue
			case !strings.Contains(err.Error(), "[http 404]"):
				log.Warn("destination digest", "tag", tag, "err", err)
				continue
			}
			pairs = append(pairs, tag+"@"+digest)
		}

		// Anyone who can push to the source package can add tags, so cap the
		// verifications per image per cycle; the rest wait for later cycles.
		if len(pairs) > s.limits.pollPerImage {
			log.Warn("many tags to verify; deferring some to later cycles", "pending", len(pairs), "this_cycle", s.limits.pollPerImage)
			pairs = pairs[:s.limits.pollPerImage]
		}
		// Mirror tag by tag so one unverifiable tag does not block the rest.
		for _, p := range pairs {
			start := time.Now()
			out, err := s.mirror(ctx, name, []string{p}, "poll-"+randomHex(4), true)
			if ctx.Err() != nil {
				return
			}
			observeJob(name, "poll", "", out, err, time.Since(start))
			if err != nil {
				_, digest, _ := strings.Cut(p, "@")
				s.stateMu.Lock()
				s.rejected[name+"@"+digest] = time.Now()
				s.stateMu.Unlock()
				log.Warn("poll mirror refused; retrying this digest later", "tag", p, "retry_after", rejectedRetryAfter, "output", lastLines(out, 3))
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

package main

import (
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "image_mirror_http_requests_total",
		Help: "API requests by route and status code.",
	}, []string{"route", "code"})
	// repo and image label only admitted work, so their values are bounded by
	// the allowlist: anyone with a GitHub OIDC token can call the service.
	jobsFinished = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "image_mirror_jobs_finished_total",
		Help: "Verify-and-copy runs by publishing repository, image, source (publish or poll) and result (success, failed, rate_limited).",
	}, []string{"repo", "image", "source", "result"})
	tagsCopied = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "image_mirror_tags_copied_total",
		Help: "Destination tags created or moved, by publishing repository and image.",
	}, []string{"repo", "image"})
	lastPublish = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "image_mirror_last_success_timestamp_seconds",
		Help: "When a run from this repository last succeeded for this image.",
	}, []string{"repo", "image"})
	jobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "image_mirror_job_duration_seconds",
		Help:    "Verify-and-copy run time, including waiting for the image lock.",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 900},
	}, []string{"source", "result"})
	lockWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "image_mirror_image_lock_wait_seconds",
		Help:    "Time spent waiting for an image's lock.",
		Buckets: []float64{0.1, 1, 5, 15, 60, 300},
	})
	jobsRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "image_mirror_jobs_running",
		Help: "Publish jobs running on this replica.",
	})
	jobsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "image_mirror_jobs_active",
		Help: "Unfinished publish jobs across all replicas.",
	})
	jobsResumed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "image_mirror_jobs_resumed_total",
		Help: "Jobs this replica took over from a replica that stopped or drained.",
	})
	jobsHandedOver = promauto.NewCounter(prometheus.CounterOpts{
		Name: "image_mirror_jobs_handed_over_total",
		Help: "Jobs this replica stopped before finishing, for another replica to resume.",
	})
	pollerLeader = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "image_mirror_poller_leader",
		Help: "1 when this replica runs the poller.",
	})
	pollCycles = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "image_mirror_poll_cycle_duration_seconds",
		Help:    "Time one poll cycle over all images took.",
		Buckets: []float64{10, 30, 60, 120, 300, 600, 1800},
	})
	draining = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "image_mirror_draining",
		Help: "1 while this replica is shutting down.",
	})
	redisErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "image_mirror_redis_errors_total",
		Help: "Failed Redis calls.",
	})
)

var (
	rateLimitedRe = regexp.MustCompile(`(?i)toomanyrequests|http 429|status 429`)
	// The script names the repository whose attestation it accepted, and
	// marks each tag it created or moved.
	verifiedRepoRe = regexp.MustCompile(`(?m)^verified [^ ]+: ([^ /]+/[^ /]+) `)
	copiedRe       = regexp.MustCompile(`(?m) \(copied\)$`)
)

// observeJob records a run. repo is the caller for publish requests; for the
// poller it's the repository the script verified, if it got that far.
func observeJob(image, source, repo, out string, err error, d time.Duration) {
	if repo == "" {
		repo = "unknown"
		if m := verifiedRepoRe.FindStringSubmatch(out); m != nil {
			repo = strings.ToLower(m[1])
		}
	}
	result := "success"
	switch {
	case err != nil && rateLimitedRe.MatchString(out):
		result = "rate_limited"
	case err != nil:
		result = "failed"
	}
	jobsFinished.WithLabelValues(repo, image, source, result).Inc()
	jobDuration.WithLabelValues(source, result).Observe(d.Seconds())
	if err == nil {
		tagsCopied.WithLabelValues(repo, image).Add(float64(len(copiedRe.FindAllString(out, -1))))
		lastPublish.WithLabelValues(repo, image).SetToCurrentTime()
	}
}

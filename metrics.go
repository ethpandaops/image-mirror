package main

import (
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "image_mirror_http_requests_total",
		Help: "API requests by route and status code.",
	}, []string{"route", "code"})
	jobsFinished = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "image_mirror_jobs_finished_total",
		Help: "Verify-and-copy runs by image, source (publish or poll) and result (success, failed, rate_limited).",
	}, []string{"image", "source", "result"})
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

var rateLimitedRe = regexp.MustCompile(`(?i)toomanyrequests|http 429|status 429`)

func observeJob(image, source, out string, err error, d time.Duration) {
	result := "success"
	switch {
	case err != nil && rateLimitedRe.MatchString(out):
		result = "rate_limited"
	case err != nil:
		result = "failed"
	}
	jobsFinished.WithLabelValues(image, source, result).Inc()
	jobDuration.WithLabelValues(source, result).Observe(d.Seconds())
}

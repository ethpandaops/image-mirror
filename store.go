package main

// Jobs, image locks and the poller's leadership live in Redis, so several
// replicas can share the work: any replica admits, answers and resumes any
// job, and a job whose replica stops (a rollout, a crash) is picked up by
// another one. Every copy is pinned to a digest, so running a job again is
// safe.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix = "image-mirror:"
	activeKey = keyPrefix + "active" // sorted set of unfinished job IDs

	leaseTTL = 30 * time.Second // a replica that stops renewing loses its jobs, locks and leadership after this
)

func jobKey(id string) string   { return keyPrefix + "job:" + id }
func ownerKey(id string) string { return keyPrefix + "owner:" + id }

// admit stores the job and counts it against the limits in one step, so two
// replicas can't both admit the last free slot.
var admitScript = redis.NewScript(`
local ids = redis.call('ZRANGE', KEYS[1], 0, -1)
local mine = 0
for _, id in ipairs(ids) do
  if redis.call('HGET', ARGV[6] .. id, 'repo') == ARGV[2] then mine = mine + 1 end
end
if mine >= tonumber(ARGV[3]) then return {1, mine} end
if #ids >= tonumber(ARGV[4]) then return {2, #ids} end
redis.call('ZADD', KEYS[1], ARGV[5], ARGV[1])
redis.call('HSET', KEYS[2], unpack(ARGV, 9))
if ARGV[7] ~= '' then redis.call('SET', KEYS[3], ARGV[7], 'PX', ARGV[8]) end
return {0, 0}
`)

var renewScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return 0
`)

var releaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
`)

// jobRecord is a job as stored in Redis.
type jobRecord struct {
	Image, Pairs, RequestID string
	Repo, RepoID            string
	State                   string // running, done or failed
	Out                     string
	Start, End              time.Time
}

func (r jobRecord) fields() []any {
	return []any{
		"image", r.Image, "pairs", r.Pairs, "request", r.RequestID,
		"repo", r.Repo, "repo_id", r.RepoID, "state", r.State,
		"start", strconv.FormatInt(r.Start.UnixMilli(), 10),
	}
}

func parseJob(m map[string]string) (jobRecord, bool) {
	if len(m) == 0 {
		return jobRecord{}, false
	}
	ms := func(k string) time.Time {
		v, _ := strconv.ParseInt(m[k], 10, 64)
		return time.UnixMilli(v)
	}
	return jobRecord{
		Image: m["image"], Pairs: m["pairs"], RequestID: m["request"],
		Repo: m["repo"], RepoID: m["repo_id"], State: m["state"], Out: m["out"],
		Start: ms("start"), End: ms("end"),
	}, true
}

type busyError struct{ msg string }

func (e busyError) Error() string { return e.msg }

// admit stores a new job, or refuses it with a busyError when its repository
// or the whole service already has too many jobs queued or running. With own,
// this replica takes the job; otherwise it waits for another replica's reaper.
func (s *server) admit(ctx context.Context, id string, rec jobRecord, own bool) error {
	owner := ""
	if own {
		owner = s.replica
	}
	args := []any{id, rec.Repo, s.limits.jobsPerRepo, s.limits.jobs, rec.Start.UnixMilli(), keyPrefix + "job:", owner, leaseTTL.Milliseconds()}
	args = append(args, rec.fields()...)
	res, err := admitScript.Run(ctx, s.rdb, []string{activeKey, jobKey(id), ownerKey(id)}, args...).Int64Slice()
	if err != nil {
		redisErrors.Inc()
		return err
	}
	switch res[0] {
	case 1:
		return busyError{fmt.Sprintf("%s already has %d mirror jobs queued or running", rec.Repo, res[1])}
	case 2:
		return busyError{"too many mirror jobs queued or running"}
	}
	return nil
}

func (s *server) loadJob(ctx context.Context, id string) (jobRecord, bool, error) {
	m, err := s.rdb.HGetAll(ctx, jobKey(id)).Result()
	if err != nil {
		redisErrors.Inc()
		return jobRecord{}, false, err
	}
	rec, ok := parseJob(m)
	return rec, ok, nil
}

// finishJob records the result, keeps it for jobRetention and frees the slot.
func (s *server) finishJob(id, out string, failed bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state := "done"
	if failed {
		state = "failed"
	}
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, jobKey(id), "state", state, "out", out, "end", strconv.FormatInt(time.Now().UnixMilli(), 10))
		p.Expire(ctx, jobKey(id), jobRetention)
		p.ZRem(ctx, activeKey, id)
		return nil
	})
	if err != nil {
		redisErrors.Inc()
		slog.Error("recording job result", "job", id, "err", err)
	}
}

// tryAcquire takes the lease on key if nobody holds it.
func (s *server) tryAcquire(ctx context.Context, key string) bool {
	ok, err := s.rdb.SetNX(ctx, key, s.replica, leaseTTL).Result()
	if err != nil {
		redisErrors.Inc()
		return false
	}
	return ok
}

// hold keeps renewing a lease this replica took, and returns a context that
// ends when the lease is lost (another holder, or Redis unreachable for a
// whole lease) and a function that stops renewing and releases it.
func (s *server) hold(ctx context.Context, key string) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(leaseTTL / 3)
		defer t.Stop()
		lastOK := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			n, err := renewScript.Run(ctx, s.rdb, []string{key}, s.replica, leaseTTL.Milliseconds()).Int()
			switch {
			case err == nil && n == 1:
				lastOK = time.Now()
			case err == nil:
				cancel(errLeaseLost)
				return
			default:
				redisErrors.Inc()
				if time.Since(lastOK) > leaseTTL {
					cancel(errLeaseLost)
					return
				}
			}
		}
	}()
	return ctx, func() {
		cancel(nil)
		<-stopped
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		if err := releaseScript.Run(rctx, s.rdb, []string{key}, s.replica).Err(); err != nil {
			redisErrors.Inc()
		}
	}
}

var errLeaseLost = errors.New("lease lost")

// lockImage waits for the image's lock, so one image's copies don't race.
func (s *server) lockImage(ctx context.Context, image string) (context.Context, func(), error) {
	key := keyPrefix + "lock:" + image
	start := time.Now()
	for !s.tryAcquire(ctx, key) {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	lockWait.Observe(time.Since(start).Seconds())
	lctx, release := s.hold(ctx, key)
	return lctx, release, nil
}

// runJob runs a job this replica owns; callers add it to jobsWG first. If
// the run is cut short by shutdown or a lost lease, the job stays active for
// another replica to resume.
func (s *server) runJob(id string, rec jobRecord) {
	defer s.jobsWG.Done()
	jobsRunning.Inc()
	defer jobsRunning.Dec()

	ctx, release := s.hold(s.jobsCtx, ownerKey(id))
	defer release()
	log := slog.With("job", id, "request", rec.RequestID, "image", rec.Image, "repo", rec.Repo)
	start := time.Now()
	out, err := s.mirror(ctx, rec.Image, strings.Fields(rec.Pairs), rec.RequestID, false)
	if ctx.Err() != nil {
		log.Warn("job interrupted; leaving it for another replica", "cause", context.Cause(ctx))
		jobsHandedOver.Inc()
		return
	}
	observeJob(rec.Image, "publish", out, err, time.Since(start))
	s.finishJob(id, out, err != nil)
	if err != nil {
		log.Warn("mirror failed", "err", err, "elapsed", time.Since(rec.Start).Round(time.Millisecond))
	} else {
		log.Info("mirror done", "elapsed", time.Since(rec.Start).Round(time.Millisecond))
	}
}

// reapLoop resumes active jobs nobody holds: jobs a replica admitted while
// draining, and jobs whose replica stopped without finishing them.
func (s *server) reapLoop(ctx context.Context) {
	t := time.NewTicker(s.reapEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ids, err := s.rdb.ZRange(ctx, activeKey, 0, -1).Result()
		if err != nil {
			redisErrors.Inc()
			continue
		}
		jobsActive.Set(float64(len(ids)))
		if s.draining.Load() {
			continue
		}
		for _, id := range ids {
			if n, err := s.rdb.Exists(ctx, ownerKey(id)).Result(); err != nil || n > 0 || !s.tryAcquire(ctx, ownerKey(id)) {
				continue
			}
			rec, ok, err := s.loadJob(ctx, id)
			if err != nil || !ok || rec.State != "running" {
				// The record expired or the job already finished.
				s.rdb.ZRem(ctx, activeKey, id)
				s.rdb.Del(ctx, ownerKey(id))
				continue
			}
			slog.Info("resuming job", "job", id, "request", rec.RequestID, "image", rec.Image)
			jobsResumed.Inc()
			s.jobsWG.Add(1)
			go s.runJob(id, rec)
		}
	}
}

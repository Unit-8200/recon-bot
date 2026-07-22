package scanqueue

import (
	"context"
	"sync"
	"testing"
	"time"
)

type recordingDeleter struct {
	mu  sync.Mutex
	ids []int64
}

func (d *recordingDeleter) DeleteRun(_ context.Context, runID int64) error {
	d.mu.Lock()
	d.ids = append(d.ids, runID)
	d.mu.Unlock()
	return nil
}

func (d *recordingDeleter) contains(runID int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, id := range d.ids {
		if id == runID {
			return true
		}
	}
	return false
}

func TestManagerLimitsSubdomainWorkersAndDeletesQueuedJob(t *testing.T) {
	t.Parallel()

	manager := New(&recordingDeleter{})
	release := make(chan struct{})
	started := make(chan int64, 3)
	task := func(runID int64) Task {
		return func(context.Context) int64 {
			started <- runID
			<-release
			return runID
		}
	}

	manager.Submit(context.Background(), KindSubs, "one.example", task(101))
	manager.Submit(context.Background(), KindSubs, "two.example", task(102))
	manager.Submit(context.Background(), KindSubs, "three.example", task(103))

	var queuedID int64
	waitFor(t, func() bool {
		jobs := manager.List()
		if countStatus(jobs, StatusRunning) != 2 || countStatus(jobs, StatusQueued) != 1 {
			return false
		}
		for _, job := range jobs {
			if job.Status == StatusQueued {
				queuedID = job.ID
			}
		}
		return queuedID != 0
	})
	if !manager.Delete(queuedID) {
		t.Fatal("Delete() did not find queued scan")
	}
	close(release)
	waitFor(t, func() bool { return len(manager.List()) == 0 })

	close(started)
	count := 0
	for range started {
		count++
	}
	if count != 2 {
		t.Fatalf("started %d tasks, want 2", count)
	}
}

func TestManagerCancelsRunningJobAndDeletesItsRun(t *testing.T) {
	t.Parallel()

	deleter := &recordingDeleter{}
	manager := New(deleter)
	started := make(chan struct{})
	id := manager.Submit(context.Background(), KindIPs, "1 target entry", func(ctx context.Context) int64 {
		close(started)
		<-ctx.Done()
		return 404
	})

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task did not start")
	}
	if !manager.Delete(id) {
		t.Fatal("Delete() did not find running scan")
	}
	waitFor(t, func() bool { return deleter.contains(404) })
	if manager.Delete(id) {
		t.Fatal("Delete() found an already deleted scan")
	}
}

func countStatus(jobs []Job, status Status) int {
	count := 0
	for _, job := range jobs {
		if job.Status == status {
			count++
		}
	}
	return count
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

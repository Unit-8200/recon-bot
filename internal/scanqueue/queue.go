// Package scanqueue coordinates queued and running reconnaissance scans.
package scanqueue

import (
	"context"
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/Unit-8200/recon-bot/internal/database"
)

// Kind identifies the workflow used by a queue job.
type Kind string

const (
	KindSubs Kind = "subs"
	KindIPs  Kind = "ips"
)

// Status describes whether a current job is waiting or executing.
type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
)

// Job is the public snapshot of one current queue entry.
type Job struct {
	ID          int64
	Kind        Kind
	Target      string
	Status      Status
	SubmittedAt time.Time
	StartedAt   time.Time
}

// Task performs a scan and returns the database run ID it created, if any.
type Task func(context.Context) int64

// RunDeleter removes a scan and all of its related persisted data.
type RunDeleter interface {
	DeleteRun(ctx context.Context, runID int64) error
}

type entry struct {
	job     Job
	ctx     context.Context
	cancel  context.CancelFunc
	deleted bool
}

// Manager owns the current process's scan queue.
type Manager struct {
	mu      sync.Mutex
	nextID  int64
	jobs    map[int64]*entry
	gates   map[Kind]chan struct{}
	deleter RunDeleter
}

// New creates a queue with two subdomain workers and one IP worker.
func New(deleter RunDeleter) *Manager {
	return &Manager{
		jobs: make(map[int64]*entry),
		gates: map[Kind]chan struct{}{
			KindSubs: make(chan struct{}, 2),
			KindIPs:  make(chan struct{}, 1),
		},
		deleter: deleter,
	}
}

// Submit adds a scan to the queue and returns its process-local job ID.
func (m *Manager) Submit(parent context.Context, kind Kind, target string, task Task) int64 {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)

	m.mu.Lock()
	m.nextID++
	item := &entry{
		job: Job{
			ID:          m.nextID,
			Kind:        kind,
			Target:      target,
			Status:      StatusQueued,
			SubmittedAt: time.Now().UTC(),
		},
		ctx:    ctx,
		cancel: cancel,
	}
	m.jobs[item.job.ID] = item
	m.mu.Unlock()

	go m.execute(item, task)
	return item.job.ID
}

// List returns current queued and running scans ordered by job ID.
func (m *Manager) List() []Job {
	m.mu.Lock()
	jobs := make([]Job, 0, len(m.jobs))
	for _, item := range m.jobs {
		jobs = append(jobs, item.job)
	}
	m.mu.Unlock()

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	return jobs
}

// Delete cancels a current scan. Persisted data is removed after its worker exits.
func (m *Manager) Delete(id int64) bool {
	m.mu.Lock()
	item, ok := m.jobs[id]
	if ok {
		item.deleted = true
		delete(m.jobs, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	item.cancel()
	return true
}

func (m *Manager) execute(item *entry, task Task) {
	gate, ok := m.gates[item.job.Kind]
	if !ok || task == nil {
		m.finish(item, 0)
		return
	}

	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-item.ctx.Done():
		m.finish(item, 0)
		return
	}

	m.mu.Lock()
	if item.deleted {
		m.mu.Unlock()
		m.finish(item, 0)
		return
	}
	item.job.Status = StatusRunning
	item.job.StartedAt = time.Now().UTC()
	m.mu.Unlock()

	runID := task(item.ctx)
	m.finish(item, runID)
}

func (m *Manager) finish(item *entry, runID int64) {
	m.mu.Lock()
	deleted := item.deleted
	if current, ok := m.jobs[item.job.ID]; ok && current == item {
		delete(m.jobs, item.job.ID)
	}
	m.mu.Unlock()
	item.cancel()

	if !deleted || runID == 0 || m.deleter == nil {
		return
	}
	if err := m.deleter.DeleteRun(context.Background(), runID); err != nil && !errors.Is(err, database.ErrNotFound) {
		log.Printf("delete cancelled queue scan #%d database run %d: %v", item.job.ID, runID, err)
	}
}

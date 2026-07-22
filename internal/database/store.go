// Package database owns normalized SQLite persistence for reconnaissance data.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	RunKindSubs = "subs"
	RunKindIPs  = "ips"

	RunStatusRunning   = "running"
	RunStatusCompleted = "completed"
	RunStatusFailed    = "failed"
	RunStatusPartial   = "partial"

	SubdomainStageDiscovered  = "discovered"
	SubdomainStagePassive     = "passive"
	SubdomainStageBruteforced = "bruteforced"
	SubdomainStageResolved    = "resolved"
)

// ErrNotFound indicates that a requested database record does not exist.
var ErrNotFound = errors.New("database record not found")

// Run is the metadata for one persisted scan.
type Run struct {
	ID         int64
	Kind       string
	Domain     string
	StartedAt  time.Time
	Status     string
	Error      string
	SourcePath string
}

// Subdomain records how a hostname participated in a subdomain scan.
type Subdomain struct {
	Hostname    string
	Passive     bool
	Bruteforced bool
	Resolved    bool
}

// HTTPProbe is the normalized persisted subset of an HTTPX result.
type HTTPProbe struct {
	Timestamp     time.Time
	Input         string
	URL           string
	FinalURL      string
	Scheme        string
	Host          string
	Port          string
	StatusCode    int
	Title         string
	Technologies  []string
	WebServer     string
	IPs           []string
	CDN           bool
	CDNName       string
	CDNType       string
	ContentLength int
	ContentType   string
	BodyPreview   string
	Location      string
	Error         string
	Output        string
}

// ImportData contains the typed data parsed from one legacy result directory.
type ImportData struct {
	Run        Run
	Subdomains []Subdomain
	HTTPProbes []HTTPProbe
	IPTargets  []string
	IPDomains  []string
}

// Store wraps the application's SQLite database.
type Store struct {
	db   *sql.DB
	path string
}

// Open creates or opens a database and applies its schema.
func Open(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, path: absolute}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("protect SQLite database: %w", err)
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	for _, statement := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY,
			kind TEXT NOT NULL CHECK (kind IN ('subs', 'ips')),
			domain TEXT NOT NULL DEFAULT '',
			started_at TEXT NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'partial')),
			error TEXT NOT NULL DEFAULT '',
			source_path TEXT UNIQUE
		)`,
		`CREATE INDEX IF NOT EXISTS runs_kind_domain_started_idx
			ON runs(kind, domain, started_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS subdomains (
			run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
			hostname TEXT NOT NULL,
			passive INTEGER NOT NULL DEFAULT 0,
			bruteforced INTEGER NOT NULL DEFAULT 0,
			resolved INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (run_id, hostname)
		)`,
		`CREATE INDEX IF NOT EXISTS subdomains_hostname_idx ON subdomains(hostname)`,
		`CREATE TABLE IF NOT EXISTS http_probes (
			id INTEGER PRIMARY KEY,
			run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
			timestamp TEXT NOT NULL DEFAULT '',
			input TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL DEFAULT '',
			final_url TEXT NOT NULL DEFAULT '',
			scheme TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL DEFAULT '',
			port TEXT NOT NULL DEFAULT '',
			status_code INTEGER NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT '',
			technologies TEXT NOT NULL DEFAULT '[]',
			web_server TEXT NOT NULL DEFAULT '',
			ips TEXT NOT NULL DEFAULT '[]',
			cdn INTEGER NOT NULL DEFAULT 0,
			cdn_name TEXT NOT NULL DEFAULT '',
			cdn_type TEXT NOT NULL DEFAULT '',
			content_length INTEGER NOT NULL DEFAULT 0,
			content_type TEXT NOT NULL DEFAULT '',
			body_preview TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			output TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS http_probes_run_idx ON http_probes(run_id, id)`,
		`CREATE INDEX IF NOT EXISTS http_probes_url_idx ON http_probes(url)`,
		`CREATE TABLE IF NOT EXISTS ip_targets (
			run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
			target TEXT NOT NULL,
			PRIMARY KEY (run_id, target)
		)`,
		`CREATE TABLE IF NOT EXISTS ip_domains (
			run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			PRIMARY KEY (run_id, domain)
		)`,
		`CREATE INDEX IF NOT EXISTS ip_domains_domain_idx ON ip_domains(domain)`,
		`CREATE TABLE IF NOT EXISTS stored_items (
			id INTEGER PRIMARY KEY,
			data TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize SQLite database: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the absolute path of the open SQLite database.
func (s *Store) Path() string { return s.path }

// CreateRun inserts a new live scan.
func (s *Store) CreateRun(ctx context.Context, kind, domain string, startedAt time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO runs(kind, domain, started_at, status) VALUES(?, ?, ?, ?)`,
		kind, domain, startedAt.UTC().Format(time.RFC3339Nano), RunStatusRunning,
	)
	if err != nil {
		return 0, fmt.Errorf("create database run: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read database run ID: %w", err)
	}
	return id, nil
}

// FinishRun records the terminal status of a run.
func (s *Store) FinishRun(ctx context.Context, runID int64, status string, runErr error) error {
	message := ""
	if runErr != nil {
		message = runErr.Error()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE runs SET status = ?, error = ? WHERE id = ?`, status, message, runID)
	if err != nil {
		return fmt.Errorf("finish database run: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check finished database run: %w", err)
	}
	if changed == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRun removes a scan and all related rows through foreign-key cascades.
func (s *Store) DeleteRun(ctx context.Context, runID int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE id = ?`, runID)
	if err != nil {
		return fmt.Errorf("delete database run: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deleted database run: %w", err)
	}
	if changed == 0 {
		return ErrNotFound
	}
	return nil
}

// PutSubdomains upserts hostnames and marks their participation in one stage.
func (s *Store) PutSubdomains(ctx context.Context, runID int64, values []string, stage string) error {
	column := ""
	switch stage {
	case SubdomainStageDiscovered:
	case SubdomainStagePassive:
		column = "passive"
	case SubdomainStageBruteforced:
		column = "bruteforced"
	case SubdomainStageResolved:
		column = "resolved"
	default:
		return fmt.Errorf("unknown subdomain stage %q", stage)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subdomain save: %w", err)
	}
	defer tx.Rollback()
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		query := `INSERT INTO subdomains(run_id, hostname) VALUES(?, ?) ON CONFLICT(run_id, hostname) DO NOTHING`
		if column != "" {
			query = fmt.Sprintf(`INSERT INTO subdomains(run_id, hostname, %s) VALUES(?, ?, 1)
				ON CONFLICT(run_id, hostname) DO UPDATE SET %s = 1`, column, column)
		}
		if _, err := tx.ExecContext(ctx, query, runID, value); err != nil {
			return fmt.Errorf("save subdomain %q: %w", value, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subdomains: %w", err)
	}
	return nil
}

// PutHTTPProbes replaces the normalized HTTP probe rows for a run.
func (s *Store) PutHTTPProbes(ctx context.Context, runID int64, probes []HTTPProbe) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin HTTP probe save: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM http_probes WHERE run_id = ?`, runID); err != nil {
		return fmt.Errorf("replace HTTP probes: %w", err)
	}
	for _, probe := range probes {
		technologies, err := json.Marshal(probe.Technologies)
		if err != nil {
			return fmt.Errorf("encode HTTP technologies: %w", err)
		}
		ips, err := json.Marshal(probe.IPs)
		if err != nil {
			return fmt.Errorf("encode HTTP IPs: %w", err)
		}
		timestamp := ""
		if !probe.Timestamp.IsZero() {
			timestamp = probe.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO http_probes(
			run_id, timestamp, input, url, final_url, scheme, host, port, status_code, title,
			technologies, web_server, ips, cdn, cdn_name, cdn_type, content_length,
			content_type, body_preview, location, error, output
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, timestamp, probe.Input, probe.URL, probe.FinalURL, probe.Scheme, probe.Host,
			probe.Port, probe.StatusCode, probe.Title, string(technologies), probe.WebServer,
			string(ips), probe.CDN, probe.CDNName, probe.CDNType, probe.ContentLength,
			probe.ContentType, probe.BodyPreview, probe.Location, probe.Error, probe.Output,
		)
		if err != nil {
			return fmt.Errorf("save HTTP probe %q: %w", probe.URL, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit HTTP probes: %w", err)
	}
	return nil
}

// PutIPTargets replaces the input targets for an IP scan.
func (s *Store) PutIPTargets(ctx context.Context, runID int64, targets []string) error {
	return s.replaceStrings(ctx, "ip_targets", "target", runID, targets)
}

// PutIPDomains replaces the domain names discovered by an IP scan.
func (s *Store) PutIPDomains(ctx context.Context, runID int64, domains []string) error {
	return s.replaceStrings(ctx, "ip_domains", "domain", runID, domains)
}

// Runs returns run metadata of one kind, newest first.
func (s *Store) Runs(ctx context.Context, kind string) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, domain, started_at, status, error, COALESCE(source_path, '')
		FROM runs WHERE kind = ? ORDER BY started_at DESC, id DESC`, kind)
	if err != nil {
		return nil, fmt.Errorf("query database runs: %w", err)
	}
	defer rows.Close()
	runs := make([]Run, 0)
	for rows.Next() {
		var run Run
		var timestamp string
		if err := rows.Scan(&run.ID, &run.Kind, &run.Domain, &timestamp, &run.Status, &run.Error, &run.SourcePath); err != nil {
			return nil, fmt.Errorf("scan database run: %w", err)
		}
		run.StartedAt, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse database run timestamp: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate database runs: %w", err)
	}
	return runs, nil
}

// CompletedSubRuns returns completed subdomain runs, newest first.
func (s *Store) CompletedSubRuns(ctx context.Context) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, domain, started_at, status, error, COALESCE(source_path, '')
		FROM runs WHERE kind = ? AND status = ? ORDER BY started_at DESC, id DESC`, RunKindSubs, RunStatusCompleted)
	if err != nil {
		return nil, fmt.Errorf("query completed subdomain runs: %w", err)
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		var run Run
		var timestamp string
		if err := rows.Scan(&run.ID, &run.Kind, &run.Domain, &timestamp, &run.Status, &run.Error, &run.SourcePath); err != nil {
			return nil, fmt.Errorf("scan completed subdomain run: %w", err)
		}
		run.StartedAt, err = time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse completed subdomain timestamp: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate completed subdomain runs: %w", err)
	}
	return runs, nil
}

// Subdomains returns all typed hostname rows for a run.
func (s *Store) Subdomains(ctx context.Context, runID int64) ([]Subdomain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT hostname, passive, bruteforced, resolved
		FROM subdomains WHERE run_id = ? ORDER BY hostname`, runID)
	if err != nil {
		return nil, fmt.Errorf("query subdomains: %w", err)
	}
	defer rows.Close()
	var values []Subdomain
	for rows.Next() {
		var value Subdomain
		if err := rows.Scan(&value.Hostname, &value.Passive, &value.Bruteforced, &value.Resolved); err != nil {
			return nil, fmt.Errorf("scan subdomain: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subdomains: %w", err)
	}
	return values, nil
}

// HTTPProbes returns normalized HTTP results in their persisted order.
func (s *Store) HTTPProbes(ctx context.Context, runID int64) ([]HTTPProbe, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT timestamp, input, url, final_url, scheme, host, port,
		status_code, title, technologies, web_server, ips, cdn, cdn_name, cdn_type,
		content_length, content_type, body_preview, location, error, output
		FROM http_probes WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, fmt.Errorf("query HTTP probes: %w", err)
	}
	defer rows.Close()
	var probes []HTTPProbe
	for rows.Next() {
		var probe HTTPProbe
		var timestamp, technologies, ips string
		if err := rows.Scan(&timestamp, &probe.Input, &probe.URL, &probe.FinalURL, &probe.Scheme,
			&probe.Host, &probe.Port, &probe.StatusCode, &probe.Title, &technologies,
			&probe.WebServer, &ips, &probe.CDN, &probe.CDNName, &probe.CDNType,
			&probe.ContentLength, &probe.ContentType, &probe.BodyPreview, &probe.Location,
			&probe.Error, &probe.Output); err != nil {
			return nil, fmt.Errorf("scan HTTP probe: %w", err)
		}
		if timestamp != "" {
			probe.Timestamp, err = time.Parse(time.RFC3339Nano, timestamp)
			if err != nil {
				return nil, fmt.Errorf("parse HTTP probe timestamp: %w", err)
			}
		}
		if err := json.Unmarshal([]byte(technologies), &probe.Technologies); err != nil {
			return nil, fmt.Errorf("decode HTTP technologies: %w", err)
		}
		if err := json.Unmarshal([]byte(ips), &probe.IPs); err != nil {
			return nil, fmt.Errorf("decode HTTP IPs: %w", err)
		}
		probes = append(probes, probe)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate HTTP probes: %w", err)
	}
	return probes, nil
}

// IPTargets returns the normalized inputs for an IP scan.
func (s *Store) IPTargets(ctx context.Context, runID int64) ([]string, error) {
	return s.stringRows(ctx, `SELECT target FROM ip_targets WHERE run_id = ? ORDER BY target`, runID)
}

// IPDomains returns the unique domain names found by an IP scan.
func (s *Store) IPDomains(ctx context.Context, runID int64) ([]string, error) {
	return s.stringRows(ctx, `SELECT domain FROM ip_domains WHERE run_id = ? ORDER BY domain`, runID)
}

// Domains returns distinct non-empty domains for one run kind.
func (s *Store) Domains(ctx context.Context, kind string) ([]string, error) {
	return s.stringRows(ctx, `SELECT DISTINCT domain FROM runs WHERE kind = ? AND domain <> '' ORDER BY domain`, kind)
}

// ImportRun atomically imports one parsed legacy directory. Existing source paths are skipped.
func (s *Store) ImportRun(ctx context.Context, data ImportData) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin legacy import: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO runs(kind, domain, started_at, status, error, source_path)
		VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(source_path) DO NOTHING`, data.Run.Kind, data.Run.Domain,
		data.Run.StartedAt.UTC().Format(time.RFC3339Nano), data.Run.Status, data.Run.Error, data.Run.SourcePath)
	if err != nil {
		return false, fmt.Errorf("import legacy run: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check legacy import: %w", err)
	}
	if changed == 0 {
		return false, nil
	}
	runID, err := result.LastInsertId()
	if err != nil {
		return false, fmt.Errorf("read imported run ID: %w", err)
	}
	if err := insertTypedData(ctx, tx, runID, data); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit legacy import: %w", err)
	}
	return true, nil
}

func insertTypedData(ctx context.Context, tx *sql.Tx, runID int64, data ImportData) error {
	for _, value := range data.Subdomains {
		if _, err := tx.ExecContext(ctx, `INSERT INTO subdomains(run_id, hostname, passive, bruteforced, resolved)
			VALUES(?, ?, ?, ?, ?) ON CONFLICT(run_id, hostname) DO UPDATE SET
			passive = MAX(passive, excluded.passive), bruteforced = MAX(bruteforced, excluded.bruteforced),
			resolved = MAX(resolved, excluded.resolved)`, runID, value.Hostname, value.Passive, value.Bruteforced, value.Resolved); err != nil {
			return fmt.Errorf("import subdomain %q: %w", value.Hostname, err)
		}
	}
	for _, probe := range data.HTTPProbes {
		technologies, _ := json.Marshal(probe.Technologies)
		ips, _ := json.Marshal(probe.IPs)
		timestamp := ""
		if !probe.Timestamp.IsZero() {
			timestamp = probe.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO http_probes(run_id, timestamp, input, url, final_url,
			scheme, host, port, status_code, title, technologies, web_server, ips, cdn, cdn_name,
			cdn_type, content_length, content_type, body_preview, location, error, output)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, runID, timestamp,
			probe.Input, probe.URL, probe.FinalURL, probe.Scheme, probe.Host, probe.Port, probe.StatusCode,
			probe.Title, string(technologies), probe.WebServer, string(ips), probe.CDN, probe.CDNName,
			probe.CDNType, probe.ContentLength, probe.ContentType, probe.BodyPreview, probe.Location,
			probe.Error, probe.Output); err != nil {
			return fmt.Errorf("import HTTP probe %q: %w", probe.URL, err)
		}
	}
	for _, target := range data.IPTargets {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ip_targets(run_id, target) VALUES(?, ?)`, runID, target); err != nil {
			return fmt.Errorf("import IP target %q: %w", target, err)
		}
	}
	for _, domain := range data.IPDomains {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ip_domains(run_id, domain) VALUES(?, ?)`, runID, domain); err != nil {
			return fmt.Errorf("import IP-discovered domain %q: %w", domain, err)
		}
	}
	return nil
}

func (s *Store) replaceStrings(ctx context.Context, table, column string, runID int64, values []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s save: %w", table, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE run_id = ?`, table), runID); err != nil {
		return fmt.Errorf("replace %s: %w", table, err)
	}
	query := fmt.Sprintf(`INSERT OR IGNORE INTO %s(run_id, %s) VALUES(?, ?)`, table, column)
	for _, value := range values {
		if _, err := tx.ExecContext(ctx, query, runID, value); err != nil {
			return fmt.Errorf("save %s value %q: %w", table, value, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", table, err)
	}
	return nil
}

func (s *Store) stringRows(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query database strings: %w", err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan database string: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate database strings: %w", err)
	}
	return values, nil
}

// ProbeFromOutput converts one legacy CLI-formatted HTTPX line to its queryable core fields.
func ProbeFromOutput(line string) HTTPProbe { return probeFromOutput(line) }

func probeFromOutput(line string) HTTPProbe {
	line = strings.TrimSpace(line)
	probe := HTTPProbe{Output: line}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return probe
	}
	probe.URL = fields[0]
	parsed, err := url.Parse(probe.URL)
	if err != nil {
		return probe
	}
	probe.Input = parsed.Hostname()
	probe.Scheme = parsed.Scheme
	probe.Host = parsed.Hostname()
	probe.Port = parsed.Port()
	if probe.Port == "" {
		if probe.Scheme == "https" {
			probe.Port = "443"
		}
		if probe.Scheme == "http" {
			probe.Port = "80"
		}
	}
	return probe
}

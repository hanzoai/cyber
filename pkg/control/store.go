// Copyright © 2026 Hanzo AI. MIT License.

// Package control implements Hanzo Cyber's native zip control plane:
// engagements, task reasoning graphs, captured HTTP traffic, deterministic
// verbatim-proof finding verification, Kai risk-scored action approvals,
// scope/intercept governance rules, MITRE ATT&CK / Course of Action /
// hardening posture projections, and autonomous Enso/Zen operator chat.
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// github.com/hanzoai/sqlite is the canonical Hanzo SQLite driver
	// (SQLCipher under CGO, pure-Go modernc under !cgo). Blank import
	// registers the "sqlite" database/sql driver.
	_ "github.com/hanzoai/sqlite"
)

// ErrNotFound is returned when a requested org-scoped record does not exist.
var ErrNotFound = errors.New("cyber: not found")

// Engagement is an authorized cyber assessment workspace scoped to an org.
type Engagement struct {
	ID        string
	Org       string
	Name      string
	Target    string
	Scope     []string
	Mode      string
	Status    string
	Synthetic bool
	CreatedAt int64
	UpdatedAt int64
}

// Task is an autonomous or operator-guided cyber objective inside an engagement.
type Task struct {
	ID           string
	Org          string
	EngagementID string
	Title        string
	Goal         string
	Status       string
	Phase        string
	CreatedAt    int64
	UpdatedAt    int64
}

// GraphNode is one node in a task reasoning graph (goal, intent, finding, hint, action).
type GraphNode struct {
	ID        string
	Org       string
	TaskID    string
	Kind      string
	Label     string
	Detail    string
	Status    string
	Severity  string
	ParentID  string
	CreatedAt int64
}

// Finding is a security finding with optional verbatim proof bound to captured HTTP traffic.
type Finding struct {
	ID               string
	Org              string
	EngagementID     string
	TaskID           string
	Title            string
	Severity         string
	Category         string
	CWE              string
	MitreTechnique   string
	MitreTactic      string
	Status           string
	Target           string
	EvidenceQuote    string
	TrafficID        string
	Verified         bool
	VerificationNote string
	Remediation      string
	CreatedAt        int64
	UpdatedAt        int64
}

// TrafficRecord is a captured HTTP request/response exchange used for analysis and verbatim proof.
type TrafficRecord struct {
	ID              string
	Org             string
	EngagementID    string
	TaskID          string
	Method          string
	URL             string
	Host            string
	StatusCode      int
	RequestHeaders  string
	RequestBody     string
	ResponseHeaders string
	ResponseBody    string
	LatencyMS       int
	CreatedAt       int64
}

// Approval is a Kai risk-scored action gate awaiting or recording human decision.
type Approval struct {
	ID           string
	Org          string
	EngagementID string
	TaskID       string
	Action       string
	Target       string
	Tool         string
	RiskScore    int
	RiskLevel    string
	KaiRationale string
	Status       string
	DecidedBy    string
	DecidedAt    int64
	CreatedAt    int64
}

// InterceptRule is a scope or action-governance rule applied to cyber operations.
type InterceptRule struct {
	ID           string
	Org          string
	EngagementID string
	Name         string
	MatchHost    string
	MatchPath    string
	Action       string
	Enabled      bool
	CreatedAt    int64
}

// ChatMessage is one persisted Enso/Zen operator chat turn scoped to an engagement.
type ChatMessage struct {
	ID           string
	Org          string
	EngagementID string
	TaskID       string
	Role         string
	Content      string
	Model        string
	SandboxID    string
	InputTokens  int
	OutputTokens int
	CreatedAt    int64
}

// Store persists org-isolated cyber operations state in the shared $1..$n SQL dialect.
type Store struct {
	db   *sql.DB
	path string
}

// OpenMemoryStore opens an ephemeral in-memory SQLite store for tests and schema tooling.
func OpenMemoryStore() (*Store, error) {
	return OpenStore(":memory:")
}

// OpenStore opens or creates a SQLite-backed Store at pathOrDir.
// Pass ":memory:" for an in-memory DB, a *.db/*.sqlite file path, or a directory
// (in which case cyber.db is created inside it).
func OpenStore(pathOrDir string) (*Store, error) {
	p := strings.TrimSpace(pathOrDir)
	isMemory := p == "" || p == ":memory:"
	dbPath := ":memory:"
	if !isMemory {
		lower := strings.ToLower(p)
		if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3") {
			dbPath = p
		} else {
			dbPath = filepath.Join(p, "cyber.db")
		}
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
			return nil, fmt.Errorf("cyber store mkdir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open cyber sqlite %q: %w", dbPath, err)
	}
	// Single writer pool prevents SQLITE_BUSY under concurrent writes and keeps :memory: unified.
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping cyber sqlite: %w", err)
	}

	pragmas := []string{
		"PRAGMA busy_timeout = 10000",
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = NORMAL",
	}
	if !isMemory {
		pragmas = append([]string{"PRAGMA journal_mode = WAL"}, pragmas...)
	}
	for _, stmt := range pragmas {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply pragma %q: %w", stmt, err)
		}
	}

	s := &Store{db: db, path: dbPath}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("begin cyber migrate: %w", err)
	}
	if err := s.migrate(ctx, tx); err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("commit cyber migrate: %w", err)
	}
	return s, nil
}

// Path returns the resolved SQLite path (or ":memory:").
func (s *Store) Path() string { return s.path }

// Ping verifies the database handle is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context, tx *sql.Tx) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS cyber_engagements (
  id         TEXT PRIMARY KEY,
  org        TEXT NOT NULL,
  name       TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  scope_json TEXT NOT NULL DEFAULT '[]',
  mode       TEXT NOT NULL DEFAULT 'enclave',
  status     TEXT NOT NULL DEFAULT 'active',
  synthetic  BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_eng_org ON cyber_engagements(org, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_tasks (
  id            TEXT PRIMARY KEY,
  org           TEXT NOT NULL,
  engagement_id TEXT NOT NULL,
  title         TEXT NOT NULL,
  goal          TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'active',
  phase         TEXT NOT NULL DEFAULT 'recon',
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_tasks_org_eng ON cyber_tasks(org, engagement_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_nodes (
  id         TEXT PRIMARY KEY,
  org        TEXT NOT NULL,
  task_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,
  label      TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'active',
  severity   TEXT NOT NULL DEFAULT '',
  parent_id  TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_nodes_org_task ON cyber_nodes(org, task_id, created_at ASC);

CREATE TABLE IF NOT EXISTS cyber_findings (
  id                TEXT PRIMARY KEY,
  org               TEXT NOT NULL,
  engagement_id     TEXT NOT NULL,
  task_id           TEXT NOT NULL DEFAULT '',
  title             TEXT NOT NULL,
  severity          TEXT NOT NULL DEFAULT 'medium',
  category          TEXT NOT NULL DEFAULT '',
  cwe               TEXT NOT NULL DEFAULT '',
  mitre_technique   TEXT NOT NULL DEFAULT '',
  mitre_tactic      TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT 'open',
  target            TEXT NOT NULL DEFAULT '',
  evidence_quote    TEXT NOT NULL DEFAULT '',
  traffic_id        TEXT NOT NULL DEFAULT '',
  verified          BIGINT NOT NULL DEFAULT 0,
  verification_note TEXT NOT NULL DEFAULT '',
  remediation       TEXT NOT NULL DEFAULT '',
  created_at        BIGINT NOT NULL,
  updated_at        BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_findings_org_eng ON cyber_findings(org, engagement_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_traffic (
  id               TEXT PRIMARY KEY,
  org              TEXT NOT NULL,
  engagement_id    TEXT NOT NULL,
  task_id          TEXT NOT NULL DEFAULT '',
  method           TEXT NOT NULL DEFAULT 'GET',
  url              TEXT NOT NULL,
  host             TEXT NOT NULL DEFAULT '',
  status_code      BIGINT NOT NULL DEFAULT 200,
  request_headers  TEXT NOT NULL DEFAULT '',
  request_body     TEXT NOT NULL DEFAULT '',
  response_headers TEXT NOT NULL DEFAULT '',
  response_body    TEXT NOT NULL DEFAULT '',
  latency_ms       BIGINT NOT NULL DEFAULT 0,
  created_at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_traffic_org_eng ON cyber_traffic(org, engagement_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_approvals (
  id            TEXT PRIMARY KEY,
  org           TEXT NOT NULL,
  engagement_id TEXT NOT NULL,
  task_id       TEXT NOT NULL DEFAULT '',
  action        TEXT NOT NULL,
  target        TEXT NOT NULL DEFAULT '',
  tool          TEXT NOT NULL DEFAULT '',
  risk_score    BIGINT NOT NULL DEFAULT 50,
  risk_level    TEXT NOT NULL DEFAULT 'medium',
  kai_rationale TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'pending',
  decided_by    TEXT NOT NULL DEFAULT '',
  decided_at    BIGINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_approvals_org_eng ON cyber_approvals(org, engagement_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_intercept_rules (
  id            TEXT PRIMARY KEY,
  org           TEXT NOT NULL,
  engagement_id TEXT NOT NULL DEFAULT '',
  name          TEXT NOT NULL,
  match_host    TEXT NOT NULL DEFAULT '*',
  match_path    TEXT NOT NULL DEFAULT '/*',
  action        TEXT NOT NULL DEFAULT 'require_approval',
  enabled       BIGINT NOT NULL DEFAULT 1,
  created_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_rules_org ON cyber_intercept_rules(org, created_at DESC);

CREATE TABLE IF NOT EXISTS cyber_chat_messages (
  id            TEXT PRIMARY KEY,
  org           TEXT NOT NULL,
  engagement_id TEXT NOT NULL DEFAULT '',
  task_id       TEXT NOT NULL DEFAULT '',
  role          TEXT NOT NULL,
  content       TEXT NOT NULL,
  model         TEXT NOT NULL DEFAULT '',
  sandbox_id    TEXT NOT NULL DEFAULT '',
  input_tokens  BIGINT NOT NULL DEFAULT 0,
  output_tokens BIGINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cyber_chat_org_eng ON cyber_chat_messages(org, engagement_id, created_at ASC);

CREATE TABLE IF NOT EXISTS cyber_audit_events (
  id            TEXT PRIMARY KEY,
  org           TEXT NOT NULL,
  engagement_id TEXT NOT NULL DEFAULT '',
  seq           BIGINT NOT NULL,
  event         TEXT NOT NULL,
  actor         TEXT NOT NULL DEFAULT '',
  payload_json  TEXT NOT NULL DEFAULT '{}',
  prev_hash     TEXT NOT NULL,
  hash          TEXT NOT NULL,
  created_at    BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cyber_audit_org_eng_seq ON cyber_audit_events(org, engagement_id, seq);
CREATE INDEX IF NOT EXISTS ix_cyber_audit_org_eng ON cyber_audit_events(org, engagement_id, seq ASC);
`
	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("migrate cyber schema: %w", err)
	}
	return nil
}

func checkText(vals ...string) error {
	for _, v := range vals {
		if strings.IndexByte(v, 0) >= 0 {
			return errors.New("cyber: NUL byte not permitted in text field")
		}
	}
	return nil
}

func boolToInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

func encodeScope(scope []string) string {
	if len(scope) == 0 {
		return "[]"
	}
	b, err := json.Marshal(scope)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeScope(raw string) []string {
	var out []string
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

// ---- Engagements ----

// SaveEngagement upserts an org-scoped engagement record.
func (s *Store) SaveEngagement(ctx context.Context, e Engagement) error {
	scopeJSON := encodeScope(e.Scope)
	if err := checkText(e.ID, e.Org, e.Name, e.Target, scopeJSON, e.Mode, e.Status); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_engagements (id,org,name,target,scope_json,mode,status,synthetic,created_at,updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name,
		   target = EXCLUDED.target,
		   scope_json = EXCLUDED.scope_json,
		   mode = EXCLUDED.mode,
		   status = EXCLUDED.status,
		   updated_at = EXCLUDED.updated_at`,
		e.ID, e.Org, e.Name, e.Target, scopeJSON, e.Mode, e.Status, boolToInt(e.Synthetic), e.CreatedAt, e.UpdatedAt)
	return err
}

// ListEngagements returns all engagements belonging to org ordered newest first.
func (s *Store) ListEngagements(ctx context.Context, org string) ([]Engagement, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org,name,target,scope_json,mode,status,synthetic,created_at,updated_at
		 FROM cyber_engagements WHERE org=$1 ORDER BY created_at DESC, id DESC`, org)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Engagement
	for rows.Next() {
		var e Engagement
		var scopeRaw string
		var syn int64
		if err := rows.Scan(&e.ID, &e.Org, &e.Name, &e.Target, &scopeRaw, &e.Mode, &e.Status, &syn, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.Scope = decodeScope(scopeRaw)
		e.Synthetic = syn != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEngagement returns a single org-scoped engagement or ErrNotFound.
func (s *Store) GetEngagement(ctx context.Context, org, id string) (Engagement, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,org,name,target,scope_json,mode,status,synthetic,created_at,updated_at
		 FROM cyber_engagements WHERE org=$1 AND id=$2`, org, id)
	var e Engagement
	var scopeRaw string
	var syn int64
	if err := row.Scan(&e.ID, &e.Org, &e.Name, &e.Target, &scopeRaw, &e.Mode, &e.Status, &syn, &e.CreatedAt, &e.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Engagement{}, ErrNotFound
		}
		return Engagement{}, err
	}
	e.Scope = decodeScope(scopeRaw)
	e.Synthetic = syn != 0
	return e, nil
}

// ---- Tasks & Graph Nodes ----

// SaveTask upserts a task record.
func (s *Store) SaveTask(ctx context.Context, t Task) error {
	if err := checkText(t.ID, t.Org, t.EngagementID, t.Title, t.Goal, t.Status, t.Phase); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_tasks (id,org,engagement_id,title,goal,status,phase,created_at,updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   title = EXCLUDED.title,
		   goal = EXCLUDED.goal,
		   status = EXCLUDED.status,
		   phase = EXCLUDED.phase,
		   updated_at = EXCLUDED.updated_at`,
		t.ID, t.Org, t.EngagementID, t.Title, t.Goal, t.Status, t.Phase, t.CreatedAt, t.UpdatedAt)
	return err
}

// GetTask returns an org-scoped task or ErrNotFound.
func (s *Store) GetTask(ctx context.Context, org, id string) (Task, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,org,engagement_id,title,goal,status,phase,created_at,updated_at
		 FROM cyber_tasks WHERE org=$1 AND id=$2`, org, id)
	var t Task
	if err := row.Scan(&t.ID, &t.Org, &t.EngagementID, &t.Title, &t.Goal, &t.Status, &t.Phase, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Task{}, ErrNotFound
		}
		return Task{}, err
	}
	return t, nil
}

// ListTasks returns org-scoped tasks optionally narrowed to one engagement.
func (s *Store) ListTasks(ctx context.Context, org, engagementID string) ([]Task, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,title,goal,status,phase,created_at,updated_at
			 FROM cyber_tasks WHERE org=$1 AND engagement_id=$2 ORDER BY created_at DESC, id DESC`,
			org, engagementID)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,title,goal,status,phase,created_at,updated_at
			 FROM cyber_tasks WHERE org=$1 ORDER BY created_at DESC, id DESC`,
			org)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Org, &t.EngagementID, &t.Title, &t.Goal, &t.Status, &t.Phase, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveNode upserts a reasoning graph node.
func (s *Store) SaveNode(ctx context.Context, n GraphNode) error {
	if err := checkText(n.ID, n.Org, n.TaskID, n.Kind, n.Label, n.Detail, n.Status, n.Severity, n.ParentID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_nodes (id,org,task_id,kind,label,detail,status,severity,parent_id,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   label = EXCLUDED.label,
		   detail = EXCLUDED.detail,
		   status = EXCLUDED.status,
		   severity = EXCLUDED.severity`,
		n.ID, n.Org, n.TaskID, n.Kind, n.Label, n.Detail, n.Status, n.Severity, n.ParentID, n.CreatedAt)
	return err
}

// ListNodes returns reasoning graph nodes for an org-scoped task in chronological order.
func (s *Store) ListNodes(ctx context.Context, org, taskID string) ([]GraphNode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org,task_id,kind,label,detail,status,severity,parent_id,created_at
		 FROM cyber_nodes WHERE org=$1 AND task_id=$2 ORDER BY created_at ASC, id ASC`, org, taskID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []GraphNode
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.ID, &n.Org, &n.TaskID, &n.Kind, &n.Label, &n.Detail, &n.Status, &n.Severity, &n.ParentID, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- Findings ----

const findingCols = `id,org,engagement_id,task_id,title,severity,category,cwe,mitre_technique,mitre_tactic,status,target,evidence_quote,traffic_id,verified,verification_note,remediation,created_at,updated_at`

func scanFinding(sc interface{ Scan(...any) error }) (Finding, error) {
	var f Finding
	var ver int64
	err := sc.Scan(
		&f.ID, &f.Org, &f.EngagementID, &f.TaskID, &f.Title, &f.Severity, &f.Category,
		&f.CWE, &f.MitreTechnique, &f.MitreTactic, &f.Status, &f.Target,
		&f.EvidenceQuote, &f.TrafficID, &ver, &f.VerificationNote, &f.Remediation,
		&f.CreatedAt, &f.UpdatedAt,
	)
	f.Verified = ver != 0
	return f, err
}

// SaveFinding upserts a security finding.
func (s *Store) SaveFinding(ctx context.Context, f Finding) error {
	if err := checkText(
		f.ID, f.Org, f.EngagementID, f.TaskID, f.Title, f.Severity, f.Category,
		f.CWE, f.MitreTechnique, f.MitreTactic, f.Status, f.Target,
		f.EvidenceQuote, f.TrafficID, f.VerificationNote, f.Remediation,
	); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_findings (`+findingCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		 ON CONFLICT (id) DO UPDATE SET
		   title = EXCLUDED.title,
		   severity = EXCLUDED.severity,
		   status = EXCLUDED.status,
		   evidence_quote = EXCLUDED.evidence_quote,
		   traffic_id = EXCLUDED.traffic_id,
		   verified = EXCLUDED.verified,
		   verification_note = EXCLUDED.verification_note,
		   remediation = EXCLUDED.remediation,
		   updated_at = EXCLUDED.updated_at`,
		f.ID, f.Org, f.EngagementID, f.TaskID, f.Title, f.Severity, f.Category,
		f.CWE, f.MitreTechnique, f.MitreTactic, f.Status, f.Target,
		f.EvidenceQuote, f.TrafficID, boolToInt(f.Verified), f.VerificationNote, f.Remediation,
		f.CreatedAt, f.UpdatedAt)
	return err
}

// GetFinding returns a single org-scoped finding or ErrNotFound.
func (s *Store) GetFinding(ctx context.Context, org, id string) (Finding, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+findingCols+` FROM cyber_findings WHERE org=$1 AND id=$2`, org, id)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return f, err
}

// ListFindings returns org-scoped findings optionally filtered by engagement, severity, and status.
func (s *Store) ListFindings(ctx context.Context, org, engagementID, severity, status string) ([]Finding, error) {
	var (
		args  = []any{org}
		where = []string{"org=$1"}
	)
	if engagementID != "" {
		args = append(args, engagementID)
		where = append(where, fmt.Sprintf("engagement_id=$%d", len(args)))
	}
	if severity != "" {
		args = append(args, severity)
		where = append(where, fmt.Sprintf("severity=$%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	q := `SELECT ` + findingCols + ` FROM cyber_findings WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- Traffic ----

const trafficCols = `id,org,engagement_id,task_id,method,url,host,status_code,request_headers,request_body,response_headers,response_body,latency_ms,created_at`

func scanTraffic(sc interface{ Scan(...any) error }) (TrafficRecord, error) {
	var tr TrafficRecord
	err := sc.Scan(
		&tr.ID, &tr.Org, &tr.EngagementID, &tr.TaskID, &tr.Method, &tr.URL, &tr.Host,
		&tr.StatusCode, &tr.RequestHeaders, &tr.RequestBody, &tr.ResponseHeaders, &tr.ResponseBody,
		&tr.LatencyMS, &tr.CreatedAt,
	)
	return tr, err
}

// SaveTraffic persists a captured HTTP exchange (idempotent on ID).
func (s *Store) SaveTraffic(ctx context.Context, tr TrafficRecord) error {
	if err := checkText(
		tr.ID, tr.Org, tr.EngagementID, tr.TaskID, tr.Method, tr.URL, tr.Host,
		tr.RequestHeaders, tr.RequestBody, tr.ResponseHeaders, tr.ResponseBody,
	); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_traffic (`+trafficCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		 ON CONFLICT (id) DO NOTHING`,
		tr.ID, tr.Org, tr.EngagementID, tr.TaskID, tr.Method, tr.URL, tr.Host,
		tr.StatusCode, tr.RequestHeaders, tr.RequestBody, tr.ResponseHeaders, tr.ResponseBody,
		tr.LatencyMS, tr.CreatedAt)
	return err
}

// GetTraffic returns an org-scoped captured traffic exchange or ErrNotFound.
func (s *Store) GetTraffic(ctx context.Context, org, id string) (TrafficRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+trafficCols+` FROM cyber_traffic WHERE org=$1 AND id=$2`, org, id)
	tr, err := scanTraffic(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TrafficRecord{}, ErrNotFound
	}
	return tr, err
}

// ListTraffic returns up to 200 recent captured HTTP exchanges scoped to org.
func (s *Store) ListTraffic(ctx context.Context, org, engagementID, host string) ([]TrafficRecord, error) {
	var (
		args  = []any{org}
		where = []string{"org=$1"}
	)
	if engagementID != "" {
		args = append(args, engagementID)
		where = append(where, fmt.Sprintf("engagement_id=$%d", len(args)))
	}
	if host != "" {
		args = append(args, host)
		where = append(where, fmt.Sprintf("host=$%d", len(args)))
	}
	q := `SELECT ` + trafficCols + ` FROM cyber_traffic WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at DESC, id DESC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TrafficRecord
	for rows.Next() {
		tr, err := scanTraffic(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tr)
	}
	return out, rows.Err()
}

// ---- Approvals ----

const approvalCols = `id,org,engagement_id,task_id,action,target,tool,risk_score,risk_level,kai_rationale,status,decided_by,decided_at,created_at`

func scanApproval(sc interface{ Scan(...any) error }) (Approval, error) {
	var a Approval
	err := sc.Scan(
		&a.ID, &a.Org, &a.EngagementID, &a.TaskID, &a.Action, &a.Target, &a.Tool,
		&a.RiskScore, &a.RiskLevel, &a.KaiRationale, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.CreatedAt,
	)
	return a, err
}

// SaveApproval upserts a Kai action approval gate record.
func (s *Store) SaveApproval(ctx context.Context, a Approval) error {
	if err := checkText(
		a.ID, a.Org, a.EngagementID, a.TaskID, a.Action, a.Target, a.Tool,
		a.RiskLevel, a.KaiRationale, a.Status, a.DecidedBy,
	); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_approvals (`+approvalCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		 ON CONFLICT (id) DO UPDATE SET
		   status = EXCLUDED.status,
		   decided_by = EXCLUDED.decided_by,
		   decided_at = EXCLUDED.decided_at`,
		a.ID, a.Org, a.EngagementID, a.TaskID, a.Action, a.Target, a.Tool,
		a.RiskScore, a.RiskLevel, a.KaiRationale, a.Status, a.DecidedBy, a.DecidedAt, a.CreatedAt)
	return err
}

// GetApproval returns an org-scoped approval or ErrNotFound.
func (s *Store) GetApproval(ctx context.Context, org, id string) (Approval, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+approvalCols+` FROM cyber_approvals WHERE org=$1 AND id=$2`, org, id)
	a, err := scanApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	return a, err
}

// ListApprovals returns org-scoped Kai approval requests optionally filtered by engagement and status.
func (s *Store) ListApprovals(ctx context.Context, org, engagementID, status string) ([]Approval, error) {
	var (
		args  = []any{org}
		where = []string{"org=$1"}
	)
	if engagementID != "" {
		args = append(args, engagementID)
		where = append(where, fmt.Sprintf("engagement_id=$%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	q := `SELECT ` + approvalCols + ` FROM cyber_approvals WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Intercept Rules ----

// SaveRule upserts an org-scoped scope or intercept governance rule.
func (s *Store) SaveRule(ctx context.Context, r InterceptRule) error {
	if err := checkText(r.ID, r.Org, r.EngagementID, r.Name, r.MatchHost, r.MatchPath, r.Action); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_intercept_rules (id,org,engagement_id,name,match_host,match_path,action,enabled,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name,
		   match_host = EXCLUDED.match_host,
		   match_path = EXCLUDED.match_path,
		   action = EXCLUDED.action,
		   enabled = EXCLUDED.enabled`,
		r.ID, r.Org, r.EngagementID, r.Name, r.MatchHost, r.MatchPath, r.Action, boolToInt(r.Enabled), r.CreatedAt)
	return err
}

// ListRules returns org-scoped intercept rules, including org-wide rules when engagementID is provided.
func (s *Store) ListRules(ctx context.Context, org, engagementID string) ([]InterceptRule, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,name,match_host,match_path,action,enabled,created_at
			 FROM cyber_intercept_rules WHERE org=$1 AND (engagement_id=$2 OR engagement_id='') ORDER BY created_at DESC, id DESC`,
			org, engagementID)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,name,match_host,match_path,action,enabled,created_at
			 FROM cyber_intercept_rules WHERE org=$1 ORDER BY created_at DESC, id DESC`,
			org)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []InterceptRule
	for rows.Next() {
		var r InterceptRule
		var en int64
		if err := rows.Scan(&r.ID, &r.Org, &r.EngagementID, &r.Name, &r.MatchHost, &r.MatchPath, &r.Action, &en, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRule removes an org-scoped intercept rule or returns ErrNotFound.
func (s *Store) DeleteRule(ctx context.Context, org, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM cyber_intercept_rules WHERE org=$1 AND id=$2`, org, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- Chat Messages ----

const chatCols = `id,org,engagement_id,task_id,role,content,model,sandbox_id,input_tokens,output_tokens,created_at`

func scanChatMessage(sc interface{ Scan(...any) error }) (ChatMessage, error) {
	var m ChatMessage
	err := sc.Scan(
		&m.ID, &m.Org, &m.EngagementID, &m.TaskID, &m.Role, &m.Content,
		&m.Model, &m.SandboxID, &m.InputTokens, &m.OutputTokens, &m.CreatedAt,
	)
	return m, err
}

// SaveChatMessage inserts an org-scoped operator or assistant chat message.
func (s *Store) SaveChatMessage(ctx context.Context, m ChatMessage) error {
	if err := checkText(m.ID, m.Org, m.EngagementID, m.TaskID, m.Role, m.Content, m.Model, m.SandboxID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cyber_chat_messages (`+chatCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (id) DO NOTHING`,
		m.ID, m.Org, m.EngagementID, m.TaskID, m.Role, m.Content,
		m.Model, m.SandboxID, m.InputTokens, m.OutputTokens, m.CreatedAt)
	return err
}

// ListChatMessages returns org-scoped chat messages ordered chronologically.
func (s *Store) ListChatMessages(ctx context.Context, org, engagementID, taskID string) ([]ChatMessage, error) {
	var (
		args  = []any{org}
		where = []string{"org=$1"}
	)
	if engagementID != "" {
		args = append(args, engagementID)
		where = append(where, fmt.Sprintf("engagement_id=$%d", len(args)))
	}
	if taskID != "" {
		args = append(args, taskID)
		where = append(where, fmt.Sprintf("task_id=$%d", len(args)))
	}
	q := `SELECT ` + chatCols + ` FROM cyber_chat_messages WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at ASC, id ASC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ChatMessage
	for rows.Next() {
		m, err := scanChatMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

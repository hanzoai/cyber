// Package analysis implements Hanzo Cyber's deterministic security analysis,
// API auditing, offline CVE indexing and exploit-chain planning, artifact and
// finding triage, engagement workflows, PoC verification/approval gates, and
// hardware/firmware analysis layers in pure Go.
package analysis

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ToolName    = "OpenCyber"
	ToolVersion = "1.0.0"

	DefaultHTTPResponseMaxBytes = 262144 // 256 KiB
	DefaultHTTPTimeout          = 30 * time.Second
	DefaultWorkspaceReadMax     = 1048576 // 1 MiB
)

// Coverage declares what an analysis operation inspected and whether it was
// exhausted, matching the OpenCyber result envelope contract.
type Coverage struct {
	Status     string `json:"status"`
	Examined   *int   `json:"examined"`
	Total      *int   `json:"total"`
	Exhausted  *bool  `json:"exhausted"`
	NextOffset *int   `json:"next_offset"`
}

// NewCoverage constructs a Coverage declaration.
func NewCoverage(status string, examined, total *int, exhausted *bool) Coverage {
	return Coverage{
		Status:    status,
		Examined:  examined,
		Total:     total,
		Exhausted: exhausted,
	}
}

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }
func floatPtr(v float64) *float64 {
	return &v
}

// LimitFacts describes an enforced operational ceiling and its recovery guidance.
type LimitFacts struct {
	ID           string   `json:"id"`
	Unit         string   `json:"unit"`
	Effective    float64  `json:"effective"`
	Requested    *float64 `json:"requested"`
	Default      float64  `json:"default"`
	Minimum      *float64 `json:"minimum"`
	Maximum      *float64 `json:"maximum"`
	Source       string   `json:"source"`
	Setting      string   `json:"setting,omitempty"`
	Parameter    string   `json:"parameter,omitempty"`
	Recovery     string   `json:"recovery"`
	DoesNotRaise string   `json:"does_not_raise"`
}

type limitSpec struct {
	id           string
	unit         string
	def          float64
	min          *float64
	max          *float64
	source       string
	env          string
	parameter    string
	recovery     string
	doesNotRaise string
}

var registeredLimits = map[string]limitSpec{
	"triage.max_bytes": {
		id: "triage.max_bytes", unit: "bytes", def: 16777216,
		min: floatPtr(1), max: floatPtr(268435456), source: "argument", parameter: "max_bytes",
		recovery:     "Pass a larger max_bytes value in the same call.",
		doesNotRaise: "The source file's own size on disk.",
	},
	"triage.max_records": {
		id: "triage.max_records", unit: "records", def: 10000,
		min: floatPtr(1), max: floatPtr(1000000), source: "argument", parameter: "max_records",
		recovery:     "Pass a larger max_records value or narrow the time window.",
		doesNotRaise: "The number of records present in the source.",
	},
	"triage.max_packets": {
		id: "triage.max_packets", unit: "packets", def: 10000,
		min: floatPtr(1), max: floatPtr(1000000), source: "argument", parameter: "max_packets",
		recovery:     "Pass a larger max_packets value or pre-filter the capture.",
		doesNotRaise: "The number of packets present in the capture.",
	},
	"http.response_max_bytes": {
		id: "http.response_max_bytes", unit: "bytes", def: DefaultHTTPResponseMaxBytes,
		source:       "fixed",
		recovery:     "Request a smaller resource or use server-supported Range requests to retrieve specific bytes.",
		doesNotRaise: "HTTP headers, other HTTP tools, or the envelope evidence ceiling.",
	},
	"serial.read_max_bytes": {
		id: "serial.read_max_bytes", unit: "bytes", def: 4096,
		min: floatPtr(1), max: floatPtr(65536), source: "argument", parameter: "max_bytes",
		recovery:     "Pass a larger max_bytes value or read again.",
		doesNotRaise: "The bytes already buffered on the device.",
	},
	"serial.read_timeout": {
		id: "serial.read_timeout", unit: "seconds", def: 1,
		min: floatPtr(0), max: floatPtr(30), source: "argument", parameter: "timeout",
		recovery:     "Pass a larger timeout value or poll again.",
		doesNotRaise: "The device's own response time.",
	},
	"poc.max_requests": {
		id: "poc.max_requests", unit: "requests", def: 20,
		min: floatPtr(1), max: floatPtr(20), source: "environment", env: MaxRequestsEnv,
		recovery:     "Lower the spec limit; the environment cannot raise the hard ceiling.",
		doesNotRaise: "The evidence-to-claim requirement of the engagement.",
	},
	"poc.timeout_s": {
		id: "poc.timeout_s", unit: "seconds", def: 60,
		min: floatPtr(1), max: floatPtr(60), source: "environment", env: TimeoutEnv,
		recovery:     "Lower the spec timeout; the environment cannot raise the hard ceiling.",
		doesNotRaise: "The client's own request deadline.",
	},
	"poc.max_bytes": {
		id: "poc.max_bytes", unit: "bytes", def: 1048576,
		source:       "fixed",
		recovery:     "Narrow the assertions or the request set.",
		doesNotRaise: "The target's response size.",
	},
	"tool.max_output_bytes": {
		id: "tool.max_output_bytes", unit: "bytes", def: 4194304,
		min: floatPtr(0), max: floatPtr(268435456), source: "environment", env: "OPENCYBER_TOOL_MAX_OUTPUT_BYTES",
		recovery:     "Raise OPENCYBER_TOOL_MAX_OUTPUT_BYTES, or redirect the tool's output to an engagement file.",
		doesNotRaise: "The child process's own write path; the excess is read and discarded.",
	},
}

// FactsForLimit builds LimitFacts for a registered limit ID.
func FactsForLimit(id string, effective *float64, requested *float64, parameter string) *LimitFacts {
	spec, ok := registeredLimits[id]
	if !ok {
		return nil
	}
	eff := spec.def
	if effective != nil {
		eff = *effective
	}
	param := spec.parameter
	if parameter != "" {
		param = parameter
	}
	return &LimitFacts{
		ID:           spec.id,
		Unit:         spec.unit,
		Effective:    eff,
		Requested:    requested,
		Default:      spec.def,
		Minimum:      spec.min,
		Maximum:      spec.max,
		Source:       spec.source,
		Setting:      spec.env,
		Parameter:    param,
		Recovery:     spec.recovery,
		DoesNotRaise: spec.doesNotRaise,
	}
}

// AnalysisError is a typed operational refusal mirroring OpenCyber's OcError.
type AnalysisError struct {
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	Details     map[string]any `json:"details,omitempty"`
	Limit       *LimitFacts    `json:"limit,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
}

func (e *AnalysisError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewError creates a structured AnalysisError.
func NewError(code, message string, details ...map[string]any) *AnalysisError {
	err := &AnalysisError{Code: code, Message: message}
	if len(details) > 0 && details[0] != nil {
		err.Details = details[0]
	}
	return err
}

// NewLimitError creates a limit_exceeded AnalysisError with LimitFacts.
func NewLimitError(limitID, message string, effective, requested float64, parameter string) *AnalysisError {
	eff := effective
	req := requested
	return &AnalysisError{
		Code:    "limit_exceeded",
		Message: message,
		Limit:   FactsForLimit(limitID, &eff, &req, parameter),
	}
}

// Engagement describes one isolated assessment workspace.
type Engagement struct {
	EngagementID string   `json:"engagement_id"`
	Name         string   `json:"name"`
	Targets      []string `json:"targets"`
	Workspace    string   `json:"workspace"`
	CreatedAt    string   `json:"created_at"`
}

// AuditEntry represents a hash-chained engagement audit event.
type AuditEntry struct {
	Seq       int            `json:"seq"`
	Timestamp string         `json:"timestamp"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
	Event     map[string]any `json:"event"`
}

// CommandRunner executes external CLI helpers (e.g., tshark, binwalk) when available.
type CommandRunner func(ctx context.Context, name string, args ...string) (stdout []byte, stderr []byte, exitCode int, err error)

// Workspace manages engagement directories, scope checking, audit recording,
// and injectable runtime dependencies (HTTP client, CVE index, external tools).
type Workspace struct {
	Root            string
	EnforceScope    *bool // nil = read OPENCYBER_ENFORCE_SCOPE env var
	HTTPClient      *http.Client
	HTTPMaxBytes    int
	HTTPTimeout     time.Duration
	CVEIndex        *CVEIndex
	CommandRunner   CommandRunner
	LookPath        func(file string) (string, error)
	AuditHook       func(engagementID string, event map[string]any) (AuditEntry, error)
	CustomPoCRunner CustomRunner

	auditMu sync.Mutex
}

// NewWorkspace returns a Workspace rooted at dir.
func NewWorkspace(dir string) *Workspace {
	return &Workspace{
		Root:         dir,
		HTTPMaxBytes: DefaultHTTPResponseMaxBytes,
		HTTPTimeout:  DefaultHTTPTimeout,
	}
}

var engagementIDPattern = regexp.MustCompile(`^eng_\d{8}_[0-9a-f]{32}$`)

// CreateEngagement initializes a new engagement workspace on disk.
func (w *Workspace) CreateEngagement(name string, targets []string) (*Engagement, error) {
	if strings.TrimSpace(name) == "" {
		return nil, NewError("invalid_argument", "engagement name must be non-empty")
	}
	now := UTCNow()
	id := fmt.Sprintf("eng_%s_%s", now.Format("20060102"), randomHex(16))
	cleanTargets := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		s := strings.TrimSpace(t)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			cleanTargets = append(cleanTargets, s)
		}
	}
	engRoot := filepath.Join(w.Root, "engagements", id)
	for _, sub := range []string{"", "artifacts", "evidence", "findings", "notes", "poc", "audit"} {
		if err := os.MkdirAll(filepath.Join(engRoot, sub), 0o700); err != nil {
			return nil, fmt.Errorf("create engagement directory: %w", err)
		}
	}
	eng := &Engagement{
		EngagementID: id,
		Name:         strings.TrimSpace(name),
		Targets:      cleanTargets,
		Workspace:    engRoot,
		CreatedAt:    ISOUTC(now),
	}
	raw, err := json.MarshalIndent(eng, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(filepath.Join(engRoot, "engagement.json"), append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	return eng, nil
}

// GetEngagement loads and validates an engagement record.
func (w *Workspace) GetEngagement(engagementID string) (*Engagement, error) {
	if !engagementIDPattern.MatchString(engagementID) {
		return nil, NewError("engagement_not_found", fmt.Sprintf("unknown engagement_id %q", engagementID))
	}
	nsDir := filepath.Join(w.Root, "engagements")
	if info, err := os.Lstat(nsDir); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, NewError("invalid_argument", "engagement namespace must not contain symlinks")
	}
	engRoot := filepath.Join(nsDir, engagementID)
	if info, err := os.Lstat(engRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, NewError("engagement_not_found", fmt.Sprintf("unknown engagement_id %q", engagementID))
		}
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, NewError("invalid_argument", "engagement root must be a real directory without symlinks")
	}
	raw, err := readRegularFileNoSymlink(filepath.Join(engRoot, "engagement.json"))
	if err != nil {
		return nil, NewError("engagement_not_found", fmt.Sprintf("cannot read engagement %q: %v", engagementID, err))
	}
	var eng Engagement
	if err := json.Unmarshal(raw, &eng); err != nil {
		return nil, NewError("engagement_not_found", fmt.Sprintf("malformed engagement %q: %v", engagementID, err))
	}
	eng.Workspace = engRoot
	return &eng, nil
}

// ResolveEngagementPath safely resolves an engagement-relative path while
// rejecting traversal, absolute paths, NUL bytes, and symlinks anywhere along
// the engagement subpath.
func (w *Workspace) ResolveEngagementPath(engagementID, rel string, mustExist bool) (string, error) {
	eng, err := w.GetEngagement(engagementID)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(rel, '\x00') {
		return "", NewError("invalid_argument", "path must not contain NUL bytes")
	}
	if rel == "." || rel == "" {
		return eng.Workspace, nil
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return "", NewError("invalid_argument", "path must be engagement-relative without traversal")
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == ".." {
			return "", NewError("invalid_argument", "path must be engagement-relative without traversal")
		}
	}
	cleaned := path.Clean(filepath.ToSlash(rel))
	if cleaned == "." || cleaned == "" {
		return eng.Workspace, nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", NewError("invalid_argument", "path must be engagement-relative without traversal")
	}

	// Verify no existing path component inside the engagement is a symlink.
	cur := eng.Workspace
	segList := strings.Split(cleaned, "/")
	for i, seg := range segList {
		cur = filepath.Join(cur, seg)
		info, lerr := os.Lstat(cur)
		if lerr != nil {
			if errors.Is(lerr, os.ErrNotExist) {
				if mustExist {
					return "", NewError("not_found", fmt.Sprintf("artifact does not exist: %s", rel), map[string]any{"path": rel, "engagement_id": engagementID})
				}
				// Remaining segments don't exist yet; finish joining.
				for j := i + 1; j < len(segList); j++ {
					cur = filepath.Join(cur, segList[j])
				}
				break
			}
			return "", NewError("invalid_argument", fmt.Sprintf("cannot inspect path %q: %v", rel, lerr))
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", NewError("invalid_argument", "artifact paths must not contain symlinks", map[string]any{"path": rel})
		}
	}
	return cur, nil
}

// ReadWorkspaceFile reads up to maxBytes of an engagement-relative regular file.
func (w *Workspace) ReadWorkspaceFile(engagementID, rel string, maxBytes int) (string, int, bool, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultWorkspaceReadMax
	}
	full, err := w.ResolveEngagementPath(engagementID, rel, true)
	if err != nil {
		return "", 0, false, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", 0, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", 0, false, NewError("invalid_argument", "path must be a regular file without symlinks")
	}
	f, err := os.Open(full)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", 0, false, err
	}
	truncated := n > maxBytes
	if truncated {
		n = maxBytes
	}
	return string(buf[:n]), int(info.Size()), truncated, nil
}

// WriteWorkspaceFile atomically writes an engagement-relative file, refusing
// server-managed paths (engagement.json, poc/**).
func (w *Workspace) WriteWorkspaceFile(engagementID, rel string, data []byte) (string, error) {
	if ServerManagedPath(rel) {
		return "", NewError("invalid_argument", fmt.Sprintf("cannot write server-managed path: %s", rel))
	}
	full, err := w.ResolveEngagementPath(engagementID, rel, false)
	if err != nil {
		return "", err
	}
	if err := atomicWriteFile(full, data, 0o600); err != nil {
		return "", err
	}
	return path.Clean(filepath.ToSlash(rel)), nil
}

// RecordAudit appends an event to the engagement's hash-chained audit trail.
func (w *Workspace) RecordAudit(engagementID string, event map[string]any) (AuditEntry, error) {
	if w.AuditHook != nil {
		return w.AuditHook(engagementID, event)
	}
	w.auditMu.Lock()
	defer w.auditMu.Unlock()

	eng, err := w.GetEngagement(engagementID)
	if err != nil {
		return AuditEntry{}, err
	}
	auditPath := filepath.Join(eng.Workspace, "audit", "events.jsonl")
	seq := 1
	prevHash := strings.Repeat("0", 64)
	if raw, rerr := os.ReadFile(auditPath); rerr == nil {
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		for i := len(lines) - 1; i >= 0; i-- {
			if len(bytes.TrimSpace(lines[i])) == 0 {
				continue
			}
			var last AuditEntry
			if json.Unmarshal(lines[i], &last) == nil && last.Hash != "" {
				seq = last.Seq + 1
				prevHash = last.Hash
			}
			break
		}
	}
	entry := AuditEntry{
		Seq:       seq,
		Timestamp: ISOUTC(UTCNow()),
		PrevHash:  prevHash,
		Event:     event,
	}
	material := map[string]any{
		"seq":       entry.Seq,
		"timestamp": entry.Timestamp,
		"prev_hash": entry.PrevHash,
		"event":     entry.Event,
	}
	entry.Hash = CanonicalSHA256(material)
	line, err := CanonicalJSON(entry)
	if err != nil {
		return AuditEntry{}, err
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return AuditEntry{}, err
	}
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return AuditEntry{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return AuditEntry{}, err
	}
	return entry, nil
}

// SafeRecordAudit records an audit event without failing the caller on error.
func (w *Workspace) SafeRecordAudit(engagementID string, event map[string]any) {
	_, _ = w.RecordAudit(engagementID, event)
}

func (w *Workspace) scopeEnforcementEnabled() bool {
	if w.EnforceScope != nil {
		return *w.EnforceScope
	}
	val := strings.ToLower(strings.TrimSpace(os.Getenv("OPENCYBER_ENFORCE_SCOPE")))
	return val == "1" || val == "true" || val == "yes" || val == "on"
}

func (w *Workspace) httpClient(timeout time.Duration) *http.Client {
	if w.HTTPClient != nil {
		return w.HTTPClient
	}
	if timeout <= 0 {
		timeout = w.HTTPTimeout
		if timeout <= 0 {
			timeout = DefaultHTTPTimeout
		}
	}
	return &http.Client{Timeout: timeout}
}

func (w *Workspace) lookPath(file string) (string, error) {
	if w.LookPath != nil {
		return w.LookPath(file)
	}
	return exec.LookPath(file)
}

func (w *Workspace) runCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	if w.CommandRunner != nil {
		return w.CommandRunner(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}

// ---------------------------------------------------------------------------
// Scope matching, URL canonicalization, and candidate extraction (policy.py)
// ---------------------------------------------------------------------------

// ScopeResult reports whether a host/target is allowed under an engagement's scope.
type ScopeResult struct {
	Host          string `json:"host"`
	Allowed       bool   `json:"allowed"`
	MatchedTarget string `json:"matched_target,omitempty"`
}

var (
	ambiguousAuthorityRe = regexp.MustCompile(`[\\\s\x00-\x1f\x7f@]`)
	policyURLRe          = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>]+`)
	policyIPv4Re         = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
	policyHostnameRe     = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	fileExtensions       = map[string]struct{}{
		"txt": {}, "json": {}, "yaml": {}, "yml": {}, "xml": {}, "csv": {}, "tsv": {}, "log": {},
		"md": {}, "html": {}, "htm": {}, "js": {}, "css": {}, "php": {}, "asp": {}, "aspx": {},
		"jsp": {}, "sh": {}, "py": {}, "pl": {}, "rb": {}, "go": {}, "rs": {}, "c": {}, "h": {},
		"cpp": {}, "nse": {}, "lua": {}, "conf": {}, "config": {}, "ini": {}, "db": {}, "sqlite": {},
		"sqlite3": {}, "bin": {}, "elf": {}, "exe": {}, "dll": {}, "so": {}, "img": {}, "iso": {},
		"tar": {}, "gz": {}, "tgz": {}, "bz2": {}, "xz": {}, "zip": {}, "7z": {}, "pcap": {},
		"pcapng": {}, "cap": {}, "der": {}, "pem": {}, "crt": {}, "key": {}, "pub": {}, "lst": {},
		"dict": {}, "rules": {}, "service": {}, "proto": {}, "war": {}, "jar": {}, "apk": {},
		"dex": {}, "o": {}, "a": {}, "ko": {},
	}
)

const trailingPunct = ",;:)]}'\""

// CanonicalHTTPURL validates an HTTP(S) URL so the parsed authority is unambiguous.
func CanonicalHTTPURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", NewError("invalid_argument", "URL must be a non-empty string")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", NewError("invalid_argument", fmt.Sprintf("invalid URL: %v", err))
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", NewError("invalid_argument", "URL must use http or https")
	}
	if u.Host == "" {
		return "", NewError("invalid_argument", "URL must include an authority")
	}
	// Check raw authority section before path/query/fragment for @, \, whitespace, %.
	afterScheme := rawURL[len(u.Scheme)+3:]
	authEnd := strings.IndexAny(afterScheme, "/?#")
	rawAuth := afterScheme
	if authEnd >= 0 {
		rawAuth = afterScheme[:authEnd]
	}
	if u.User != nil || ambiguousAuthorityRe.MatchString(rawAuth) || strings.Contains(rawAuth, "%") {
		return "", NewError(
			"invalid_argument",
			"URL authority is ambiguous: backslash, userinfo, whitespace, control characters and encoded separators are refused",
		)
	}
	if u.Hostname() == "" {
		return "", NewError("invalid_argument", "URL must include a host")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n >= 65536 {
			return "", NewError("invalid_argument", "URL port is out of range")
		}
	}
	return rawURL, nil
}

// CredentialBoundaryChanged returns true if following nextURL from currentURL
// changes the effective host or downgrades HTTPS to HTTP.
func CredentialBoundaryChanged(currentURL, nextURL string) (bool, error) {
	cStr, err := CanonicalHTTPURL(currentURL)
	if err != nil {
		return true, err
	}
	nStr, err := CanonicalHTTPURL(nextURL)
	if err != nil {
		return true, err
	}
	cur, _ := url.Parse(cStr)
	nxt, _ := url.Parse(nStr)
	if !strings.EqualFold(cur.Hostname(), nxt.Hostname()) {
		return true, nil
	}
	return strings.EqualFold(cur.Scheme, "https") && strings.EqualFold(nxt.Scheme, "http"), nil
}

// NormalizeHost extracts a normalized lowercase host/IP/CIDR from a URL,
// host:port, wildcard, or bare hostname string.
func NormalizeHost(value string) string {
	text := strings.TrimSpace(value)
	text = strings.Trim(text, trailingPunct)
	text = strings.Trim(text, "[]")
	text = strings.ToLower(text)
	text = strings.TrimRight(text, ".")
	if text == "" {
		return ""
	}
	if strings.Contains(text, "://") {
		u, err := url.Parse(text)
		if err != nil {
			return ""
		}
		text = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	}
	text = strings.TrimPrefix(text, "*.")
	if idx := strings.LastIndex(text, "@"); idx >= 0 {
		text = text[idx+1:]
	}
	if strings.HasPrefix(text, "[") {
		if end := strings.Index(text, "]"); end > 0 {
			text = text[1:end]
		}
	} else if strings.Count(text, ":") == 1 {
		host, port, _ := strings.Cut(text, ":")
		if isAllDigits(port) {
			text = host
		}
	}
	return strings.TrimRight(text, ".")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// TargetMatches returns true when host falls within the declared scope target
// (wildcard *, CIDR block, exact IP, or exact domain / subdomain).
func TargetMatches(host, target string) bool {
	normHost := NormalizeHost(host)
	normTarget := NormalizeHost(target)
	if normHost == "" || normTarget == "" {
		return false
	}
	if normTarget == "*" {
		return true
	}
	if strings.Contains(normTarget, "/") {
		prefix, err := netip.ParsePrefix(normTarget)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(normHost)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	}
	tIP := isIP(normTarget)
	hIP := isIP(normHost)
	if tIP || hIP {
		if !tIP || !hIP {
			return false
		}
		a1, err1 := netip.ParseAddr(normHost)
		a2, err2 := netip.ParseAddr(normTarget)
		return err1 == nil && err2 == nil && a1 == a2
	}
	return normHost == normTarget || strings.HasSuffix(normHost, "."+normTarget)
}

func validHostname(token string) bool {
	if len(token) == 0 || len(token) > 253 {
		return false
	}
	lower := strings.ToLower(token)
	if lower == "localhost" {
		return true
	}
	if !policyHostnameRe.MatchString(lower) {
		return false
	}
	labels := strings.Split(lower, ".")
	for _, lbl := range labels {
		if lbl == "" || lbl == "localhost" {
			return false
		}
	}
	if _, isExt := fileExtensions[labels[len(labels)-1]]; isExt {
		return false
	}
	for _, p := range []string{"http-", "https-", "dns-", "ssl-"} {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	return true
}

// ExtractHostCandidates extracts plausible URL, IPv4/CIDR, and hostname targets
// from arbitrary string tokens for scope enforcement.
func ExtractHostCandidates(tokens []string) []string {
	var candidates []string
	seen := make(map[string]struct{})
	add := func(val string) {
		cleaned := strings.Trim(strings.TrimSpace(val), trailingPunct)
		cleaned = strings.Trim(cleaned, "[]")
		if cleaned == "" {
			return
		}
		if _, ok := seen[cleaned]; ok {
			return
		}
		host := NormalizeHost(cleaned)
		if host == "" {
			return
		}
		if strings.Contains(cleaned, "/") && !strings.Contains(cleaned, "://") {
			if _, err := netip.ParsePrefix(cleaned); err != nil {
				return
			}
		} else if !isIP(host) && !validHostname(host) {
			return
		}
		seen[cleaned] = struct{}{}
		candidates = append(candidates, cleaned)
	}

	for _, raw := range tokens {
		for _, m := range policyURLRe.FindAllString(raw, -1) {
			add(m)
		}
		for _, loc := range policyIPv4Re.FindAllStringIndex(raw, -1) {
			if loc[0] > 0 && isWordOrDot(raw[loc[0]-1]) {
				continue
			}
			if loc[1] < len(raw) && isWordOrDot(raw[loc[1]]) {
				continue
			}
			add(raw[loc[0]:loc[1]])
		}
		stripped := strings.Trim(strings.TrimSpace(raw), trailingPunct)
		if stripped != "" && !strings.HasPrefix(stripped, "-") && !strings.Contains(stripped, "=") {
			host := NormalizeHost(stripped)
			if host != "" && validHostname(host) {
				add(stripped)
			}
		}
	}
	return candidates
}

func isWordOrDot(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.'
}

// ScopeCheck checks whether value falls inside the engagement's target scope.
func (w *Workspace) ScopeCheck(engagementID, value string) (ScopeResult, error) {
	eng, err := w.GetEngagement(engagementID)
	if err != nil {
		return ScopeResult{}, err
	}
	host := NormalizeHost(value)
	if host == "" {
		return ScopeResult{Host: "", Allowed: false}, nil
	}
	for _, target := range eng.Targets {
		if TargetMatches(host, target) {
			return ScopeResult{Host: host, Allowed: true, MatchedTarget: target}, nil
		}
	}
	return ScopeResult{Host: host, Allowed: false}, nil
}

// EnforceURLScope validates rawURL and, if scope enforcement is enabled,
// verifies it belongs to engagementID's targets.
func (w *Workspace) EnforceURLScope(engagementID, rawURL, tool string) error {
	if _, err := CanonicalHTTPURL(rawURL); err != nil {
		return err
	}
	if !w.scopeEnforcementEnabled() {
		return nil
	}
	res, err := w.ScopeCheck(engagementID, rawURL)
	if err != nil {
		return err
	}
	if !res.Allowed {
		return NewError(
			"scope_denied",
			fmt.Sprintf("%s refused: %q is outside engagement %s scope", tool, rawURL, engagementID),
			map[string]any{"url": rawURL, "host": res.Host, "tool": tool, "engagement_id": engagementID},
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Atomic file I/O and portable file locks
// ---------------------------------------------------------------------------

func atomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

func readRegularFileNoSymlink(filePath string) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("file must not be a symlink: %s", filePath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", filePath)
	}
	return os.ReadFile(filePath)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// Fallback deterministic-free hash of monotonic timestamp if rand fails
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(sum[:nBytes])
	}
	return hex.EncodeToString(b)
}

var (
	pathLockMu  sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)
	activeLocks = make(map[string]bool)
)

func getPathMutex(lockPath string) *sync.Mutex {
	pathLockMu.Lock()
	defer pathLockMu.Unlock()
	m, ok := pathLocks[lockPath]
	if !ok {
		m = &sync.Mutex{}
		pathLocks[lockPath] = m
	}
	return m
}

// acquireFileLock takes an exclusive cross-goroutine and cross-process lock on
// lockPath. When nonBlocking is true, it immediately returns errLockBusy if held.
func acquireFileLock(lockPath string, nonBlocking bool) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	if nonBlocking {
		pathLockMu.Lock()
		if activeLocks[lockPath] {
			pathLockMu.Unlock()
			return nil, errLockBusy
		}
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			pathLockMu.Unlock()
			if errors.Is(err, os.ErrExist) {
				return nil, errLockBusy
			}
			return nil, err
		}
		_ = f.Close()
		activeLocks[lockPath] = true
		pathLockMu.Unlock()
		return func() {
			pathLockMu.Lock()
			delete(activeLocks, lockPath)
			_ = os.Remove(lockPath)
			pathLockMu.Unlock()
		}, nil
	}

	m := getPathMutex(lockPath)
	m.Lock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() {
				_ = os.Remove(lockPath)
				m.Unlock()
			}, nil
		}
		if !errors.Is(err, os.ErrExist) || time.Now().After(deadline) {
			m.Unlock()
			return nil, fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var errLockBusy = errors.New("lock busy")

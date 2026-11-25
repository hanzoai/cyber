package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"strings"
	"sync"
	"time"
)

const (
	DefaultHanzoAPIURL    = "https://api.hanzo.ai"
	DefaultSandboxTTLSec  = 1800
	DefaultSandboxClass   = "cyber"
	DefaultSandboxRuntime = "microvm"
	maxSandboxBodyBytes   = 8 * 1024 * 1024
)

// SandboxConfig configures Hanzo Cloud /v1/sandbox microVM execution and
// hanzoai/gen autonomous agent dispatch.
type SandboxConfig struct {
	// BaseURL is the Hanzo Cloud API base URL (default: https://api.hanzo.ai).
	BaseURL string
	// Token is the IAM Bearer token (HANZO_API_KEY or HANZO_TOKEN).
	Token string
	// OrgID is sent as X-Org-Id for tenant isolation (HANZO_ORG_ID).
	OrgID string
	// DefaultClass, DefaultCluster, DefaultRuntime, DefaultProject, DefaultTTLSec
	// populate LeaseRequest defaults.
	DefaultClass   string
	DefaultCluster string
	DefaultRuntime string
	DefaultProject string
	DefaultTTLSec  int

	// GenBinary overrides the hanzoai/gen CLI path (auto-discovers hanzo-gen, gen, or hanzo).
	GenBinary string
	// ZAPEndpoint optionally routes hanzoai/gen agent dispatch over ZAP/HTTP transport.
	ZAPEndpoint string

	// AllowLocalFallback permits falling back to local subprocess Executor in
	// air-gapped enclaves (OPENCYBER_OFFLINE=1) or when /v1/sandbox is unconfigured/unreachable.
	AllowLocalFallback bool

	HTTPClient *http.Client
}

// SandboxConfigFromEnv reads SandboxConfig from standard Hanzo environment variables.
func SandboxConfigFromEnv() SandboxConfig {
	baseURL := strings.TrimSpace(os.Getenv("HANZO_SANDBOX_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("HANZO_API_URL"))
	}
	if baseURL == "" {
		baseURL = DefaultHanzoAPIURL
	}
	token := strings.TrimSpace(os.Getenv("HANZO_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HANZO_API_KEY"))
	}
	orgID := strings.TrimSpace(os.Getenv("HANZO_ORG_ID"))
	fallback := true
	if raw := strings.TrimSpace(os.Getenv("OPENCYBER_SANDBOX_FALLBACK")); raw != "" {
		fallback = isTruthy(raw)
	}
	return SandboxConfig{
		BaseURL:            strings.TrimRight(baseURL, "/"),
		Token:              token,
		OrgID:              orgID,
		DefaultClass:       envOrDefault("HANZO_SANDBOX_CLASS", DefaultSandboxClass),
		DefaultCluster:     strings.TrimSpace(os.Getenv("HANZO_SANDBOX_CLUSTER")),
		DefaultRuntime:     envOrDefault("HANZO_SANDBOX_RUNTIME", DefaultSandboxRuntime),
		DefaultProject:     envOrDefault("HANZO_SANDBOX_PROJECT", "cyber"),
		DefaultTTLSec:      DefaultSandboxTTLSec,
		GenBinary:          strings.TrimSpace(os.Getenv("HANZO_GEN_BIN")),
		ZAPEndpoint:        strings.TrimSpace(os.Getenv("HANZO_GEN_ZAP_URL")),
		AllowLocalFallback: fallback,
	}
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// LeaseRequest corresponds to POST /v1/sandbox/lease.
type LeaseRequest struct {
	ID      string `json:"id,omitempty"`
	Class   string `json:"class,omitempty"`
	Cluster string `json:"cluster,omitempty"`
	Disk    bool   `json:"disk,omitempty"`
	Project string `json:"project,omitempty"`
	Runtime string `json:"runtime,omitempty"`
	TTLSec  int    `json:"ttlSec,omitempty"`
}

// SandboxLease describes a leased Hanzo microVM sandbox.
type SandboxLease struct {
	ID        string `json:"id"`
	Class     string `json:"class,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
	Project   string `json:"project,omitempty"`
	Image     string `json:"image,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	Status    string `json:"status,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// SandboxRunRequest corresponds to POST /v1/sandbox/run.
type SandboxRunRequest struct {
	ID         string   `json:"id"`
	Argv       []string `json:"argv,omitempty"`
	Command    string   `json:"command,omitempty"`
	Dir        string   `json:"dir,omitempty"`
	Stdin      string   `json:"stdin,omitempty"`
	TimeoutSec int      `json:"timeoutSec,omitempty"`
	Session    string   `json:"session,omitempty"`
	Blind      []string `json:"blind,omitempty"`
	Events     bool     `json:"events,omitempty"`
}

// SandboxRunResult is the response from POST /v1/sandbox/run.
type SandboxRunResult struct {
	ID         string  `json:"id,omitempty"`
	ExitCode   int     `json:"exitCode"`
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	TimedOut   bool    `json:"timedOut,omitempty"`
	DurationMS float64 `json:"durationMs,omitempty"`
}

// SandboxFileContent is the response from POST /v1/sandbox/read.
type SandboxFileContent struct {
	ID   string `json:"id,omitempty"`
	Path string `json:"path,omitempty"`
	Data string `json:"data"`
}

// SandboxAgentRequest dispatches an agent task inside a leased sandbox via POST /v1/sandbox/{id}/agent.
type SandboxAgentRequest struct {
	Prompt  string            `json:"prompt"`
	Model   string            `json:"model,omitempty"`
	Backend string            `json:"backend,omitempty"`
	Dir     string            `json:"dir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// SandboxAgentResult is the response from POST /v1/sandbox/{id}/agent.
type SandboxAgentResult struct {
	SessionID string `json:"sessionId,omitempty"`
	Status    string `json:"status,omitempty"`
	Output    string `json:"output,omitempty"`
	ExitCode  int    `json:"exitCode,omitempty"`
}

// GenDispatchRequest describes an autonomous agentic execution request for hanzoai/gen.
type GenDispatchRequest struct {
	EngagementID     string            `json:"engagement_id"`
	Prompt           string            `json:"prompt"`
	Backend          string            `json:"backend,omitempty"` // e.g., "gen", "claude", "codex", "zen"
	Model            string            `json:"model,omitempty"`   // e.g., "enso-ultra", "zen-4"
	WorkingDirectory string            `json:"working_directory,omitempty"`
	SandboxID        string            `json:"sandbox_id,omitempty"`
	NoLink           bool              `json:"no_link,omitempty"`
	ExtraArgs        []string          `json:"extra_args,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	Timeout          time.Duration     `json:"-"`
}

// GenDispatchResult captures the outcome of a hanzoai/gen dispatch.
type GenDispatchResult struct {
	OK           bool    `json:"ok"`
	Transport    string  `json:"transport"` // "zap", "cli", "sandbox_agent"
	Binary       string  `json:"binary,omitempty"`
	Endpoint     string  `json:"endpoint,omitempty"`
	SandboxID    string  `json:"sandbox_id,omitempty"`
	SessionID    string  `json:"session_id,omitempty"`
	ExitCode     int     `json:"exit_code"`
	Stdout       string  `json:"stdout"`
	Stderr       string  `json:"stderr"`
	DurationMS   float64 `json:"duration_ms"`
	EngagementID string  `json:"engagement_id"`
}

// SandboxHealth summarizes sandbox and hanzo-gen readiness for doctor diagnostics.
type SandboxHealth struct {
	Configured      bool   `json:"configured"`
	Reachable       bool   `json:"reachable"`
	OfflineMode     bool   `json:"offline_mode"`
	BaseURL         string `json:"base_url"`
	OrgIDSet        bool   `json:"org_id_set"`
	GenAvailable    bool   `json:"gen_available"`
	GenBinary       string `json:"gen_binary,omitempty"`
	ZAPConfigured   bool   `json:"zap_configured"`
	LocalFallbackOK bool   `json:"local_fallback_ok"`
	Error           string `json:"error,omitempty"`
}

// SandboxRunner executes cyber tools inside Hanzo Cloud /v1/sandbox microVMs,
// dispatches autonomous agentic execution via hanzoai/gen, and falls back to
// local subprocess execution for air-gapped enclaves.
type SandboxRunner struct {
	Config   SandboxConfig
	Local    *Executor
	Scope    ScopeValidator
	Audit    AuditRecorder
	Resolver EngagementResolver

	mu     sync.Mutex
	leases map[string]string // engagementID -> active sandbox ID
}

// NewSandboxRunner creates a SandboxRunner backed by Hanzo Cloud /v1/sandbox
// and an optional local subprocess Executor for air-gap fallback.
func NewSandboxRunner(cfg SandboxConfig, local *Executor) *SandboxRunner {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultHanzoAPIURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.DefaultClass == "" {
		cfg.DefaultClass = DefaultSandboxClass
	}
	if cfg.DefaultRuntime == "" {
		cfg.DefaultRuntime = DefaultSandboxRuntime
	}
	if cfg.DefaultTTLSec <= 0 {
		cfg.DefaultTTLSec = DefaultSandboxTTLSec
	}
	var resolver EngagementResolver
	var scope ScopeValidator
	var audit AuditRecorder = NopAuditRecorder{}
	if local != nil {
		resolver = local.Resolver
		scope = local.Scope
		audit = local.Audit
	}
	return &SandboxRunner{
		Config:   cfg,
		Local:    local,
		Scope:    scope,
		Audit:    audit,
		Resolver: resolver,
		leases:   make(map[string]string),
	}
}

func (s *SandboxRunner) httpClient() *http.Client {
	if s.Config.HTTPClient != nil {
		return s.Config.HTTPClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// Configured reports whether Hanzo Cloud /v1/sandbox credentials and base URL are set.
func (s *SandboxRunner) Configured() bool {
	return s.Config.BaseURL != "" && s.Config.Token != ""
}

func (s *SandboxRunner) doJSON(ctx context.Context, method, path string, reqBody any, dst any) error {
	if s.Config.BaseURL == "" {
		return NewError("capability_unavailable", "Hanzo sandbox base URL is not configured")
	}
	if s.Config.Token == "" {
		return NewError("capability_unavailable", "Hanzo sandbox token (HANZO_TOKEN or HANZO_API_KEY) is not configured")
	}
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	endpoint := s.Config.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return NewError("invalid_argument", fmt.Sprintf("invalid sandbox endpoint %q: %v", endpoint, err), WithCause(err))
	}
	req.Header.Set("Authorization", "Bearer "+s.Config.Token)
	if s.Config.OrgID != "" {
		req.Header.Set("X-Org-Id", s.Config.OrgID)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hanzo-cyber/"+Version)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return NewError("cancelled", fmt.Sprintf("sandbox request cancelled: %v", ctx.Err()), WithCause(ctx.Err()))
		}
		return NewError("connection_failed", fmt.Sprintf("sandbox API request %s %s failed: %v", method, path, err), WithCause(err))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSandboxBodyBytes))
	if err != nil {
		return NewError("connection_failed", fmt.Sprintf("failed reading sandbox response: %v", err), WithCause(err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := "execution_failed"
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			code = "permission_denied"
		} else if resp.StatusCode == http.StatusNotFound {
			code = "not_found"
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			code = "connection_failed"
		}
		return NewError(code, fmt.Sprintf("sandbox API %s %s returned HTTP %d: %s",
			method, path, resp.StatusCode, strings.TrimSpace(string(raw))),
			WithDetails(map[string]any{"status": resp.StatusCode, "path": path}))
	}
	if dst != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			return NewError("execution_failed", fmt.Sprintf("failed decoding sandbox response: %v", err), WithCause(err))
		}
	}
	return nil
}

// Lease allocates or resumes a Hanzo Cloud microVM sandbox (POST /v1/sandbox/lease).
func (s *SandboxRunner) Lease(ctx context.Context, req LeaseRequest) (*SandboxLease, error) {
	if req.Class == "" {
		req.Class = s.Config.DefaultClass
	}
	if req.Cluster == "" {
		req.Cluster = s.Config.DefaultCluster
	}
	if req.Runtime == "" {
		req.Runtime = s.Config.DefaultRuntime
	}
	if req.Project == "" {
		req.Project = s.Config.DefaultProject
	}
	if req.TTLSec <= 0 {
		req.TTLSec = s.Config.DefaultTTLSec
	}
	var out SandboxLease
	if err := s.doJSON(ctx, http.MethodPost, "/v1/sandbox/lease", req, &out); err != nil {
		return nil, err
	}
	if out.ID == "" {
		return nil, NewError("execution_failed", "sandbox lease response did not include an id")
	}
	return &out, nil
}

// Get fetches one sandbox by ID (GET /v1/sandbox/{id}).
func (s *SandboxRunner) Get(ctx context.Context, id string) (*SandboxLease, error) {
	if strings.TrimSpace(id) == "" {
		return nil, NewError("invalid_argument", "sandbox id must not be empty")
	}
	var out SandboxLease
	if err := s.doJSON(ctx, http.MethodGet, "/v1/sandbox/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns active sandboxes held by the caller's org (GET /v1/sandbox).
func (s *SandboxRunner) List(ctx context.Context, project, status string) ([]SandboxLease, error) {
	q := url.Values{}
	if project != "" {
		q.Set("project", project)
	}
	if status != "" {
		q.Set("status", status)
	}
	path := "/v1/sandbox"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var raw json.RawMessage
	if err := s.doJSON(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	var list []SandboxLease
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var wrapped struct {
		Sandboxes []SandboxLease `json:"sandboxes"`
		Items     []SandboxLease `json:"items"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, NewError("execution_failed", "unexpected sandbox list format", WithCause(err))
	}
	if len(wrapped.Sandboxes) > 0 {
		return wrapped.Sandboxes, nil
	}
	return wrapped.Items, nil
}

// Run executes a command inside a leased sandbox (POST /v1/sandbox/run).
func (s *SandboxRunner) Run(ctx context.Context, req SandboxRunRequest) (*SandboxRunResult, error) {
	if strings.TrimSpace(req.ID) == "" {
		return nil, NewError("invalid_argument", "sandbox id must not be empty")
	}
	if len(req.Argv) == 0 && strings.TrimSpace(req.Command) == "" {
		return nil, NewError("invalid_argument", "sandbox run requires argv or command")
	}
	var out SandboxRunResult
	if err := s.doJSON(ctx, http.MethodPost, "/v1/sandbox/run", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Read retrieves a file from a leased sandbox (POST /v1/sandbox/read).
func (s *SandboxRunner) Read(ctx context.Context, id, filePath string) (*SandboxFileContent, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(filePath) == "" {
		return nil, NewError("invalid_argument", "sandbox id and path are required")
	}
	var out SandboxFileContent
	err := s.doJSON(ctx, http.MethodPost, "/v1/sandbox/read", map[string]string{
		"id":   id,
		"path": filePath,
	}, &out)
	if err != nil {
		return nil, err
	}
	if out.ID == "" {
		out.ID = id
	}
	if out.Path == "" {
		out.Path = filePath
	}
	return &out, nil
}

// Write writes file data into a leased sandbox (POST /v1/sandbox/write).
func (s *SandboxRunner) Write(ctx context.Context, id, filePath, data string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(filePath) == "" {
		return NewError("invalid_argument", "sandbox id and path are required")
	}
	return s.doJSON(ctx, http.MethodPost, "/v1/sandbox/write", map[string]string{
		"id":   id,
		"path": filePath,
		"data": data,
	}, nil)
}

// Stop halts the currently running command in a sandbox while keeping the lease (POST /v1/sandbox/stop).
func (s *SandboxRunner) Stop(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return NewError("invalid_argument", "sandbox id must not be empty")
	}
	return s.doJSON(ctx, http.MethodPost, "/v1/sandbox/stop", map[string]string{"id": id}, nil)
}

// End releases a leased sandbox (POST /v1/sandbox/end).
func (s *SandboxRunner) End(ctx context.Context, id string, purge bool) error {
	if strings.TrimSpace(id) == "" {
		return NewError("invalid_argument", "sandbox id must not be empty")
	}
	err := s.doJSON(ctx, http.MethodPost, "/v1/sandbox/end", map[string]any{
		"id":    id,
		"purge": purge,
	}, nil)
	if err == nil {
		s.mu.Lock()
		for eid, sid := range s.leases {
			if sid == id {
				delete(s.leases, eid)
			}
		}
		s.mu.Unlock()
	}
	return err
}

// Agent dispatches an autonomous agent run inside a leased sandbox (POST /v1/sandbox/{id}/agent).
func (s *SandboxRunner) Agent(ctx context.Context, id string, req SandboxAgentRequest) (*SandboxAgentResult, error) {
	if strings.TrimSpace(id) == "" {
		return nil, NewError("invalid_argument", "sandbox id must not be empty")
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return nil, NewError("invalid_argument", "agent prompt must not be empty")
	}
	var out SandboxAgentResult
	if err := s.doJSON(ctx, http.MethodPost, "/v1/sandbox/"+url.PathEscape(id)+"/agent", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Execute runs an ExecRequest inside a Hanzo Cloud /v1/sandbox microVM, with automatic
// local subprocess fallback for air-gapped enclaves or unreachable sandbox endpoints.
func (s *SandboxRunner) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	if err := ValidateArguments(req.Arguments); err != nil {
		return nil, err
	}
	// Check air-gap or unconfigured sandbox before attempting cloud network call.
	if OfflineEnabled() || !s.Configured() {
		reason := "hanzo sandbox not configured"
		if OfflineEnabled() {
			reason = "air-gapped mode (OPENCYBER_OFFLINE=1)"
		}
		return s.fallbackLocal(ctx, req, reason)
	}

	// Enforce scope & offline policy before invoking cloud sandbox.
	sv := s.scopeValidator()
	var scopeDec ScopeDecision
	var err error
	if req.Preflight != nil {
		scopeDec = ScopeDecision{
			Enforced:   true,
			Allowed:    true,
			Candidates: append([]string(nil), req.Preflight.Candidates...),
			Source:     req.Preflight.Source,
		}
	} else {
		scopeDec, err = sv.CheckCommand(req.EngagementID, req.Executable, req.Arguments)
		if err != nil {
			return nil, err
		}
	}
	if off := sv.CheckOffline(req.Executable); off.Blocked {
		return nil, NewError("offline_blocked", off.Reason, WithDetails(map[string]any{"executable": req.Executable}))
	}

	started := time.Now()
	sandboxID, err := s.ensureLease(ctx, req.EngagementID)
	if err != nil {
		if s.shouldFallback(err) {
			return s.fallbackLocal(ctx, req, err.Error())
		}
		return nil, err
	}

	timeoutSec := 0
	if req.TimeoutOverride != nil {
		timeoutSec = int(req.TimeoutOverride.Seconds())
	} else if t, terr := LimitToolTimeout.Effective(); terr == nil && t > 0 {
		timeoutSec = int(t)
	}

	argv := append([]string{req.Executable}, req.Arguments...)
	runRes, err := s.Run(ctx, SandboxRunRequest{
		ID:         sandboxID,
		Argv:       argv,
		Dir:        req.WorkingDirectory,
		Stdin:      req.Stdin,
		TimeoutSec: timeoutSec,
	})
	if err != nil {
		if s.shouldFallback(err) {
			return s.fallbackLocal(ctx, req, err.Error())
		}
		return nil, err
	}

	code := runRes.ExitCode
	res := &ExecResult{
		OK:            !runRes.TimedOut,
		Success:       code == 0 && !runRes.TimedOut,
		EngagementID:  req.EngagementID,
		Executable:    req.Executable,
		Backend:       "hanzo_sandbox",
		SandboxID:     sandboxID,
		Available:     true,
		Argv:          argv,
		Cwd:           req.WorkingDirectory,
		ReturnCode:    &code,
		Stdout:        runRes.Stdout,
		Stderr:        runRes.Stderr,
		StdoutBytes:   int64(len(runRes.Stdout)),
		StderrBytes:   int64(len(runRes.Stderr)),
		TimedOut:      runRes.TimedOut,
		DurationMS:    float64(time.Since(started).Microseconds()) / 1000.0,
		ScopeEnforced: scopeDec.Enforced,
	}
	if runRes.TimedOut {
		res.Error = NewError("timed_out", fmt.Sprintf("sandbox command %s timed out", req.Executable))
		res.ErrorMessage = res.Error.Message
	}
	s.recordAudit(req.EngagementID, map[string]any{
		"event":        "sandbox.exec",
		"sandbox_id":   sandboxID,
		"executable":   req.Executable,
		"arguments":    req.Arguments,
		"returncode":   code,
		"timed_out":    runRes.TimedOut,
		"duration_ms":  res.DurationMS,
		"stdout_bytes": res.StdoutBytes,
		"stderr_bytes": res.StderrBytes,
	})
	return res, nil
}

func (s *SandboxRunner) ensureLease(ctx context.Context, engagementID string) (string, error) {
	s.mu.Lock()
	existing := s.leases[engagementID]
	s.mu.Unlock()
	if existing != "" {
		return existing, nil
	}
	lease, err := s.Lease(ctx, LeaseRequest{
		Project: s.Config.DefaultProject,
		Class:   s.Config.DefaultClass,
		Runtime: s.Config.DefaultRuntime,
	})
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.leases[engagementID] = lease.ID
	s.mu.Unlock()
	s.recordAudit(engagementID, map[string]any{
		"event":      "sandbox.lease",
		"sandbox_id": lease.ID,
		"class":      lease.Class,
		"runtime":    lease.Runtime,
	})
	return lease.ID, nil
}

func (s *SandboxRunner) shouldFallback(err error) bool {
	if !s.Config.AllowLocalFallback || s.Local == nil {
		return false
	}
	code := ErrorCode(err)
	return code == "connection_failed" || code == "capability_unavailable"
}

func (s *SandboxRunner) fallbackLocal(ctx context.Context, req ExecRequest, reason string) (*ExecResult, error) {
	if !s.Config.AllowLocalFallback || s.Local == nil {
		return nil, NewError("capability_unavailable",
			fmt.Sprintf("sandbox execution unavailable (%s) and local fallback is disabled", reason),
			WithDetails(map[string]any{"reason": reason}))
	}
	res, err := s.Local.ExecuteTool(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Backend = "local_fallback"
	if res.Metadata == nil {
		res.Metadata = map[string]any{}
	}
	res.Metadata["fallback_reason"] = reason
	return res, nil
}

// ResolveGenBinary locates the hanzoai/gen CLI (`hanzo-gen`, `gen`, or `hanzo`).
func (s *SandboxRunner) ResolveGenBinary() (binaryPath string, isHanzoDev bool) {
	if s.Config.GenBinary != "" {
		if p, err := osexec.LookPath(s.Config.GenBinary); err == nil {
			return p, strings.HasSuffix(p, "hanzo")
		}
	}
	for _, cand := range []string{"hanzo-gen", "gen"} {
		if p, err := osexec.LookPath(cand); err == nil {
			return p, false
		}
	}
	if p, err := osexec.LookPath("hanzo"); err == nil {
		return p, true
	}
	return "", false
}

// DispatchGen dispatches an autonomous agentic task via hanzoai/gen (ZAP endpoint,
// local hanzo-gen/gen CLI, or remote /v1/sandbox/{id}/agent).
func (s *SandboxRunner) DispatchGen(ctx context.Context, req GenDispatchRequest) (*GenDispatchResult, error) {
	if strings.TrimSpace(req.Prompt) == "" {
		return nil, NewError("invalid_argument", "gen dispatch prompt must not be empty")
	}
	started := time.Now()

	// 1. Prefer ZAP endpoint when configured and not air-gapped (or localhost ZAP).
	if s.Config.ZAPEndpoint != "" {
		zapPayload := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "gen.dispatch",
			"params": map[string]any{
				"engagement_id": req.EngagementID,
				"prompt":        req.Prompt,
				"backend":       req.Backend,
				"model":         req.Model,
				"sandbox_id":    req.SandboxID,
				"no_link":       req.NoLink || OfflineEnabled(),
			},
		}
		b, err := json.Marshal(zapPayload)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.ZAPEndpoint, bytes.NewReader(b))
		if err != nil {
			return nil, NewError("invalid_argument", fmt.Sprintf("invalid ZAP endpoint: %v", err), WithCause(err))
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if s.Config.Token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+s.Config.Token)
		}
		if s.Config.OrgID != "" {
			httpReq.Header.Set("X-Org-Id", s.Config.OrgID)
		}
		resp, err := s.httpClient().Do(httpReq)
		if err != nil {
			return nil, NewError("connection_failed", fmt.Sprintf("ZAP dispatch failed: %v", err), WithCause(err))
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSandboxBodyBytes))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, NewError("execution_failed", fmt.Sprintf("ZAP endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw))))
		}
		var rpcResp struct {
			Result struct {
				SessionID string `json:"session_id"`
				Output    string `json:"output"`
				ExitCode  int    `json:"exit_code"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &rpcResp); err != nil {
			return nil, NewError("execution_failed", fmt.Sprintf("invalid ZAP response: %v", err), WithCause(err))
		}
		if rpcResp.Error != nil {
			return nil, NewError("execution_failed", rpcResp.Error.Message)
		}
		res := &GenDispatchResult{
			OK:           rpcResp.Result.ExitCode == 0,
			Transport:    "zap",
			Endpoint:     s.Config.ZAPEndpoint,
			SessionID:    rpcResp.Result.SessionID,
			ExitCode:     rpcResp.Result.ExitCode,
			Stdout:       rpcResp.Result.Output,
			DurationMS:   float64(time.Since(started).Microseconds()) / 1000.0,
			EngagementID: req.EngagementID,
		}
		s.recordAudit(req.EngagementID, map[string]any{
			"event":       "gen.dispatch",
			"transport":   "zap",
			"session_id":  res.SessionID,
			"exit_code":   res.ExitCode,
			"duration_ms": res.DurationMS,
		})
		return res, nil
	}

	// 2. Local hanzo-gen / gen / hanzo dev CLI dispatch.
	if bin, isHanzoDev := s.ResolveGenBinary(); bin != "" {
		var args []string
		if isHanzoDev {
			args = append(args, "dev")
		}
		if req.Backend != "" {
			args = append(args, "--backend", req.Backend)
		}
		if req.Model != "" {
			args = append(args, "--model", req.Model)
		}
		if req.NoLink || OfflineEnabled() {
			args = append(args, "--no-link")
		}
		args = append(args, req.ExtraArgs...)
		args = append(args, req.Prompt)

		if err := ValidateArguments(args); err != nil {
			return nil, err
		}
		env, err := BuildEnvironment(req.Environment)
		if err != nil {
			return nil, err
		}

		cwd := req.WorkingDirectory
		if cwd == "" && s.Resolver != nil && req.EngagementID != "" {
			if resolved, rerr := s.Resolver.ResolvePath(req.EngagementID, ".", true); rerr == nil {
				cwd = resolved
			}
		}

		runCtx := ctx
		var cancel context.CancelFunc
		if req.Timeout > 0 {
			runCtx, cancel = context.WithTimeout(ctx, req.Timeout)
			defer cancel()
		}
		cmd := osexec.CommandContext(runCtx, bin, args...)
		if cwd != "" {
			cmd.Dir = cwd
		}
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*osexec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else if runCtx.Err() != nil {
				return nil, NewError("timed_out", fmt.Sprintf("hanzo-gen timed out: %v", runCtx.Err()), WithCause(runCtx.Err()))
			} else {
				return nil, NewError("execution_failed", fmt.Sprintf("hanzo-gen execution failed: %v", runErr), WithCause(runErr))
			}
		}
		res := &GenDispatchResult{
			OK:           exitCode == 0,
			Transport:    "cli",
			Binary:       bin,
			ExitCode:     exitCode,
			Stdout:       stdout.String(),
			Stderr:       stderr.String(),
			DurationMS:   float64(time.Since(started).Microseconds()) / 1000.0,
			EngagementID: req.EngagementID,
		}
		s.recordAudit(req.EngagementID, map[string]any{
			"event":       "gen.dispatch",
			"transport":   "cli",
			"binary":      bin,
			"exit_code":   exitCode,
			"duration_ms": res.DurationMS,
		})
		return res, nil
	}

	// 3. Fallback to Hanzo Cloud /v1/sandbox/{id}/agent when online & configured.
	if !OfflineEnabled() && s.Configured() {
		sid := req.SandboxID
		if sid == "" {
			var err error
			sid, err = s.ensureLease(ctx, req.EngagementID)
			if err != nil {
				return nil, err
			}
		}
		agentRes, err := s.Agent(ctx, sid, SandboxAgentRequest{
			Prompt:  req.Prompt,
			Model:   req.Model,
			Backend: req.Backend,
			Dir:     req.WorkingDirectory,
			Env:     req.Environment,
		})
		if err != nil {
			return nil, err
		}
		res := &GenDispatchResult{
			OK:           agentRes.ExitCode == 0,
			Transport:    "sandbox_agent",
			SandboxID:    sid,
			SessionID:    agentRes.SessionID,
			ExitCode:     agentRes.ExitCode,
			Stdout:       agentRes.Output,
			DurationMS:   float64(time.Since(started).Microseconds()) / 1000.0,
			EngagementID: req.EngagementID,
		}
		s.recordAudit(req.EngagementID, map[string]any{
			"event":       "gen.dispatch",
			"transport":   "sandbox_agent",
			"sandbox_id":  sid,
			"session_id":  agentRes.SessionID,
			"duration_ms": res.DurationMS,
		})
		return res, nil
	}

	return nil, NewError("capability_unavailable",
		"hanzo-gen CLI is not installed, ZAP endpoint is unset, and Hanzo Cloud /v1/sandbox is unavailable",
		WithRemediation("Install hanzo-gen (`curl -fsSL hanzo.sh | sh`) or configure HANZO_TOKEN + HANZO_ORG_ID."))
}

// ProbeHealth checks Hanzo Cloud /v1/sandbox and hanzo-gen readiness without leaking secrets.
func (s *SandboxRunner) ProbeHealth(ctx context.Context) SandboxHealth {
	genBin, _ := s.ResolveGenBinary()
	h := SandboxHealth{
		Configured:      s.Configured(),
		OfflineMode:     OfflineEnabled(),
		BaseURL:         s.Config.BaseURL,
		OrgIDSet:        s.Config.OrgID != "",
		GenAvailable:    genBin != "",
		GenBinary:       genBin,
		ZAPConfigured:   s.Config.ZAPEndpoint != "",
		LocalFallbackOK: s.Config.AllowLocalFallback && s.Local != nil,
	}
	if h.OfflineMode || !h.Configured {
		return h
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.doJSON(probeCtx, http.MethodGet, "/v1/sandbox/quota", nil, nil); err != nil {
		h.Reachable = false
		h.Error = err.Error()
		return h
	}
	h.Reachable = true
	return h
}

func (s *SandboxRunner) scopeValidator() ScopeValidator {
	if s.Scope != nil {
		return s.Scope
	}
	return &DefaultScopeValidator{Resolver: s.Resolver}
}

func (s *SandboxRunner) recordAudit(engagementID string, event map[string]any) {
	if s.Audit == nil || engagementID == "" {
		return
	}
	_, _ = s.Audit.Record(engagementID, event)
}

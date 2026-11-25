// Package exec implements the execution, native security tools, HTTP client,
// HTTP workbench, content-addressed result store, evidence bundling, offline
// asset verification, runtime diagnostics, and CDP browser automation bridge
// layers for Hanzo Cyber using pure Go standard library primitives.
package exec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the default package version reported in diagnostics and user-agent headers.
const Version = "1.0.0"

// ErrorCategory classifies machine-actionable refusals into coarse families.
type ErrorCategory string

const (
	CategoryInvalidInput       ErrorCategory = "invalid_input"
	CategoryDenied             ErrorCategory = "denied"
	CategoryUnavailable        ErrorCategory = "unavailable"
	CategoryNotFound           ErrorCategory = "not_found"
	CategoryConflict           ErrorCategory = "conflict"
	CategoryIntegrityMismatch  ErrorCategory = "integrity_mismatch"
	CategoryTruncated          ErrorCategory = "truncated"
	CategoryTimeout            ErrorCategory = "timeout"
	CategoryCancelled          ErrorCategory = "cancelled"
	CategoryResourceConstraint ErrorCategory = "resource_constraint"
	CategoryExecutionFailure   ErrorCategory = "execution_failure"
	CategoryInternal           ErrorCategory = "internal"
)

// ErrorRemediation describes the concrete recovery action for a refusal.
type ErrorRemediation struct {
	Action string `json:"action"`
}

// Error is a machine-actionable refusal matching the OpenCyber error contract.
type Error struct {
	Code        string           `json:"code"`
	Category    ErrorCategory    `json:"category"`
	Message     string           `json:"message"`
	Retryable   bool             `json:"retryable"`
	Remediation ErrorRemediation `json:"remediation"`
	Limit       *LimitFacts      `json:"limit"`
	Details     map[string]any   `json:"details"`
	cause       error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type errorSpec struct {
	category    ErrorCategory
	retryable   bool
	remediation string
}

var errorRegistry = map[string]errorSpec{
	"invalid_argument":        {CategoryInvalidInput, false, "Correct the reported argument and repeat the call unchanged otherwise."},
	"missing_parameter":       {CategoryInvalidInput, false, "Supply the named parameter; inspect the tool schema for its type."},
	"unknown_tool":            {CategoryInvalidInput, false, "Call oc_catalog with an exact name, substring query, or category first."},
	"engagement_required":     {CategoryInvalidInput, false, "Create or select an engagement and pass its engagement_id."},
	"engagement_not_found":    {CategoryNotFound, false, "Call oc_engagement_list and use a server-generated engagement_id."},
	"scope_denied":            {CategoryDenied, false, "Add the target to the engagement scope, or call oc_scope_check before retrying."},
	"permission_denied":       {CategoryDenied, false, "Check the owning path and file mode inside the engagement workspace."},
	"capability_unavailable":  {CategoryUnavailable, false, "Inspect oc_doctor for the failing capability and use an operator-managed image that provides it."},
	"integration_unavailable": {CategoryUnavailable, false, "Install the integration and its dependencies in the operator-managed image, then restart."},
	"offline_blocked":         {CategoryUnavailable, false, "Unset OPENCYBER_OFFLINE, or use an offline data source such as the local CVE index."},
	"not_found":               {CategoryNotFound, false, "List the owning collection first and use an identifier it returns."},
	"already_exists":          {CategoryConflict, false, "Choose another name or path, or inspect the existing object first."},
	"conflict":                {CategoryConflict, false, "Re-read the current state, then repeat the call with the current identifiers."},
	"integrity_mismatch":      {CategoryIntegrityMismatch, false, "Treat the artifact as untrusted; re-export it and compare against a separately retained digest."},
	"truncated":               {CategoryTruncated, true, "Raise the named limit or narrow the request, then repeat the call."},
	"timed_out":               {CategoryTimeout, true, "Raise the named deadline, narrow the request, or run the scan as a background artifact."},
	"cancelled":               {CategoryCancelled, true, "Repeat the call if the work is still wanted; partial side effects may remain."},
	"resource_constraint":     {CategoryResourceConstraint, true, "Use the limit facts in this error to raise the ceiling or narrow the request."},
	"limit_exceeded":          {CategoryResourceConstraint, true, "Use the limit facts in this error to raise the ceiling or narrow the request."},
	"connection_failed":       {CategoryUnavailable, true, "Confirm the endpoint is reachable from the container and that the engagement scopes it."},
	"execution_failed":        {CategoryExecutionFailure, true, "Read the captured diagnostics; correct the input before repeating the call."},
	"child_failed":            {CategoryExecutionFailure, true, "Read stderr and the exit code; many tools use non-zero exits for partial findings."},
	"internal_error":          {CategoryInternal, false, "Report the tool name and exception type with a reproduction; do not retry blindly."},
}

// ErrorOption customizes a constructed *Error.
type ErrorOption func(*Error)

// WithDetails attaches structured details to an Error.
func WithDetails(details map[string]any) ErrorOption {
	return func(e *Error) {
		if details == nil {
			return
		}
		if e.Details == nil {
			e.Details = make(map[string]any, len(details))
		}
		for k, v := range details {
			e.Details[k] = v
		}
	}
}

// WithLimit attaches LimitFacts to an Error.
func WithLimit(limit *LimitFacts) ErrorOption {
	return func(e *Error) {
		e.Limit = limit
	}
}

// WithRemediation overrides the default remediation text.
func WithRemediation(action string) ErrorOption {
	return func(e *Error) {
		if action != "" {
			e.Remediation = ErrorRemediation{Action: action}
		}
	}
}

// WithCause wraps an underlying error.
func WithCause(err error) ErrorOption {
	return func(e *Error) {
		e.cause = err
	}
}

// NewError builds a structured *Error using the registered contract code.
func NewError(code, message string, opts ...ErrorOption) *Error {
	spec, ok := errorRegistry[code]
	if !ok {
		code = "internal_error"
		spec = errorRegistry[code]
	}
	if message == "" {
		message = code
	}
	err := &Error{
		Code:        code,
		Category:    spec.category,
		Message:     message,
		Retryable:   spec.retryable,
		Remediation: ErrorRemediation{Action: spec.remediation},
		Details:     map[string]any{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(err)
		}
	}
	return err
}

// ErrorCode extracts the OpenCyber error code from err, or "" if err is not an *Error.
func ErrorCode(err error) string {
	var ocErr *Error
	if errors.As(err, &ocErr) {
		return ocErr.Code
	}
	return ""
}

// Coverage declares how much of a collection, stream, or run was examined.
type Coverage struct {
	Status     string `json:"status"`
	Examined   *int64 `json:"examined"`
	Total      *int64 `json:"total"`
	Exhausted  *bool  `json:"exhausted"`
	NextOffset *int   `json:"next_offset"`
}

// NewCoverage creates a Coverage declaration with explicit status.
func NewCoverage(status string) *Coverage {
	return &Coverage{Status: status}
}

func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }
func intPtr(v int) *int       { return &v }

// LimitSource identifies who can change a named ceiling.
type LimitSource string

const (
	LimitSourceArgument    LimitSource = "argument"
	LimitSourceEnvironment LimitSource = "environment"
	LimitSourceFixed       LimitSource = "fixed"
)

// LimitSpec defines one named ceiling and its bounds.
type LimitSpec struct {
	ID           string      `json:"id"`
	Unit         string      `json:"unit"`
	Description  string      `json:"description"`
	Default      float64     `json:"default"`
	Minimum      *float64    `json:"minimum"`
	Maximum      *float64    `json:"maximum"`
	Source       LimitSource `json:"source"`
	Env          string      `json:"setting,omitempty"`
	Parameter    string      `json:"parameter,omitempty"`
	Recovery     string      `json:"recovery"`
	DoesNotRaise string      `json:"does_not_raise"`
}

// LimitFacts captures the enforced value and recovery guidance for a limit decision.
type LimitFacts struct {
	ID           string      `json:"id"`
	Unit         string      `json:"unit"`
	Effective    float64     `json:"effective"`
	Requested    *float64    `json:"requested"`
	Default      float64     `json:"default"`
	Minimum      *float64    `json:"minimum"`
	Maximum      *float64    `json:"maximum"`
	Source       LimitSource `json:"source"`
	Setting      string      `json:"setting,omitempty"`
	Parameter    string      `json:"parameter,omitempty"`
	Recovery     string      `json:"recovery"`
	DoesNotRaise string      `json:"does_not_raise"`
}

func float64Ptr(v float64) *float64 { return &v }

// Effective resolves the limit value, honoring environment overrides and failing closed on invalid input.
func (l LimitSpec) Effective() (float64, error) {
	if l.Source != LimitSourceEnvironment || l.Env == "" {
		return l.Default, nil
	}
	raw := strings.TrimSpace(os.Getenv(l.Env))
	if raw == "" {
		return l.Default, nil
	}
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, NewError("invalid_argument",
			fmt.Sprintf("%s must be a number of %s, got %q", l.Env, l.Unit, raw),
			WithDetails(map[string]any{"setting": l.Env, "limit": l.ID}),
			WithRemediation(fmt.Sprintf("Set %s to a number between %s or unset it.", l.Env, l.boundsText())),
		)
	}
	if !l.inBounds(val) {
		return 0, NewError("invalid_argument",
			fmt.Sprintf("%s must be between %s, got %g", l.Env, l.boundsText(), val),
			WithDetails(map[string]any{"setting": l.Env, "limit": l.ID}),
			WithRemediation(fmt.Sprintf("Set %s to a number between %s or unset it.", l.Env, l.boundsText())),
		)
	}
	return val, nil
}

func (l LimitSpec) inBounds(v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	if l.Minimum != nil && v < *l.Minimum {
		return false
	}
	if l.Maximum != nil && v > *l.Maximum {
		return false
	}
	return true
}

func (l LimitSpec) boundsText() string {
	low := "0"
	if l.Minimum != nil {
		low = strconv.FormatFloat(*l.Minimum, 'g', -1, 64)
	}
	high := "unbounded"
	if l.Maximum != nil {
		high = strconv.FormatFloat(*l.Maximum, 'g', -1, 64)
	}
	return low + " and " + high
}

// Facts builds LimitFacts for a specific enforced value.
func (l LimitSpec) Facts(effective float64, requested *float64, parameter string) *LimitFacts {
	param := l.Parameter
	if parameter != "" {
		param = parameter
	}
	return &LimitFacts{
		ID:           l.ID,
		Unit:         l.Unit,
		Effective:    effective,
		Requested:    requested,
		Default:      l.Default,
		Minimum:      l.Minimum,
		Maximum:      l.Maximum,
		Source:       l.Source,
		Setting:      l.Env,
		Parameter:    param,
		Recovery:     l.Recovery,
		DoesNotRaise: l.DoesNotRaise,
	}
}

// Standard execution, HTTP, and evidence limits matching limits.py.
var (
	LimitToolTimeout = LimitSpec{
		ID:           "tool.timeout_s",
		Unit:         "seconds",
		Description:  "Deadline for one executable-backed tool call.",
		Default:      1800,
		Minimum:      float64Ptr(0),
		Maximum:      float64Ptr(86400),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_TOOL_TIMEOUT_S",
		Recovery:     "Raise OPENCYBER_TOOL_TIMEOUT_S, or set it to 0 to run without a server deadline.",
		DoesNotRaise: "The client's own cancellation or request deadline.",
	}
	LimitToolMaxOutput = LimitSpec{
		ID:           "tool.max_output_bytes",
		Unit:         "bytes",
		Description:  "Output retained per stream from one executable-backed tool call.",
		Default:      4194304,
		Minimum:      float64Ptr(0),
		Maximum:      float64Ptr(268435456),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_TOOL_MAX_OUTPUT_BYTES",
		Recovery:     "Raise OPENCYBER_TOOL_MAX_OUTPUT_BYTES, or redirect the tool's output to an engagement file.",
		DoesNotRaise: "The child process's own write path; the excess is read and discarded.",
	}
	LimitHTTPTimeout = LimitSpec{
		ID:           "http.timeout",
		Unit:         "seconds",
		Description:  "Deadline for one native HTTP request.",
		Default:      30,
		Minimum:      float64Ptr(0),
		Maximum:      float64Ptr(300),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_HTTP_TIMEOUT",
		Recovery:     "Pass a per-call timeout, or raise OPENCYBER_HTTP_TIMEOUT up to 300 seconds.",
		DoesNotRaise: "The server's own deadline for executable-backed tools.",
	}
	LimitHTTPResponseMaxBytes = LimitSpec{
		ID:           "http.response_max_bytes",
		Unit:         "bytes",
		Description:  "Decompressed response body bytes retained by one native HTTP request, including redirect responses.",
		Default:      262144,
		Source:       LimitSourceFixed,
		Recovery:     "Request a smaller resource or use server-supported Range requests to retrieve specific bytes.",
		DoesNotRaise: "HTTP headers, other HTTP tools, or the envelope evidence ceiling.",
	}
	LimitEvidenceMaxFiles = LimitSpec{
		ID:           "evidence.max_files",
		Unit:         "files",
		Description:  "Files selected into one evidence bundle.",
		Default:      10000,
		Minimum:      float64Ptr(1),
		Source:       LimitSourceFixed,
		Parameter:    "paths",
		Recovery:     "Export in several bundles and retain each archive digest.",
		DoesNotRaise: "Files present in the engagement workspace.",
	}
	LimitEvidenceMaxManifestBytes = LimitSpec{
		ID:           "evidence.max_manifest_bytes",
		Unit:         "bytes",
		Description:  "Manifest size for one evidence bundle.",
		Default:      8388608,
		Source:       LimitSourceFixed,
		Recovery:     "Export fewer paths per bundle.",
		DoesNotRaise: "The size of the files being exported.",
	}
)

// DefaultLimits returns all environment-backed and core limits inspected by diagnostics.
func DefaultLimits() []LimitSpec {
	return []LimitSpec{
		LimitToolTimeout,
		LimitToolMaxOutput,
		LimitHTTPTimeout,
		LimitHTTPResponseMaxBytes,
		LimitEvidenceMaxFiles,
		LimitEvidenceMaxManifestBytes,
	}
}

// ScopeDecision is the outcome of a command or URL scope validation.
type ScopeDecision struct {
	Enforced      bool     `json:"enforced"`
	Allowed       bool     `json:"allowed"`
	Candidates    []string `json:"candidates,omitempty"`
	Denied        []string `json:"denied,omitempty"`
	Host          string   `json:"host,omitempty"`
	MatchedTarget string   `json:"matched_target,omitempty"`
	Targets       []string `json:"targets,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Source        string   `json:"source,omitempty"`
}

// OfflineDecision is the outcome of an offline/airgap policy check for an executable.
type OfflineDecision struct {
	Offline    bool   `json:"offline"`
	Executable string `json:"executable"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
}

// ScopeValidator decouples pkg/exec from pkg/policy while preserving full enforcement semantics.
type ScopeValidator interface {
	CheckCommand(engagementID, executable string, args []string) (ScopeDecision, error)
	CheckURL(engagementID, rawURL, tool string) (ScopeDecision, error)
	CheckOffline(executable string) OfflineDecision
}

// TargetBlocklist decouples browser/HTTP request interception from pkg/control.
type TargetBlocklist interface {
	IsBlocked(engagementID, host, rawURL string) (pattern string, blocked bool)
}

// RateGovernor optionally paces outbound browser or HTTP requests per target URL.
type RateGovernor interface {
	Acquire(ctx context.Context, rawURL string) (release func(), err error)
	Observe(rawURL string, statusCode int)
}

// ToolAvailability describes one catalog executable and its resolved binary status.
type ToolAvailability struct {
	Name                string   `json:"name"`
	Executable          string   `json:"executable"`
	Category            string   `json:"category,omitempty"`
	Available           bool     `json:"available"`
	Path                string   `json:"path,omitempty"`
	Required            bool     `json:"required"`
	OptionalReason      string   `json:"optional_reason,omitempty"`
	MissingDependencies []string `json:"missing_dependencies,omitempty"`
}

// CatalogLookup decouples pkg/exec from pkg/catalog.
type CatalogLookup interface {
	LookupExecutable(executable string) (ToolAvailability, bool)
	AllTools() []ToolAvailability
}

// EngagementInfo holds metadata for an engagement namespace.
type EngagementInfo struct {
	SchemaVersion int      `json:"schema_version"`
	EngagementID  string   `json:"engagement_id"`
	Name          string   `json:"name"`
	Targets       []string `json:"targets"`
	Objective     string   `json:"objective"`
	CreatedAt     string   `json:"created_at"`
	Workspace     string   `json:"workspace,omitempty"`
}

// EngagementResolver resolves engagement metadata and validates workspace-contained paths.
type EngagementResolver interface {
	ResolvePath(engagementID, relPath string, mustExist bool) (string, error)
	EngagementMetadata(engagementID string) (EngagementInfo, error)
}

// AuditSnapshot summarizes a verified copy of an engagement's audit trail.
type AuditSnapshot struct {
	Events   int    `json:"events"`
	LastHash string `json:"last_hash"`
}

// AuditVerifyResult reports hash-chain verification of an audit stream.
type AuditVerifyResult struct {
	EngagementID    string `json:"engagement_id"`
	Valid           bool   `json:"valid"`
	Events          int    `json:"events"`
	FirstInvalidSeq *int   `json:"first_invalid_seq"`
	Error           string `json:"error,omitempty"`
	LastHash        string `json:"last_hash,omitempty"`
}

// AuditRecorder decouples pkg/exec from an external audit package while supporting
// tamper-evident hash-chained recording, snapshotting, and stream verification.
type AuditRecorder interface {
	Record(engagementID string, event map[string]any) (int64, error)
	Snapshot(ctx context.Context, engagementID string, dst io.Writer) (AuditSnapshot, error)
	VerifyStream(ctx context.Context, engagementID string, r io.Reader) (AuditVerifyResult, error)
}

// NopAuditRecorder discards audit writes and treats empty audit streams as valid.
type NopAuditRecorder struct{}

func (NopAuditRecorder) Record(string, map[string]any) (int64, error) { return 0, nil }
func (NopAuditRecorder) Snapshot(context.Context, string, io.Writer) (AuditSnapshot, error) {
	return AuditSnapshot{Events: 0, LastHash: GenesisAuditHash}, nil
}
func (NopAuditRecorder) VerifyStream(ctx context.Context, engagementID string, r io.Reader) (AuditVerifyResult, error) {
	return VerifyAuditStream(ctx, engagementID, r)
}

// DefaultScopeValidator implements ScopeValidator using environment flags and optional target matching.
type DefaultScopeValidator struct {
	Resolver EngagementResolver
}

// CheckOffline refuses well-known internet-only executables when OPENCYBER_OFFLINE is truthy.
func (v *DefaultScopeValidator) CheckOffline(executable string) OfflineDecision {
	offline := OfflineEnabled()
	allowNet := isTruthy(os.Getenv(OfflineNetworkAllowEnv))
	_, isNetTool := OfflineNetworkExecutables[executable]
	blocked := offline && isNetTool && !allowNet
	reason := ""
	if blocked {
		reason = fmt.Sprintf("%s requires internet access and %s=1 is set; set %s=1 only if the target network provides the required services",
			executable, OfflineEnv, OfflineNetworkAllowEnv)
	}
	return OfflineDecision{
		Offline:    offline,
		Executable: executable,
		Blocked:    blocked,
		Reason:     reason,
	}
}

// CheckCommand validates command arguments against engagement targets when OPENCYBER_ENFORCE_SCOPE is truthy.
func (v *DefaultScopeValidator) CheckCommand(engagementID, executable string, args []string) (ScopeDecision, error) {
	enforced := isTruthy(os.Getenv("OPENCYBER_ENFORCE_SCOPE"))
	if !enforced {
		return ScopeDecision{Enforced: false, Allowed: true}, nil
	}
	if executable == "bash" || executable == "python3" || executable == "python" {
		if !isTruthy(os.Getenv("OPENCYBER_ALLOW_UNSCOPED_EXECUTION")) {
			reason := fmt.Sprintf("%s executes arbitrary code and cannot be scope-checked; set OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1 to allow it under enforcement", executable)
			return ScopeDecision{Enforced: true, Allowed: false, Reason: reason},
				NewError("scope_denied", fmt.Sprintf("scope enforcement refused %s: %s", executable, reason),
					WithDetails(map[string]any{"executable": executable}))
		}
	}
	if v == nil || v.Resolver == nil {
		return ScopeDecision{Enforced: true, Allowed: true}, nil
	}
	meta, err := v.Resolver.EngagementMetadata(engagementID)
	if err != nil {
		return ScopeDecision{Enforced: true, Allowed: false, Reason: err.Error()}, err
	}
	var candidates, denied []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			u, uerr := CanonicalHTTPURL(arg)
			if uerr == nil {
				host := strings.ToLower(u.Hostname())
				candidates = append(candidates, arg)
				if !hostMatchesAnyTarget(host, meta.Targets) {
					denied = append(denied, arg)
				}
			}
		} else if _, perr := netip.ParseAddr(arg); perr == nil {
			candidates = append(candidates, arg)
			if !hostMatchesAnyTarget(arg, meta.Targets) {
				denied = append(denied, arg)
			}
		}
	}
	if len(denied) > 0 {
		reason := "out-of-scope network target(s): " + strings.Join(denied, ", ")
		return ScopeDecision{
				Enforced:   true,
				Allowed:    false,
				Candidates: candidates,
				Denied:     denied,
				Targets:    meta.Targets,
				Reason:     reason,
			}, NewError("scope_denied", fmt.Sprintf("scope enforcement refused %s: %s", executable, reason),
				WithDetails(map[string]any{"executable": executable, "denied": denied}))
	}
	return ScopeDecision{Enforced: true, Allowed: true, Candidates: candidates, Targets: meta.Targets}, nil
}

// CheckURL validates a native HTTP target URL using CanonicalHTTPURL and engagement scope.
func (v *DefaultScopeValidator) CheckURL(engagementID, rawURL, tool string) (ScopeDecision, error) {
	u, err := CanonicalHTTPURL(rawURL)
	if err != nil {
		return ScopeDecision{}, err
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	enforced := isTruthy(os.Getenv("OPENCYBER_ENFORCE_SCOPE"))
	if !enforced {
		return ScopeDecision{Enforced: false, Allowed: true, Host: host}, nil
	}
	if engagementID == "" {
		return ScopeDecision{Enforced: true, Allowed: false, Host: host, Reason: "engagement_required"},
			NewError("engagement_required",
				fmt.Sprintf("%s requires engagement_id while OPENCYBER_ENFORCE_SCOPE is on", tool),
				WithDetails(map[string]any{"tool": tool, "url": rawURL}))
	}
	if v == nil || v.Resolver == nil {
		return ScopeDecision{Enforced: true, Allowed: false, Host: host, Reason: "no engagement resolver configured"},
			NewError("scope_denied", fmt.Sprintf("scope enforcement refused %s: no engagement resolver configured", tool),
				WithDetails(map[string]any{"tool": tool, "url": rawURL}))
	}
	meta, err := v.Resolver.EngagementMetadata(engagementID)
	if err != nil {
		return ScopeDecision{Enforced: true, Allowed: false, Host: host, Reason: err.Error()}, err
	}
	matched := matchHostTarget(host, meta.Targets)
	if matched == "" {
		reason := fmt.Sprintf("out-of-scope network target: %s", host)
		return ScopeDecision{
				Enforced: true,
				Allowed:  false,
				Host:     host,
				Targets:  meta.Targets,
				Reason:   reason,
			}, NewError("scope_denied", fmt.Sprintf("scope enforcement refused %s: %s", tool, reason),
				WithDetails(map[string]any{"tool": tool, "url": rawURL, "host": host, "targets": meta.Targets}))
	}
	return ScopeDecision{
		Enforced:      true,
		Allowed:       true,
		Host:          host,
		MatchedTarget: matched,
		Targets:       meta.Targets,
	}, nil
}

func hostMatchesAnyTarget(host string, targets []string) bool {
	return matchHostTarget(host, targets) != ""
}

func matchHostTarget(host string, targets []string) string {
	host = normalizeTargetHost(host)
	if host == "" {
		return ""
	}
	hostIP, hostIsIP := parseIP(host)
	for _, rawTarget := range targets {
		t := normalizeTargetHost(rawTarget)
		if t == "" {
			continue
		}
		if t == "*" {
			return rawTarget
		}
		if strings.Contains(t, "/") {
			if pfx, err := netip.ParsePrefix(t); err == nil && hostIsIP && pfx.Contains(hostIP) {
				return rawTarget
			}
			continue
		}
		targetIP, targetIsIP := parseIP(t)
		if targetIsIP || hostIsIP {
			if targetIsIP && hostIsIP && hostIP == targetIP {
				return rawTarget
			}
			continue
		}
		if host == t || strings.HasSuffix(host, "."+t) {
			return rawTarget
		}
	}
	return ""
}

func parseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func normalizeTargetHost(v string) string {
	s := strings.TrimSpace(v)
	s = strings.Trim(s, ",;:)]}'\"[]")
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		}
	}
	s = strings.TrimPrefix(s, "*.")
	if idx := strings.LastIndex(s, "@"); idx >= 0 {
		s = s[idx+1:]
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 1 {
			s = s[1:end]
		}
	} else if strings.Count(s, ":") == 1 {
		if h, p, err := net.SplitHostPort(s); err == nil {
			if _, perr := strconv.Atoi(p); perr == nil {
				s = h
			}
		}
	}
	return strings.TrimSuffix(s, ".")
}

// CanonicalHTTPURL validates an HTTP(S) URL so the parsed authority cannot diverge
// from the wire authority (rejecting backslash, userinfo, whitespace, control
// characters, and percent-encoded separators in the authority).
func CanonicalHTTPURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, NewError("invalid_argument", "URL must be a non-empty string")
	}
	// Inspect the raw authority slice before net/url normalizes anything.
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd <= 0 {
		return nil, NewError("invalid_argument", "URL must use http or https")
	}
	scheme := strings.ToLower(rawURL[:schemeEnd])
	if scheme != "http" && scheme != "https" {
		return nil, NewError("invalid_argument", "URL must use http or https")
	}
	rest := rawURL[schemeEnd+3:]
	authEnd := strings.IndexAny(rest, "/?#")
	rawAuthority := rest
	if authEnd >= 0 {
		rawAuthority = rest[:authEnd]
	}
	if rawAuthority == "" {
		return nil, NewError("invalid_argument", "URL must include an authority")
	}
	for i := 0; i < len(rawAuthority); i++ {
		c := rawAuthority[i]
		if c == '\\' || c == '@' || c == '%' || c <= 0x20 || c == 0x7f {
			return nil, NewError("invalid_argument",
				"URL authority is ambiguous: backslash, userinfo, whitespace, control characters and encoded separators are refused")
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, NewError("invalid_argument", fmt.Sprintf("invalid URL: %v", err), WithCause(err))
	}
	if u.Hostname() == "" {
		return nil, NewError("invalid_argument", "URL must include a host")
	}
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port >= 65536 {
			return nil, NewError("invalid_argument", "URL port is out of range")
		}
	}
	return u, nil
}

// CredentialBoundaryChanged returns true when a redirect hop must strip Authorization
// and Cookie headers (different host or HTTPS-to-HTTP downgrade; same-host HTTP->HTTPS keeps them).
func CredentialBoundaryChanged(currentURL, nextURL string) (bool, error) {
	cur, err := CanonicalHTTPURL(currentURL)
	if err != nil {
		return true, err
	}
	nxt, err := CanonicalHTTPURL(nextURL)
	if err != nil {
		return true, err
	}
	if !strings.EqualFold(cur.Hostname(), nxt.Hostname()) {
		return true, nil
	}
	return strings.EqualFold(cur.Scheme, "https") && strings.EqualFold(nxt.Scheme, "http"), nil
}

// DirEngagementResolver is a filesystem-backed EngagementResolver rooted at a workspace directory.
type DirEngagementResolver struct {
	WorkspaceRoot string
}

var engagementIDPattern = regexp.MustCompile(`^eng_\d{8}_[0-9a-f]{32}$`)

// CreateEngagement creates a new engagement directory with engagement.json and standard subdirs.
func (r *DirEngagementResolver) CreateEngagement(name string, targets []string, objective string) (EngagementInfo, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return EngagementInfo{}, NewError("invalid_argument", "name must not be empty")
	}
	if len(name) > 200 {
		return EngagementInfo{}, NewError("invalid_argument", "name must be 200 characters or fewer")
	}
	if len(targets) == 0 {
		return EngagementInfo{}, NewError("invalid_argument", "targets must contain at least one authorized target")
	}
	normTargets := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			return EngagementInfo{}, NewError("invalid_argument", "every target must be a non-empty string")
		}
		normTargets = append(normTargets, t)
	}
	engRoot := filepath.Join(r.WorkspaceRoot, "engagements")
	if err := os.MkdirAll(engRoot, 0o700); err != nil {
		return EngagementInfo{}, err
	}
	id := fmt.Sprintf("eng_%s_%s", time.Now().UTC().Format("20060102"), randomHex(16))
	dir := filepath.Join(engRoot, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return EngagementInfo{}, err
	}
	for _, sub := range []string{"artifacts", "evidence", "findings"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return EngagementInfo{}, err
		}
	}
	absDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		absDir, _ = filepath.Abs(dir)
	}
	info := EngagementInfo{
		SchemaVersion: 1,
		EngagementID:  id,
		Name:          name,
		Targets:       normTargets,
		Objective:     strings.TrimSpace(objective),
		CreatedAt:     nowUTC(),
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return EngagementInfo{}, err
	}
	data = append(data, '\n')
	if err := atomicWriteFile(filepath.Join(dir, "engagement.json"), data, 0o600); err != nil {
		return EngagementInfo{}, err
	}
	info.Workspace = absDir
	return info, nil
}

// EngagementMetadata loads and validates <workspace>/engagements/<engagementID>/engagement.json.
func (r *DirEngagementResolver) EngagementMetadata(engagementID string) (EngagementInfo, error) {
	if !engagementIDPattern.MatchString(engagementID) {
		return EngagementInfo{}, NewError("invalid_argument",
			"engagement_id must be a server-generated identifier such as eng_20261009_9f8d4c1a6b2743f4a2c11bb8d02a91a7",
			WithDetails(map[string]any{"engagement_id": engagementID}))
	}
	baseRoot, err := filepath.Abs(r.WorkspaceRoot)
	if err != nil {
		return EngagementInfo{}, err
	}
	if resolved, err := filepath.EvalSymlinks(baseRoot); err == nil {
		baseRoot = resolved
	}
	engRoot := filepath.Join(baseRoot, "engagements")
	engDir := filepath.Join(engRoot, engagementID)
	fi, err := os.Lstat(engDir)
	if err != nil {
		if os.IsNotExist(err) {
			return EngagementInfo{}, NewError("engagement_not_found", fmt.Sprintf("unknown engagement_id: %s", engagementID),
				WithDetails(map[string]any{"engagement_id": engagementID}))
		}
		return EngagementInfo{}, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return EngagementInfo{}, NewError("invalid_argument", fmt.Sprintf("invalid engagement namespace: %s", engagementID),
			WithDetails(map[string]any{"engagement_id": engagementID}))
	}
	manifestPath := filepath.Join(engDir, "engagement.json")
	mfi, err := os.Lstat(manifestPath)
	if err != nil || mfi.Mode()&os.ModeSymlink != 0 || !mfi.Mode().IsRegular() {
		return EngagementInfo{}, NewError("engagement_not_found", fmt.Sprintf("unknown engagement_id: %s", engagementID),
			WithDetails(map[string]any{"engagement_id": engagementID}))
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return EngagementInfo{}, NewError("integrity_mismatch", fmt.Sprintf("invalid engagement manifest: %s", engagementID),
			WithDetails(map[string]any{"engagement_id": engagementID}), WithCause(err))
	}
	var info EngagementInfo
	if err := json.Unmarshal(raw, &info); err != nil || info.EngagementID != engagementID {
		return EngagementInfo{}, NewError("integrity_mismatch", fmt.Sprintf("invalid engagement manifest: %s", engagementID),
			WithDetails(map[string]any{"engagement_id": engagementID}))
	}
	info.Workspace = engDir
	return info, nil
}

// ResolvePath resolves relPath strictly inside the engagement's workspace directory.
func (r *DirEngagementResolver) ResolvePath(engagementID, relPath string, mustExist bool) (string, error) {
	meta, err := r.EngagementMetadata(engagementID)
	if err != nil {
		return "", err
	}
	if relPath == "" {
		relPath = "."
	}
	root := filepath.Clean(meta.Workspace)
	var candidate string
	if filepath.IsAbs(relPath) {
		candidate = filepath.Clean(relPath)
	} else {
		candidate = filepath.Clean(filepath.Join(root, relPath))
	}
	// Reject any symlink escape for existing prefixes.
	resolvedCandidate, err := evalSymlinksExistingPrefix(candidate)
	if err != nil {
		return "", err
	}
	if !pathWithinRoot(root, resolvedCandidate) {
		return "", NewError("scope_denied",
			fmt.Sprintf("path must remain inside engagement %s", engagementID),
			WithDetails(map[string]any{"path": relPath, "engagement_id": engagementID}))
	}
	if mustExist {
		if _, err := os.Stat(resolvedCandidate); err != nil {
			if os.IsNotExist(err) {
				return "", NewError("not_found",
					fmt.Sprintf("engagement path does not exist: %s", relPath),
					WithDetails(map[string]any{"path": relPath, "engagement_id": engagementID}))
			}
			return "", err
		}
	}
	return resolvedCandidate, nil
}

func evalSymlinksExistingPrefix(p string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, nil
	}
	// Walk upward to find the deepest existing ancestor and resolve symlinks on it.
	var tail []string
	cur := filepath.Clean(p)
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return filepath.Clean(p), nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			parts := []string{resolved}
			for i := len(tail) - 1; i >= 0; i-- {
				parts = append(parts, tail[i])
			}
			return filepath.Clean(filepath.Join(parts...)), nil
		}
	}
}

func pathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// --- Tamper-evident Audit Trail (matches audit.py) ---

const (
	AuditSchemaVersion  = 1
	GenesisAuditHash    = "0000000000000000000000000000000000000000000000000000000000000000"
	MaxAuditRecordBytes = 1024 * 1024
)

var (
	secretKeyPattern   = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|private[_-]?key|credential|passphrase|bearer)`)
	secretValuePattern = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|passphrase|bearer)(\s*[:=]\s*)([^\s,;"']+)`)
	bearerPattern      = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
)

// RedactString redacts inline bearer tokens and key=value secrets in a string.
func RedactString(s string) string {
	s = bearerPattern.ReplaceAllString(s, "Bearer ***")
	s = secretValuePattern.ReplaceAllString(s, "${1}${2}***")
	return s
}

// Redact recursively redacts secret keys and credential values in maps, slices, and strings.
func Redact(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			if secretKeyPattern.MatchString(k) {
				out[k] = "***"
			} else {
				out[k] = Redact(child)
			}
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(val))
		for k, child := range val {
			if secretKeyPattern.MatchString(k) {
				out[k] = "***"
			} else {
				out[k] = RedactString(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = Redact(item)
		}
		return out
	case []string:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = RedactString(item)
		}
		return out
	case string:
		return RedactString(val)
	default:
		return v
	}
}

// CanonicalJSON serializes v into deterministic compact JSON with sorted keys and unescaped HTML.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b, nil
}

func auditDigest(payload map[string]any) (string, error) {
	b, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// FileAuditRecorder stores hash-chained JSONL audit records under <engagement>/.opencyber/audit/events.jsonl.
type FileAuditRecorder struct {
	Resolver EngagementResolver
	mu       sync.Mutex
}

// NewFileAuditRecorder creates a FileAuditRecorder backed by the given EngagementResolver.
func NewFileAuditRecorder(resolver EngagementResolver) *FileAuditRecorder {
	return &FileAuditRecorder{Resolver: resolver}
}

func (a *FileAuditRecorder) eventsPath(engagementID string, createDir bool) (string, error) {
	dir, err := a.Resolver.ResolvePath(engagementID, ".opencyber/audit", false)
	if err != nil {
		return "", err
	}
	if createDir {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, "events.jsonl"), nil
}

// Record appends one redacted, hash-chained audit event and returns its sequence number.
func (a *FileAuditRecorder) Record(engagementID string, event map[string]any) (int64, error) {
	if event == nil {
		return 0, NewError("invalid_argument", "audit event must be a dictionary")
	}
	if _, ok := event["event"].(string); !ok {
		return 0, NewError("invalid_argument", "audit event requires a string 'event' field")
	}
	path, err := a.eventsPath(engagementID, true)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	if err := flockFile(f, true); err != nil {
		return 0, err
	}
	defer func() { _ = funlockFile(f) }()

	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, NewError("integrity_mismatch", "audit requires a regular file")
	}

	var prevSeq int64
	prevHash := GenesisAuditHash
	if fi.Size() > 0 {
		window := fi.Size()
		if window > MaxAuditRecordBytes+1 {
			window = MaxAuditRecordBytes + 1
		}
		if _, err := f.Seek(fi.Size()-window, io.SeekStart); err != nil {
			return 0, err
		}
		tail, err := io.ReadAll(f)
		if err != nil {
			return 0, err
		}
		lines := strings.Split(strings.TrimRight(string(tail), "\r\n"), "\n")
		lastLine := ""
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.TrimSpace(lines[i]) != "" {
				lastLine = lines[i]
				break
			}
		}
		if lastLine == "" {
			return 0, NewError("integrity_mismatch", "existing audit has no readable final record")
		}
		if len(lastLine)+1 > MaxAuditRecordBytes {
			return 0, NewError("integrity_mismatch", "existing audit record exceeds the 1 MiB limit")
		}
		var last map[string]any
		if err := json.Unmarshal([]byte(lastLine), &last); err != nil {
			return 0, NewError("integrity_mismatch", "existing audit has an invalid final record", WithCause(err))
		}
		if seqFloat, ok := last["seq"].(float64); ok {
			prevSeq = int64(seqFloat)
		}
		if h, ok := last["hash"].(string); ok && h != "" {
			prevHash = h
		}
	}

	seq := prevSeq + 1
	redacted := Redact(event).(map[string]any)
	payload := make(map[string]any, len(redacted)+5)
	for k, v := range redacted {
		payload[k] = v
	}
	payload["schema_version"] = AuditSchemaVersion
	payload["seq"] = seq
	if _, ok := payload["ts"]; !ok {
		payload["ts"] = nowUTC()
	}
	payload["engagement_id"] = engagementID
	payload["prev_hash"] = prevHash
	delete(payload, "hash")

	hash, err := auditDigest(payload)
	if err != nil {
		return 0, err
	}
	payload["hash"] = hash
	encoded, err := CanonicalJSON(payload)
	if err != nil {
		return 0, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxAuditRecordBytes {
		return 0, NewError("invalid_argument", "audit record exceeds the 1 MiB verification limit")
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return 0, err
	}
	if _, err := f.Write(encoded); err != nil {
		return 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	return seq, nil
}

// Snapshot copies and verifies the engagement's existing audit file into dst under a shared lock.
func (a *FileAuditRecorder) Snapshot(ctx context.Context, engagementID string, dst io.Writer) (AuditSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AuditSnapshot{}, err
	}
	path, err := a.eventsPath(engagementID, false)
	if err != nil {
		return AuditSnapshot{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := openRegularNoFollow(path)
	if err != nil {
		return AuditSnapshot{}, NewError("integrity_mismatch", fmt.Sprintf("audit file missing or unreadable: %v", err), WithCause(err))
	}
	defer f.Close()

	if err := flockFile(f, false); err != nil {
		return AuditSnapshot{}, err
	}
	defer func() { _ = funlockFile(f) }()

	before, err := f.Stat()
	if err != nil {
		return AuditSnapshot{}, err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, f); err != nil {
		return AuditSnapshot{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return AuditSnapshot{}, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return AuditSnapshot{}, NewError("conflict", "audit changed while its snapshot was copied")
	}
	res, err := VerifyAuditStream(ctx, engagementID, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return AuditSnapshot{}, err
	}
	if !res.Valid {
		return AuditSnapshot{}, NewError("integrity_mismatch", fmt.Sprintf("invalid audit snapshot: %s", res.Error))
	}
	if _, err := dst.Write(buf.Bytes()); err != nil {
		return AuditSnapshot{}, err
	}
	return AuditSnapshot{Events: res.Events, LastHash: res.LastHash}, nil
}

// VerifyStream verifies an audit JSONL stream against engagementID.
func (a *FileAuditRecorder) VerifyStream(ctx context.Context, engagementID string, r io.Reader) (AuditVerifyResult, error) {
	return VerifyAuditStream(ctx, engagementID, r)
}

// VerifyAuditStream validates the sequence, schema_version, engagement_id, prev_hash, and SHA-256 chain.
func VerifyAuditStream(ctx context.Context, engagementID string, r io.Reader) (AuditVerifyResult, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	prevHash := GenesisAuditHash
	count := 0
	lineNo := 0
	for {
		if err := ctx.Err(); err != nil {
			return AuditVerifyResult{}, err
		}
		line, isPrefix, err := readBoundedLine(br, MaxAuditRecordBytes)
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return AuditVerifyResult{}, err
		}
		lineNo++
		if isPrefix {
			return invalidAuditResult(engagementID, count, lineNo, "audit record exceeds the 1 MiB verification limit"), nil
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if err == io.EOF {
				break
			}
			continue
		}
		var rec map[string]any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if jerr := dec.Decode(&rec); jerr != nil {
			return invalidAuditResult(engagementID, count, lineNo, fmt.Sprintf("invalid JSON: %v", jerr)), nil
		}
		if rec == nil {
			return invalidAuditResult(engagementID, count, lineNo, "record is not an object"), nil
		}
		seqNum, ok := jsonInt(rec["seq"])
		if !ok || seqNum != int64(count+1) {
			return invalidAuditResult(engagementID, count, lineNo, fmt.Sprintf("expected seq %d", count+1)), nil
		}
		verNum, ok := jsonInt(rec["schema_version"])
		if !ok || verNum != AuditSchemaVersion {
			return invalidAuditResult(engagementID, count, lineNo, "unsupported audit schema_version"), nil
		}
		if eid, _ := rec["engagement_id"].(string); eid != engagementID {
			return invalidAuditResult(engagementID, count, lineNo, "audit engagement_id does not match"), nil
		}
		if ph, _ := rec["prev_hash"].(string); ph != prevHash {
			return invalidAuditResult(engagementID, count, lineNo, "prev_hash does not match the previous record"), nil
		}
		recHash, _ := rec["hash"].(string)
		noHash := make(map[string]any, len(rec)-1)
		for k, v := range rec {
			if k != "hash" {
				noHash[k] = v
			}
		}
		expectedHash, derr := auditDigest(noHash)
		if derr != nil || expectedHash != recHash {
			return invalidAuditResult(engagementID, count, lineNo, "record hash does not match its contents"), nil
		}
		count++
		prevHash = recHash
		if err == io.EOF {
			break
		}
	}
	return AuditVerifyResult{
		EngagementID:    engagementID,
		Valid:           true,
		Events:          count,
		FirstInvalidSeq: nil,
		LastHash:        prevHash,
	}, nil
}

func invalidAuditResult(engagementID string, count, lineNo int, msg string) AuditVerifyResult {
	seq := count + 1
	return AuditVerifyResult{
		EngagementID:    engagementID,
		Valid:           false,
		Events:          count,
		FirstInvalidSeq: &seq,
		Error:           fmt.Sprintf("line %d: %s", lineNo, msg),
	}
}

func readBoundedLine(br *bufio.Reader, limit int) ([]byte, bool, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > limit {
			return out[:limit], true, nil
		}
		if err == nil {
			return out, false, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return out, false, err
	}
}

func jsonInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if strings.ContainsAny(n.String(), ".eE") {
			return 0, false
		}
		i, err := n.Int64()
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if math.Trunc(n) != n {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}

// --- Common internal helpers ---

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func randomHex(numBytes int) string {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp entropy if crypto/rand ever failed.
		sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		return hex.EncodeToString(sum[:numBytes])
	}
	return hex.EncodeToString(b)
}

func atomicWriteFile(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	success = true
	return nil
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Package errors implements the machine-actionable refusal contract, uniform
// tool result envelope, named operational limits, IOC/secret extraction and
// redaction, and coverage accounting shared across Hanzo Cyber.
package errors

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Version is the semantic release string reported in result envelope contract blocks.
const Version = "1.0.0-beta.1"

// ErrorCategory is the coarse failure family used for routing and reporting.
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

// Registered error code constants.
const (
	CodeInvalidArgument        = "invalid_argument"
	CodeMissingParameter       = "missing_parameter"
	CodeUnknownTool            = "unknown_tool"
	CodeEngagementRequired     = "engagement_required"
	CodeEngagementNotFound     = "engagement_not_found"
	CodeScopeDenied            = "scope_denied"
	CodePermissionDenied       = "permission_denied"
	CodeAuthorizationRequired  = "authorization_required"
	CodeAuthorizationInvalid   = "authorization_invalid"
	CodeApprovalInvalid        = "approval_invalid"
	CodeCapabilityUnavailable  = "capability_unavailable"
	CodeIntegrationUnavailable = "integration_unavailable"
	CodeOfflineBlocked         = "offline_blocked"
	CodeNotFound               = "not_found"
	CodeAlreadyExists          = "already_exists"
	CodeConflict               = "conflict"
	CodeIntegrityMismatch      = "integrity_mismatch"
	CodeTruncated              = "truncated"
	CodeTimedOut               = "timed_out"
	CodeCancelled              = "cancelled"
	CodeResourceConstraint     = "resource_constraint"
	CodeLimitExceeded          = "limit_exceeded"
	CodeConnectionFailed       = "connection_failed"
	CodeExecutionFailed        = "execution_failed"
	CodeChildFailed            = "child_failed"
	CodeInternalError          = "internal_error"
)

var allCategories = []ErrorCategory{
	CategoryInvalidInput,
	CategoryDenied,
	CategoryUnavailable,
	CategoryNotFound,
	CategoryConflict,
	CategoryIntegrityMismatch,
	CategoryTruncated,
	CategoryTimeout,
	CategoryCancelled,
	CategoryResourceConstraint,
	CategoryExecutionFailure,
	CategoryInternal,
}

// AllCategories returns a copy of the closed category vocabulary.
func AllCategories() []ErrorCategory {
	out := make([]ErrorCategory, len(allCategories))
	copy(out, allCategories)
	return out
}

// ErrorSpec describes one registered refusal code and its default recovery guidance.
type ErrorSpec struct {
	Code        string
	Category    ErrorCategory
	Retryable   bool
	Summary     string
	Remediation string
}

var errorSpecs = []ErrorSpec{
	{
		Code:        CodeInvalidArgument,
		Category:    CategoryInvalidInput,
		Retryable:   false,
		Summary:     "An argument is missing, malformed, or out of range.",
		Remediation: "Correct the reported argument and repeat the call unchanged otherwise.",
	},
	{
		Code:        CodeMissingParameter,
		Category:    CategoryInvalidInput,
		Retryable:   false,
		Summary:     "A required parameter was not supplied.",
		Remediation: "Supply the named parameter; inspect the tool schema for its type.",
	},
	{
		Code:        CodeUnknownTool,
		Category:    CategoryInvalidInput,
		Retryable:   false,
		Summary:     "No catalog tool matches the requested oc_* name.",
		Remediation: "Call oc_catalog with an exact name, substring query, or category first.",
	},
	{
		Code:        CodeEngagementRequired,
		Category:    CategoryInvalidInput,
		Retryable:   false,
		Summary:     "Scope enforcement is on and the call did not name an engagement.",
		Remediation: "Create or select an engagement and pass its engagement_id.",
	},
	{
		Code:        CodeEngagementNotFound,
		Category:    CategoryNotFound,
		Retryable:   false,
		Summary:     "No engagement exists for the supplied identifier.",
		Remediation: "Call oc_engagement_list and use a server-generated engagement_id.",
	},
	{
		Code:        CodeScopeDenied,
		Category:    CategoryDenied,
		Retryable:   false,
		Summary:     "The target is outside the engagement's authorized scope.",
		Remediation: "Add the target to the engagement scope, or call oc_scope_check before retrying.",
	},
	{
		Code:        CodePermissionDenied,
		Category:    CategoryDenied,
		Retryable:   false,
		Summary:     "The container refused the filesystem or process operation.",
		Remediation: "Check the owning path and file mode inside the engagement workspace.",
	},
	{
		Code:        CodeAuthorizationRequired,
		Category:    CategoryDenied,
		Retryable:   false,
		Summary:     "The engagement has no signed operator authorization for this action.",
		Remediation: "Run `opencyber-poc authorize` on the host with OPENCYBER_APPROVAL_KEY set.",
	},
	{
		Code:        CodeAuthorizationInvalid,
		Category:    CategoryDenied,
		Retryable:   false,
		Summary:     "The signed authorization is invalid, expired, or does not cover this action.",
		Remediation: "Re-run `opencyber-poc authorize` for the current engagement and technique set.",
	},
	{
		Code:        CodeApprovalInvalid,
		Category:    CategoryDenied,
		Retryable:   false,
		Summary:     "The single-use run approval is missing, consumed, expired, or does not match.",
		Remediation: "Mint a new approval with `opencyber-poc approve` for this exact spec and code hash.",
	},
	{
		Code:        CodeCapabilityUnavailable,
		Category:    CategoryUnavailable,
		Retryable:   false,
		Summary:     "A capability this tool needs is not present in this deployment.",
		Remediation: "Inspect oc_doctor for the failing capability and use an operator-managed image that provides it.",
	},
	{
		Code:        CodeIntegrationUnavailable,
		Category:    CategoryUnavailable,
		Retryable:   false,
		Summary:     "The executable backing this tool is not installed or lacks a dependency.",
		Remediation: "Install the integration and its dependencies in the operator-managed image, then restart.",
	},
	{
		Code:        CodeOfflineBlocked,
		Category:    CategoryUnavailable,
		Retryable:   false,
		Summary:     "Offline mode refuses this internet-dependent operation.",
		Remediation: "Unset OPENCYBER_OFFLINE, or use an offline data source such as the local CVE index.",
	},
	{
		Code:        CodeNotFound,
		Category:    CategoryNotFound,
		Retryable:   false,
		Summary:     "The named object does not exist in this engagement.",
		Remediation: "List the owning collection first and use an identifier it returns.",
	},
	{
		Code:        CodeAlreadyExists,
		Category:    CategoryConflict,
		Retryable:   false,
		Summary:     "The target already exists and this operation never overwrites.",
		Remediation: "Choose another name or path, or inspect the existing object first.",
	},
	{
		Code:        CodeConflict,
		Category:    CategoryConflict,
		Retryable:   false,
		Summary:     "The request contradicts current state, such as a hash or revision mismatch.",
		Remediation: "Re-read the current state, then repeat the call with the current identifiers.",
	},
	{
		Code:        CodeIntegrityMismatch,
		Category:    CategoryIntegrityMismatch,
		Retryable:   false,
		Summary:     "Stored hashes or the audit chain do not match the recorded value.",
		Remediation: "Treat the artifact as untrusted; re-export it and compare against a separately retained digest.",
	},
	{
		Code:        CodeTruncated,
		Category:    CategoryTruncated,
		Retryable:   true,
		Summary:     "The complete result could not be returned and the partial result is unusable.",
		Remediation: "Raise the named limit or narrow the request, then repeat the call.",
	},
	{
		Code:        CodeTimedOut,
		Category:    CategoryTimeout,
		Retryable:   true,
		Summary:     "The operation exceeded its deadline and was stopped.",
		Remediation: "Raise the named deadline, narrow the request, or run the scan as a background artifact.",
	},
	{
		Code:        CodeCancelled,
		Category:    CategoryCancelled,
		Retryable:   true,
		Summary:     "The caller cancelled the operation.",
		Remediation: "Repeat the call if the work is still wanted; partial side effects may remain.",
	},
	{
		Code:        CodeResourceConstraint,
		Category:    CategoryResourceConstraint,
		Retryable:   true,
		Summary:     "A named size, count, or request ceiling ended the operation early.",
		Remediation: "Use the limit facts in this error to raise the ceiling or narrow the request.",
	},
	{
		Code:        CodeLimitExceeded,
		Category:    CategoryResourceConstraint,
		Retryable:   true,
		Summary:     "The request exceeded a named ceiling and nothing ran.",
		Remediation: "Use the limit facts in this error to raise the ceiling or narrow the request.",
	},
	{
		Code:        CodeConnectionFailed,
		Category:    CategoryUnavailable,
		Retryable:   true,
		Summary:     "A network connection to the named endpoint failed.",
		Remediation: "Confirm the endpoint is reachable from the container and that the engagement scopes it.",
	},
	{
		Code:        CodeExecutionFailed,
		Category:    CategoryExecutionFailure,
		Retryable:   true,
		Summary:     "The operation ran but did not complete successfully.",
		Remediation: "Read the captured diagnostics; correct the input before repeating the call.",
	},
	{
		Code:        CodeChildFailed,
		Category:    CategoryExecutionFailure,
		Retryable:   true,
		Summary:     "The child process exited non-zero.",
		Remediation: "Read stderr and the exit code; many tools use non-zero exits for partial findings.",
	},
	{
		Code:        CodeInternalError,
		Category:    CategoryInternal,
		Retryable:   false,
		Summary:     "The server hit an unexpected condition. This is a harness bug.",
		Remediation: "Report the tool name and exception type with a reproduction; do not retry blindly.",
	},
}

var errorRegistry map[string]ErrorSpec

func init() {
	errorRegistry = make(map[string]ErrorSpec, len(errorSpecs))
	for _, spec := range errorSpecs {
		if _, dup := errorRegistry[spec.Code]; dup {
			panic("duplicate error code in OpenCyber error registry: " + spec.Code)
		}
		errorRegistry[spec.Code] = spec
	}
}

// LookupCode returns the registered ErrorSpec for code.
func LookupCode(code string) (ErrorSpec, bool) {
	spec, ok := errorRegistry[code]
	return spec, ok
}

// ErrorCodes returns a shallow copy of the registered error code table.
func ErrorCodes() map[string]ErrorSpec {
	out := make(map[string]ErrorSpec, len(errorRegistry))
	for k, v := range errorRegistry {
		out[k] = v
	}
	return out
}

// CodeDescription is one sorted, documentation-ready row from DescribeCodes.
type CodeDescription struct {
	Code        string `json:"code"`
	Category    string `json:"category"`
	Retryable   string `json:"retryable"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
}

// DescribeCodes returns the error registry as sorted, serializable rows.
func DescribeCodes() []CodeDescription {
	rows := make([]CodeDescription, 0, len(errorSpecs))
	for _, spec := range errorSpecs {
		retry := "no"
		if spec.Retryable {
			retry = "yes"
		}
		rows = append(rows, CodeDescription{
			Code:        spec.Code,
			Category:    string(spec.Category),
			Retryable:   retry,
			Summary:     spec.Summary,
			Remediation: spec.Remediation,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Code < rows[j].Code })
	return rows
}

// ErrorSchema returns the JSON Schema (draft 2020-12) for the serialized Error object.
func ErrorSchema() map[string]any {
	codes := make([]string, 0, len(errorRegistry))
	for code := range errorRegistry {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	categories := make([]string, 0, len(allCategories))
	for _, cat := range allCategories {
		categories = append(categories, string(cat))
	}
	sort.Strings(categories)

	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "https://github.com/mitkox/opencyber/schemas/error-contract.schema.json",
		"title":   "OpenCyber tool error",
		"description": "A refusal returned in a tool result. Codes are a closed set; category, " +
			"retryable, and remediation are always present so a client never parses prose.",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"code", "category", "message", "retryable", "remediation"},
		"properties": map[string]any{
			"code":      map[string]any{"type": "string", "enum": codes},
			"category":  map[string]any{"type": "string", "enum": categories},
			"message":   map[string]any{"type": "string", "minLength": 1},
			"retryable": map[string]any{"type": "boolean"},
			"remediation": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"action"},
				"properties": map[string]any{
					"action": map[string]any{"type": "string", "minLength": 1},
				},
			},
			"limit":   map[string]any{"type": []string{"object", "null"}},
			"details": map[string]any{"type": "object"},
		},
	}
}

// Remediation holds the concrete recovery action for an Error.
type Remediation struct {
	Action string `json:"action"`
}

// Error is a machine-actionable refusal matching the OpenCyber error contract.
type Error struct {
	Code        string         `json:"code"`
	Category    ErrorCategory  `json:"category"`
	Message     string         `json:"message"`
	Retryable   bool           `json:"retryable"`
	Remediation Remediation    `json:"remediation"`
	Limit       *LimitFacts    `json:"limit"`
	Details     map[string]any `json:"details"`
	cause       error
}

// Error implements the standard error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Hint returns the human- and machine-actionable remediation action.
func (e *Error) Hint() string {
	if e == nil {
		return ""
	}
	return e.Remediation.Action
}

// Retriable reports whether the caller may retry this refusal.
func (e *Error) Retriable() bool {
	return e != nil && e.Retryable
}

// ToMap serializes the refusal into the stable JSON map wire shape with deep copies.
func (e *Error) ToMap() map[string]any {
	if e == nil {
		return nil
	}
	var limitVal any
	if e.Limit != nil {
		limitVal = e.Limit.ToMap()
	}
	return map[string]any{
		"code":        e.Code,
		"category":    string(e.Category),
		"message":     e.Message,
		"retryable":   e.Retryable,
		"remediation": map[string]any{"action": e.Remediation.Action},
		"limit":       limitVal,
		"details":     deepCopyMap(e.Details),
	}
}

// Option configures an Error during construction.
type Option func(*Error)

// WithDetails merges a deep copy of details into the error's Details map.
func WithDetails(details map[string]any) Option {
	return func(e *Error) {
		if len(details) == 0 {
			return
		}
		if e.Details == nil {
			e.Details = make(map[string]any, len(details))
		}
		for k, v := range details {
			e.Details[k] = deepCopyValue(v)
		}
	}
}

// WithDetail sets a single key/value pair (deep-copied) in Details.
func WithDetail(key string, value any) Option {
	return func(e *Error) {
		if e.Details == nil {
			e.Details = make(map[string]any)
		}
		e.Details[key] = deepCopyValue(value)
	}
}

// WithLimit attaches a copy of limit facts to the error.
func WithLimit(limit *LimitFacts) Option {
	return func(e *Error) {
		if limit == nil {
			e.Limit = nil
			return
		}
		e.Limit = limit.Clone()
	}
}

// WithRemediation overrides the default remediation action text.
func WithRemediation(action string) Option {
	return func(e *Error) {
		if strings.TrimSpace(action) != "" {
			e.Remediation = Remediation{Action: action}
		}
	}
}

// WithHint is an alias for WithRemediation.
func WithHint(hint string) Option {
	return WithRemediation(hint)
}

// WithRetryable overrides the registry default retryable flag.
func WithRetryable(retryable bool) Option {
	return func(e *Error) {
		e.Retryable = retryable
	}
}

// WithCause wraps an underlying error for errors.Is / errors.As traversal.
func WithCause(err error) Option {
	return func(e *Error) {
		e.cause = err
	}
}

// NewStrict constructs an Error and fails closed if code is unregistered or message is empty.
func NewStrict(code, message string, opts ...Option) (*Error, error) {
	spec, ok := errorRegistry[code]
	if !ok {
		return nil, fmt.Errorf("unregistered OpenCyber error code: %s", code)
	}
	if message == "" {
		return nil, fmt.Errorf("an OpenCyber Error message must be a non-empty string")
	}
	return buildError(spec, message, opts...), nil
}

// New constructs a registered Error. Unknown codes fall back to internal_error
// with the original code recorded in details, and empty messages default to the
// registered summary so runtime call sites never panic or emit malformed refusals.
func New(code, message string, opts ...Option) *Error {
	spec, ok := errorRegistry[code]
	if !ok {
		orig := code
		spec = errorRegistry[CodeInternalError]
		if message == "" {
			message = fmt.Sprintf("unregistered OpenCyber error code: %s", orig)
		}
		opts = append([]Option{WithDetail("unregistered_code", orig)}, opts...)
	} else if message == "" {
		message = spec.Summary
	}
	return buildError(spec, message, opts...)
}

func buildError(spec ErrorSpec, message string, opts ...Option) *Error {
	err := &Error{
		Code:        spec.Code,
		Category:    spec.Category,
		Message:     message,
		Retryable:   spec.Retryable,
		Remediation: Remediation{Action: spec.Remediation},
		Details:     map[string]any{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(err)
		}
	}
	return err
}

// LimitExceeded builds a limit_exceeded refusal carrying named limit facts.
func LimitExceeded(limit *LimitFacts, message string, details map[string]any) *Error {
	return New(CodeLimitExceeded, message, WithLimit(limit), WithDetails(details))
}

// Internal wraps an unexpected Go error as internal_error without inventing a cause.
func Internal(err error) *Error {
	if err == nil {
		return New(CodeInternalError, "unexpected internal error")
	}
	typeName := errorTypeName(err)
	return New(
		CodeInternalError,
		fmt.Sprintf("unexpected %s: %v", typeName, err),
		WithDetail("exception", typeName),
		WithCause(err),
	)
}

// Translate maps an arbitrary Go error onto the registered contract.
//
// If err represents cancellation (context.Canceled), Translate returns (nil, true)
// so callers can propagate cancellation rather than reporting a failed tool.
func Translate(err error) (ocErr *Error, cancelled bool) {
	if err == nil {
		return nil, false
	}
	var existing *Error
	if stderrors.As(err, &existing) {
		return existing, false
	}
	if stderrors.Is(err, context.Canceled) {
		return nil, true
	}
	if stderrors.Is(err, context.DeadlineExceeded) || stderrors.Is(err, os.ErrDeadlineExceeded) {
		msg := err.Error()
		if msg == "" {
			msg = "operation timed out"
		}
		return New(CodeTimedOut, msg, WithCause(err)), false
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		if netErr.Timeout() {
			return New(CodeTimedOut, err.Error(), WithCause(err)), false
		}
		return New(CodeConnectionFailed, err.Error(), WithCause(err)), false
	}
	if stderrors.Is(err, os.ErrNotExist) {
		return New(CodeNotFound, err.Error(), WithCause(err)), false
	}
	if stderrors.Is(err, os.ErrExist) {
		return New(CodeAlreadyExists, err.Error(), WithCause(err)), false
	}
	if stderrors.Is(err, os.ErrPermission) {
		return New(CodePermissionDenied, err.Error(), WithCause(err)), false
	}
	var pathErr *os.PathError
	var linkErr *os.LinkError
	var sysErr *os.SyscallError
	if stderrors.As(err, &pathErr) || stderrors.As(err, &linkErr) || stderrors.As(err, &sysErr) {
		return New(
			CodeExecutionFailed,
			err.Error(),
			WithDetail("exception", errorTypeName(err)),
			WithCause(err),
		), false
	}
	return Internal(err), false
}

// CodeOf returns the registered OpenCyber error code if err wraps *Error, or "".
func CodeOf(err error) string {
	var ocErr *Error
	if stderrors.As(err, &ocErr) {
		return ocErr.Code
	}
	return ""
}

// IsCode reports whether err wraps an *Error with the specified code.
func IsCode(err error, code string) bool {
	return CodeOf(err) == code
}

func errorTypeName(err error) string {
	if err == nil {
		return "error"
	}
	t := reflect.TypeOf(err)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Name() != "" {
		return t.Name()
	}
	return t.String()
}

func deepCopyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = deepCopyValue(v)
	}
	return dst
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = deepCopyValue(item)
		}
		return out
	case []string:
		out := make([]string, len(val))
		copy(out, val)
		return out
	case []int:
		out := make([]int, len(val))
		copy(out, val)
		return out
	case []float64:
		out := make([]float64, len(val))
		copy(out, val)
		return out
	default:
		return v
	}
}

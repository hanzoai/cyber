package errors

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// LimitSource identifies who can change a named ceiling.
type LimitSource string

const (
	LimitSourceArgument    LimitSource = "argument"
	LimitSourceEnvironment LimitSource = "environment"
	LimitSourceFixed       LimitSource = "fixed"
)

// Limit defines one named operational ceiling, its bounds, and its recovery guidance.
type Limit struct {
	ID           string      `json:"id"`
	Unit         string      `json:"unit"`
	Description  string      `json:"description"`
	Default      float64     `json:"default"`
	Minimum      *float64    `json:"minimum"`
	Maximum      *float64    `json:"maximum"`
	Source       LimitSource `json:"source"`
	AppliesTo    []string    `json:"applies_to"`
	Recovery     string      `json:"recovery"`
	DoesNotRaise string      `json:"does_not_raise"`
	Env          string      `json:"setting,omitempty"`
	Parameter    string      `json:"parameter,omitempty"`
}

// LimitFacts captures the enforced value, requested value, and recovery facts for one decision.
type LimitFacts struct {
	ID           string      `json:"id"`
	Unit         string      `json:"unit"`
	Effective    float64     `json:"effective"`
	Requested    *float64    `json:"requested"`
	Default      float64     `json:"default"`
	Minimum      *float64    `json:"minimum"`
	Maximum      *float64    `json:"maximum"`
	Source       LimitSource `json:"source"`
	Setting      *string     `json:"setting"`
	Parameter    *string     `json:"parameter"`
	Recovery     string      `json:"recovery"`
	DoesNotRaise string      `json:"does_not_raise"`
}

// Clone returns a deep copy of LimitFacts.
func (f *LimitFacts) Clone() *LimitFacts {
	if f == nil {
		return nil
	}
	cp := *f
	cp.Requested = cloneFloatPtr(f.Requested)
	cp.Minimum = cloneFloatPtr(f.Minimum)
	cp.Maximum = cloneFloatPtr(f.Maximum)
	cp.Setting = cloneStringPtr(f.Setting)
	cp.Parameter = cloneStringPtr(f.Parameter)
	return &cp
}

// ToMap renders LimitFacts into a JSON-compatible map matching limits.py wire shape
// (whole numbers rendered as int64 rather than float64).
func (f *LimitFacts) ToMap() map[string]any {
	if f == nil {
		return nil
	}
	var req any
	if f.Requested != nil {
		req = cleanNumber(*f.Requested)
	}
	var minVal any
	if f.Minimum != nil {
		minVal = cleanNumber(*f.Minimum)
	}
	var maxVal any
	if f.Maximum != nil {
		maxVal = cleanNumber(*f.Maximum)
	}
	var setting any
	if f.Setting != nil {
		setting = *f.Setting
	}
	var param any
	if f.Parameter != nil {
		param = *f.Parameter
	}
	return map[string]any{
		"id":             f.ID,
		"unit":           f.Unit,
		"effective":      cleanNumber(f.Effective),
		"requested":      req,
		"default":        cleanNumber(f.Default),
		"minimum":        minVal,
		"maximum":        maxVal,
		"source":         string(f.Source),
		"setting":        setting,
		"parameter":      param,
		"recovery":       f.Recovery,
		"does_not_raise": f.DoesNotRaise,
	}
}

// DocumentEffective resolves the documented default, honoring any environment override.
// Unparseable, non-finite, or out-of-bounds environment values fail closed with invalid_argument.
func (l Limit) DocumentEffective() (float64, error) {
	if l.Source != LimitSourceEnvironment || l.Env == "" {
		return l.Default, nil
	}
	raw := strings.TrimSpace(os.Getenv(l.Env))
	if raw == "" {
		return l.Default, nil
	}
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, New(
			CodeInvalidArgument,
			fmt.Sprintf("%s must be a number of %s, got %q", l.Env, l.Unit, raw),
			WithDetails(map[string]any{"setting": l.Env, "limit": l.ID}),
			WithRemediation(fmt.Sprintf("Set %s to a number between %s or unset it.", l.Env, l.boundsText())),
		)
	}
	if !l.inBounds(val) {
		return 0, New(
			CodeInvalidArgument,
			fmt.Sprintf("%s must be between %s, got %g", l.Env, l.boundsText(), val),
			WithDetails(map[string]any{"setting": l.Env, "limit": l.ID}),
			WithRemediation(fmt.Sprintf("Set %s to a number between %s or unset it.", l.Env, l.boundsText())),
		)
	}
	return val, nil
}

// Facts builds the LimitFacts object for one enforced ceiling decision.
func (l Limit) Facts(effective *float64, requested *float64, parameter string) (*LimitFacts, error) {
	var resolved float64
	if effective == nil {
		var err error
		resolved, err = l.DocumentEffective()
		if err != nil {
			return nil, err
		}
	} else {
		resolved = *effective
	}
	var settingPtr *string
	if l.Env != "" {
		s := l.Env
		settingPtr = &s
	}
	var paramPtr *string
	if parameter != "" {
		p := parameter
		paramPtr = &p
	} else if l.Parameter != "" {
		p := l.Parameter
		paramPtr = &p
	}
	return &LimitFacts{
		ID:           l.ID,
		Unit:         l.Unit,
		Effective:    resolved,
		Requested:    cloneFloatPtr(requested),
		Default:      l.Default,
		Minimum:      cloneFloatPtr(l.Minimum),
		Maximum:      cloneFloatPtr(l.Maximum),
		Source:       l.Source,
		Setting:      settingPtr,
		Parameter:    paramPtr,
		Recovery:     l.Recovery,
		DoesNotRaise: l.DoesNotRaise,
	}, nil
}

func (l Limit) inBounds(v float64) bool {
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

func (l Limit) boundsText() string {
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

func cleanNumber(v float64) any {
	if !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v && v >= math.MinInt64 && v <= math.MaxInt64 {
		return int64(v)
	}
	return v
}

func floatPtr(v float64) *float64 { return &v }

func cloneFloatPtr(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

var registeredLimits = []Limit{
	{
		ID:           "triage.max_bytes",
		Unit:         "bytes",
		Description:  "Bytes inspected from a supplied file, log, or capture.",
		Default:      16777216,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(268435456),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_file_triage", "oc_log_timeline", "oc_pcap_triage"},
		Recovery:     "Pass a larger max_bytes value in the same call.",
		DoesNotRaise: "The source file's own size on disk.",
		Parameter:    "max_bytes",
	},
	{
		ID:           "triage.max_records",
		Unit:         "records",
		Description:  "Timeline records returned from a log.",
		Default:      10000,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(1000000),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_log_timeline"},
		Recovery:     "Pass a larger max_records value or narrow the time window.",
		DoesNotRaise: "The number of records present in the source.",
		Parameter:    "max_records",
	},
	{
		ID:           "triage.max_packets",
		Unit:         "packets",
		Description:  "Packets examined in a capture.",
		Default:      10000,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(1000000),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_pcap_triage"},
		Recovery:     "Pass a larger max_packets value or pre-filter the capture.",
		DoesNotRaise: "The number of packets present in the capture.",
		Parameter:    "max_packets",
	},
	{
		ID:           "workspace.read_max_bytes",
		Unit:         "bytes",
		Description:  "Bytes returned by one workspace read.",
		Default:      1048576,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(67108864),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_workspace_read"},
		Recovery:     "Pass a larger max_bytes value, or page with the returned offset.",
		DoesNotRaise: "The client's own response or context budget.",
		Parameter:    "max_bytes",
	},
	{
		ID:           "audit.read_limit",
		Unit:         "events",
		Description:  "Audit events returned by one read.",
		Default:      100,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(1000),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_audit_log"},
		Recovery:     "Page with the returned offset or reduce the request size.",
		DoesNotRaise: "The number of events retained for the engagement.",
		Parameter:    "limit",
	},
	{
		ID:           "audit.max_events",
		Unit:         "events",
		Description:  "Retained audit events available to one read.",
		Default:      5000,
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"oc_audit_log", "oc_audit_verify"},
		Recovery:     "Export the audit trail and read it outside the tool.",
		DoesNotRaise: "Events already written; they remain on disk.",
	},
	{
		ID:           "evidence.max_files",
		Unit:         "files",
		Description:  "Files selected into one evidence bundle.",
		Default:      10000,
		Minimum:      floatPtr(1),
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"oc_evidence_export"},
		Recovery:     "Export in several bundles and retain each archive digest.",
		DoesNotRaise: "Files present in the engagement workspace.",
	},
	{
		ID:           "evidence.max_manifest_bytes",
		Unit:         "bytes",
		Description:  "Manifest size for one evidence bundle.",
		Default:      8388608,
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"oc_evidence_export", "oc_evidence_verify"},
		Recovery:     "Export fewer paths per bundle.",
		DoesNotRaise: "The size of the files being exported.",
	},
	{
		ID:           "http.response_max_bytes",
		Unit:         "bytes",
		Description:  "Decompressed response body bytes retained by one native HTTP request, including redirect responses.",
		Default:      262144,
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"oc_http_request"},
		Recovery:     "Request a smaller resource or use server-supported Range requests to retrieve specific bytes.",
		DoesNotRaise: "HTTP headers, other HTTP tools, or the envelope evidence ceiling.",
	},
	{
		ID:          "http.timeout",
		Unit:        "seconds",
		Description: "Deadline for one native HTTP request.",
		Default:     30,
		Minimum:     floatPtr(0),
		Maximum:     floatPtr(300),
		Source:      LimitSourceEnvironment,
		Env:         "OPENCYBER_HTTP_TIMEOUT",
		AppliesTo: []string{
			"oc_http_request",
			"oc_graphql_request",
			"oc_openapi_inspect",
			"oc_hibp_password_check",
			"oc_cve_lookup",
		},
		Recovery:     "Pass a per-call timeout, or raise OPENCYBER_HTTP_TIMEOUT up to 300 seconds.",
		DoesNotRaise: "The server's own deadline for executable-backed tools.",
	},
	{
		ID:           "serial.read_max_bytes",
		Unit:         "bytes",
		Description:  "Bytes returned by one serial read.",
		Default:      4096,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(65536),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_serial_read"},
		Recovery:     "Pass a larger max_bytes value or read again.",
		DoesNotRaise: "The bytes already buffered on the device.",
		Parameter:    "max_bytes",
	},
	{
		ID:           "serial.read_timeout",
		Unit:         "seconds",
		Description:  "Blocking window for one serial read.",
		Default:      1,
		Minimum:      floatPtr(0),
		Maximum:      floatPtr(30),
		Source:       LimitSourceArgument,
		AppliesTo:    []string{"oc_serial_read"},
		Recovery:     "Pass a larger timeout value or poll again.",
		DoesNotRaise: "The device's own response time.",
		Parameter:    "timeout",
	},
	{
		ID:           "poc.max_requests",
		Unit:         "requests",
		Description:  "Requests one approved PoC run may send.",
		Default:      20,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(20),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_POC_MAX_REQUESTS",
		AppliesTo:    []string{"oc_poc_run"},
		Recovery:     "Lower the spec limit; the environment cannot raise the hard ceiling.",
		DoesNotRaise: "The evidence-to-claim requirement of the engagement.",
	},
	{
		ID:           "poc.timeout_s",
		Unit:         "seconds",
		Description:  "Deadline for one approved PoC run.",
		Default:      60,
		Minimum:      floatPtr(1),
		Maximum:      floatPtr(60),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_POC_TIMEOUT",
		AppliesTo:    []string{"oc_poc_run"},
		Recovery:     "Lower the spec timeout; the environment cannot raise the hard ceiling.",
		DoesNotRaise: "The client's own request deadline.",
	},
	{
		ID:           "poc.max_bytes",
		Unit:         "bytes",
		Description:  "Response bytes one PoC run may retain.",
		Default:      1048576,
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"oc_poc_run"},
		Recovery:     "Narrow the assertions or the request set.",
		DoesNotRaise: "The target's response size.",
	},
	{
		ID:           "tool.timeout_s",
		Unit:         "seconds",
		Description:  "Deadline for one executable-backed tool call.",
		Default:      1800,
		Minimum:      floatPtr(0),
		Maximum:      floatPtr(86400),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_TOOL_TIMEOUT_S",
		AppliesTo:    []string{"*"},
		Recovery:     "Raise OPENCYBER_TOOL_TIMEOUT_S, or set it to 0 to run without a server deadline.",
		DoesNotRaise: "The client's own cancellation or request deadline.",
	},
	{
		ID:           "tool.max_output_bytes",
		Unit:         "bytes",
		Description:  "Output retained per stream from one executable-backed tool call.",
		Default:      4194304,
		Minimum:      floatPtr(0),
		Maximum:      floatPtr(268435456),
		Source:       LimitSourceEnvironment,
		Env:          "OPENCYBER_TOOL_MAX_OUTPUT_BYTES",
		AppliesTo:    []string{"*"},
		Recovery:     "Raise OPENCYBER_TOOL_MAX_OUTPUT_BYTES, or redirect the tool's output to an engagement file.",
		DoesNotRaise: "The child process's own write path; the excess is read and discarded.",
	},
	{
		ID:           "envelope.evidence_max_bytes",
		Unit:         "bytes",
		Description:  "Result size above which no evidence digest is computed.",
		Default:      4194304,
		Source:       LimitSourceFixed,
		AppliesTo:    []string{"*"},
		Recovery:     "Request a smaller page or inspect the persisted artifact instead.",
		DoesNotRaise: "The result itself; it is still returned.",
	},
}

var limitRegistry map[string]Limit

func init() {
	limitRegistry = make(map[string]Limit, len(registeredLimits))
	for _, lim := range registeredLimits {
		if _, dup := limitRegistry[lim.ID]; dup {
			panic("duplicate limit id in OpenCyber limit registry: " + lim.ID)
		}
		limitRegistry[lim.ID] = lim
	}
}

// LimitFor returns the registered Limit by ID.
func LimitFor(id string) (Limit, bool) {
	lim, ok := limitRegistry[id]
	if !ok {
		return Limit{}, false
	}
	lim.AppliesTo = append([]string(nil), lim.AppliesTo...)
	lim.Minimum = cloneFloatPtr(lim.Minimum)
	lim.Maximum = cloneFloatPtr(lim.Maximum)
	return lim, true
}

// Limits returns a copy of all registered limits keyed by ID.
func Limits() map[string]Limit {
	out := make(map[string]Limit, len(limitRegistry))
	for id := range limitRegistry {
		lim, _ := LimitFor(id)
		out[id] = lim
	}
	return out
}

// FactsFor builds LimitFacts for a registered limit ID.
func FactsFor(limitID string, effective *float64, requested *float64, parameter string) (*LimitFacts, error) {
	lim, ok := limitRegistry[limitID]
	if !ok {
		return nil, fmt.Errorf("no registered limit: %s", limitID)
	}
	return lim.Facts(effective, requested, parameter)
}

// RaiseExceeded builds a limit_exceeded *Error populated with the named limit's facts.
func RaiseExceeded(limitID, message string, effective *float64, requested *float64, parameter string, details map[string]any) *Error {
	facts, err := FactsFor(limitID, effective, requested, parameter)
	if err != nil {
		return New(CodeLimitExceeded, message, WithDetails(details), WithCause(err))
	}
	return LimitExceeded(facts, message, details)
}

// LimitDescription is one sorted, serializable row from DescribeLimits.
type LimitDescription struct {
	ID           string `json:"id"`
	Unit         string `json:"unit"`
	Description  string `json:"description"`
	Default      any    `json:"default"`
	Minimum      any    `json:"minimum"`
	Maximum      any    `json:"maximum"`
	Source       string `json:"source"`
	Setting      string `json:"setting"`
	AppliesTo    string `json:"applies_to"`
	Recovery     string `json:"recovery"`
	DoesNotRaise string `json:"does_not_raise"`
}

// DescribeLimits returns the limit registry sorted by ID for documentation and diagnostics.
func DescribeLimits() []LimitDescription {
	rows := make([]LimitDescription, 0, len(registeredLimits))
	for _, lim := range registeredLimits {
		var minVal, maxVal any
		if lim.Minimum != nil {
			minVal = cleanNumber(*lim.Minimum)
		}
		if lim.Maximum != nil {
			maxVal = cleanNumber(*lim.Maximum)
		}
		rows = append(rows, LimitDescription{
			ID:           lim.ID,
			Unit:         lim.Unit,
			Description:  lim.Description,
			Default:      cleanNumber(lim.Default),
			Minimum:      minVal,
			Maximum:      maxVal,
			Source:       string(lim.Source),
			Setting:      lim.Env,
			AppliesTo:    strings.Join(lim.AppliesTo, ", "),
			Recovery:     lim.Recovery,
			DoesNotRaise: lim.DoesNotRaise,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
}

// LimitSettings returns all environment-backed limits keyed by environment variable name.
func LimitSettings() map[string]Limit {
	out := make(map[string]Limit)
	for _, lim := range registeredLimits {
		if lim.Env != "" {
			cp, _ := LimitFor(lim.ID)
			out[lim.Env] = cp
		}
	}
	return out
}

// EffectiveTimeout resolves a seconds-unit limit to a time.Duration (0 means no deadline).
func EffectiveTimeout(limitID string) (time.Duration, error) {
	lim, ok := limitRegistry[limitID]
	if !ok {
		return 0, fmt.Errorf("no registered limit: %s", limitID)
	}
	secs, err := lim.DocumentEffective()
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// EffectiveMaxBytes resolves a bytes-unit limit to an integer byte ceiling.
func EffectiveMaxBytes(limitID string) (int64, error) {
	lim, ok := limitRegistry[limitID]
	if !ok {
		return 0, fmt.Errorf("no registered limit: %s", limitID)
	}
	val, err := lim.DocumentEffective()
	if err != nil {
		return 0, err
	}
	return int64(val), nil
}

// ConcurrencyLimiter bounds simultaneous operations using a non-blocking or
// context-aware semaphore.
type ConcurrencyLimiter struct {
	sem    chan struct{}
	active atomic.Int64
}

// NewConcurrencyLimiter creates a limiter allowing up to maxConcurrent active holders.
// Values <= 0 clamp to 1.
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &ConcurrencyLimiter{
		sem: make(chan struct{}, maxConcurrent),
	}
}

// Max returns the configured maximum concurrency.
func (c *ConcurrencyLimiter) Max() int {
	return cap(c.sem)
}

// Active returns the current number of acquired slots.
func (c *ConcurrencyLimiter) Active() int {
	return int(c.active.Load())
}

// Acquire blocks until a slot is available or ctx is cancelled, returning an idempotent release function.
func (c *ConcurrencyLimiter) Acquire(ctx context.Context) (func(), error) {
	select {
	case c.sem <- struct{}{}:
		c.active.Add(1)
		var released atomic.Bool
		return func() {
			if released.CompareAndSwap(false, true) {
				c.active.Add(-1)
				<-c.sem
			}
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TryAcquire acquires a slot without blocking, returning (release, true) on success.
func (c *ConcurrencyLimiter) TryAcquire() (func(), bool) {
	select {
	case c.sem <- struct{}{}:
		c.active.Add(1)
		var released atomic.Bool
		return func() {
			if released.CompareAndSwap(false, true) {
				c.active.Add(-1)
				<-c.sem
			}
		}, true
	default:
		return nil, false
	}
}

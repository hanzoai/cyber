package errors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	// EnvelopeSchemaVersion is the wire schema version of the uniform tool envelope.
	EnvelopeSchemaVersion = 1

	// DefaultContractSchemaVersion is used when ContractMeta.ContractSchemaVersion is unset.
	DefaultContractSchemaVersion = 1

	// MaxEvidenceBytes is the size above which no evidence digest is computed.
	MaxEvidenceBytes = 4 * 1024 * 1024

	// EvidencePrefix is the prefix applied to every content-addressed evidence ID.
	EvidencePrefix = "oc_ev_"
)

// ContractMeta carries the minimal tool contract metadata needed to build an envelope
// without creating an import cycle with pkg/catalog.
type ContractMeta struct {
	Name                  string
	ReturnsTargetContent  bool
	ProvenanceSource      string
	ContractSchemaVersion int
}

// ContractBlock identifies which tool and schema versions produced an envelope.
type ContractBlock struct {
	SchemaVersion         int    `json:"schema_version"`
	ContractSchemaVersion int    `json:"contract_schema_version"`
	Tool                  string `json:"tool"`
	ServerVersion         string `json:"server_version"`
}

// Provenance marks whether returned content comes from an untrusted target.
type Provenance struct {
	UntrustedContent bool   `json:"untrusted_content"`
	Source           string `json:"source"`
}

// Continuation gives a caller the exact follow-up tool invocation for paged results.
type Continuation struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// Evidence identifies the exact serialized payload returned to the caller.
type Evidence struct {
	ID             *string `json:"id"`
	SHA256         *string `json:"sha256"`
	Bytes          *int    `json:"bytes"`
	Retained       bool    `json:"retained"`
	Reason         string  `json:"reason,omitempty"`
	RetentionError string  `json:"retention_error,omitempty"`
}

// Envelope is the uniform typed response returned by every Hanzo Cyber tool.
type Envelope[T any] struct {
	OK           bool          `json:"ok"`
	Data         T             `json:"data,omitempty"`
	Error        *Error        `json:"error,omitempty"`
	Contract     ContractBlock `json:"contract"`
	Coverage     Coverage      `json:"coverage"`
	Limitations  []string      `json:"limitations"`
	Provenance   Provenance    `json:"provenance"`
	Continuation *Continuation `json:"continuation"`
	Evidence     Evidence      `json:"evidence"`
}

// EnvelopeOption customizes an Envelope[T] before its evidence digest is computed.
type EnvelopeOption[T any] func(*Envelope[T])

// WithEnvelopeCoverage sets an explicit Coverage declaration on the envelope.
func WithEnvelopeCoverage[T any](cov Coverage) EnvelopeOption[T] {
	return func(e *Envelope[T]) {
		e.Coverage = NormalizeCoverage(&cov, false)
	}
}

// WithEnvelopeLimitations sets explicit limitation disclosures on the envelope.
func WithEnvelopeLimitations[T any](limitations []string) EnvelopeOption[T] {
	return func(e *Envelope[T]) {
		if limitations == nil {
			e.Limitations = []string{}
			return
		}
		e.Limitations = append([]string(nil), limitations...)
	}
}

// WithEnvelopeProvenance overrides the default provenance derived from ContractMeta.
func WithEnvelopeProvenance[T any](p Provenance) EnvelopeOption[T] {
	return func(e *Envelope[T]) {
		e.Provenance = p
	}
}

// WithEnvelopeContinuation attaches a pagination continuation hint.
func WithEnvelopeContinuation[T any](c *Continuation) EnvelopeOption[T] {
	return func(e *Envelope[T]) {
		e.Continuation = c
	}
}

// WithEnvelopeTruncated marks coverage partial when no explicit coverage was supplied.
func WithEnvelopeTruncated[T any](truncated bool) EnvelopeOption[T] {
	return func(e *Envelope[T]) {
		if truncated && e.Coverage.Status == CoverageComplete {
			e.Coverage.Status = CoveragePartial
		}
	}
}

// NewContractBlock builds the contract header for a tool.
func NewContractBlock(meta ContractMeta) ContractBlock {
	csv := meta.ContractSchemaVersion
	if csv <= 0 {
		csv = DefaultContractSchemaVersion
	}
	return ContractBlock{
		SchemaVersion:         EnvelopeSchemaVersion,
		ContractSchemaVersion: csv,
		Tool:                  meta.Name,
		ServerVersion:         Version,
	}
}

func defaultProvenance(meta ContractMeta) Provenance {
	src := meta.ProvenanceSource
	if src == "" {
		if meta.ReturnsTargetContent {
			src = "target"
		} else {
			src = "server"
		}
	}
	return Provenance{
		UntrustedContent: meta.ReturnsTargetContent,
		Source:           src,
	}
}

// CanonicalJSON renders v as deterministic compact UTF-8 JSON with sorted object
// keys and without HTML escaping, matching Python's
// json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func CanonicalJSON(v any) ([]byte, error) {
	normalized := v
	if !isPureCanonicalValue(v) {
		// Expand structs via their json tags, then decode with json.Number so every
		// object becomes map[string]any with lexicographically sorted keys at every depth.
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var decoded any
		if err := dec.Decode(&decoded); err != nil {
			return nil, err
		}
		normalized = decoded
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

func isPureCanonicalValue(v any) bool {
	switch val := v.(type) {
	case nil, bool, string, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return true
	case []string:
		return true
	case []any:
		for _, item := range val {
			if !isPureCanonicalValue(item) {
				return false
			}
		}
		return true
	case []map[string]any:
		for _, item := range val {
			if !isPureCanonicalValue(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, item := range val {
			if !isPureCanonicalValue(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// CanonicalSHA256 returns the lowercase hex SHA-256 of CanonicalJSON(v).
func CanonicalSHA256(v any) (string, error) {
	encoded, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeEvidence digests material (excluding any "evidence" key) up to maxBytes.
// If maxBytes <= 0, MaxEvidenceBytes is used.
func ComputeEvidence(material any, maxBytes int) Evidence {
	if maxBytes <= 0 {
		maxBytes = MaxEvidenceBytes
	}
	encoded, err := CanonicalJSON(material)
	if err != nil {
		return Evidence{
			Retained: false,
			Reason:   "result_not_serializable",
		}
	}
	n := len(encoded)
	if n > maxBytes {
		return Evidence{
			Bytes:    &n,
			Retained: false,
			Reason:   "result_too_large",
		}
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	id := EvidencePrefix + digest[:40]
	return Evidence{
		ID:       &id,
		SHA256:   &digest,
		Bytes:    &n,
		Retained: false,
	}
}

func evidenceForEnvelope[T any](env Envelope[T], maxBytes int) Evidence {
	raw, err := json.Marshal(env)
	if err != nil {
		return Evidence{Retained: false, Reason: "result_not_serializable"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return Evidence{Retained: false, Reason: "result_not_serializable"}
	}
	delete(m, "evidence")
	return ComputeEvidence(m, maxBytes)
}

// NewEnvelope wraps a successful typed tool result in a uniform Envelope[T].
func NewEnvelope[T any](meta ContractMeta, data T, opts ...EnvelopeOption[T]) Envelope[T] {
	env := Envelope[T]{
		OK:          true,
		Data:        data,
		Contract:    NewContractBlock(meta),
		Coverage:    Coverage{Status: CoverageComplete},
		Limitations: []string{},
		Provenance:  defaultProvenance(meta),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&env)
		}
	}
	if env.Limitations == nil {
		env.Limitations = []string{}
	}
	env.Evidence = evidenceForEnvelope(env, MaxEvidenceBytes)
	return env
}

// NewRefusal builds a typed failure Envelope[T] for a registered *Error.
func NewRefusal[T any](meta ContractMeta, err *Error, opts ...EnvelopeOption[T]) Envelope[T] {
	if err == nil {
		err = New(CodeInternalError, "unspecified refusal")
	}
	env := Envelope[T]{
		OK:          false,
		Error:       err,
		Contract:    NewContractBlock(meta),
		Coverage:    Coverage{Status: CoverageUnknown},
		Limitations: []string{"The tool did not run."},
		Provenance:  defaultProvenance(meta),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&env)
		}
	}
	if env.Limitations == nil {
		env.Limitations = []string{}
	}
	env.Evidence = evidenceForEnvelope(env, MaxEvidenceBytes)
	return env
}

// Wrap executes handler and guarantees every non-cancelled result or error is
// returned inside a uniform Envelope[T]. Context cancellation is returned as a
// Go error without producing a failed tool envelope.
func Wrap[T any](meta ContractMeta, handler func(context.Context) (T, error)) func(context.Context) (Envelope[T], error) {
	return func(ctx context.Context) (Envelope[T], error) {
		data, err := handler(ctx)
		if err != nil {
			ocErr, cancelled := Translate(err)
			if cancelled {
				return Envelope[T]{}, err
			}
			return NewRefusal[T](meta, ocErr), nil
		}
		return NewEnvelope(meta, data), nil
	}
}

// FinalizeMap applies the additive contract envelope to a map payload without
// removing any historical keys (matching envelope.py:finalize).
func FinalizeMap(meta ContractMeta, result map[string]any) map[string]any {
	return finalizeMapWithLimit(meta, result, MaxEvidenceBytes)
}

func finalizeMapWithLimit(meta ContractMeta, result map[string]any, maxEvidenceBytes int) map[string]any {
	payload := make(map[string]any, len(result)+7)
	for k, v := range result {
		payload[k] = v
	}

	okVal := true
	if rawOK, exists := payload["ok"]; exists && rawOK != nil {
		if b, isBool := rawOK.(bool); isBool {
			okVal = b
		}
	} else if rawSuccess, exists := payload["success"]; exists && rawSuccess != nil {
		if b, isBool := rawSuccess.(bool); isBool {
			okVal = b
		}
	}
	if rawErr, exists := payload["error"]; exists && rawErr != nil {
		okVal = false
	}
	payload["ok"] = okVal
	payload["contract"] = NewContractBlock(meta)

	truncated, _ := payload["truncated"].(bool)
	var cov Coverage
	if rawCov, exists := payload["coverage"]; exists && rawCov != nil {
		cov = coerceCoverage(rawCov, truncated)
	} else if !okVal {
		cov = MustCoverage(CoverageUnknown, WithExhausted(false))
	} else {
		cov = NormalizeCoverage(nil, truncated)
	}
	payload["coverage"] = cov.ToMap()

	if lims, ok := payload["limitations"].([]string); ok && lims != nil {
		payload["limitations"] = append([]string(nil), lims...)
	} else if limsAny, ok := payload["limitations"].([]any); ok && limsAny != nil {
		payload["limitations"] = append([]any(nil), limsAny...)
	} else {
		payload["limitations"] = []string{}
	}

	if _, exists := payload["provenance"]; !exists || payload["provenance"] == nil {
		p := defaultProvenance(meta)
		payload["provenance"] = map[string]any{
			"untrusted_content": p.UntrustedContent,
			"source":            p.Source,
		}
	}
	if _, exists := payload["continuation"]; !exists {
		payload["continuation"] = nil
	}

	material := make(map[string]any, len(payload))
	for k, v := range payload {
		if k != "evidence" {
			material[k] = v
		}
	}
	payload["evidence"] = ComputeEvidence(material, maxEvidenceBytes)
	return payload
}

// RefusalMap constructs an additive refusal map envelope matching envelope.py:refusal.
func RefusalMap(meta ContractMeta, err *Error, cov *Coverage, limitations []string) map[string]any {
	if err == nil {
		err = New(CodeInternalError, "unspecified refusal")
	}
	var c Coverage
	if cov != nil {
		c = NormalizeCoverage(cov, false)
	} else {
		c = Coverage{Status: CoverageUnknown}
	}
	lims := limitations
	if lims == nil {
		lims = []string{"The tool did not run."}
	}
	p := defaultProvenance(meta)
	payload := map[string]any{
		"ok":          false,
		"error":       err.ToMap(),
		"contract":    NewContractBlock(meta),
		"coverage":    c.ToMap(),
		"limitations": append([]string(nil), lims...),
		"provenance": map[string]any{
			"untrusted_content": p.UntrustedContent,
			"source":            p.Source,
		},
		"continuation": nil,
	}
	payload["evidence"] = ComputeEvidence(payload, MaxEvidenceBytes)
	return payload
}

func coerceCoverage(raw any, truncated bool) Coverage {
	switch v := raw.(type) {
	case Coverage:
		return NormalizeCoverage(&v, truncated)
	case *Coverage:
		return NormalizeCoverage(v, truncated)
	case map[string]any:
		status := CoverageComplete
		if truncated {
			status = CoveragePartial
		}
		if s, ok := v["status"].(string); ok && ValidCoverageStatus(CoverageStatus(s)) {
			status = CoverageStatus(s)
		}
		out := Coverage{Status: status}
		if n, ok := toInt(v["examined"]); ok {
			out.Examined = &n
		}
		if n, ok := toInt(v["total"]); ok {
			out.Total = &n
		}
		if b, ok := v["exhausted"].(bool); ok {
			out.Exhausted = &b
		}
		if n, ok := toInt(v["next_offset"]); ok {
			out.NextOffset = &n
		}
		return out
	default:
		return NormalizeCoverage(nil, truncated)
	}
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// String returns a concise summary for logging without leaking full payload bytes.
func (e Evidence) String() string {
	if e.ID != nil {
		return *e.ID
	}
	if e.Reason != "" {
		return fmt.Sprintf("none(%s)", e.Reason)
	}
	return "none"
}

package analysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	MaxRequestsEnv = "OPENCYBER_POC_MAX_REQUESTS"
	TimeoutEnv     = "OPENCYBER_POC_TIMEOUT_S"
)

// CustomRunner executes an isolated custom verification check inside an authorized sandbox.
type CustomRunner func(ctx context.Context, spec VerificationSpec) (VerificationResult, error)

// UTCNow returns the current UTC timestamp.
func UTCNow() time.Time {
	return time.Now().UTC()
}

// ISOUTC formats t as an RFC3339 UTC timestamp string.
func ISOUTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ServerManagedPath reports whether rel targets an engagement file managed exclusively by the control plane.
func ServerManagedPath(rel string) bool {
	cleaned := path.Clean(filepath.ToSlash(strings.TrimSpace(rel)))
	if cleaned == "engagement.json" || cleaned == "audit" || strings.HasPrefix(cleaned, "audit/") {
		return true
	}
	return cleaned == "poc" || strings.HasPrefix(cleaned, "poc/")
}

// CanonicalJSON marshals v deterministically without HTML escaping.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalSHA256 computes the lowercase hex SHA-256 digest of CanonicalJSON(v).
func CanonicalSHA256(v any) string {
	raw, err := CanonicalJSON(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerificationStep describes one bounded HTTP verification request and expected evidence checks.
type VerificationStep struct {
	Name            string            `json:"name"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	ExpectStatus    int               `json:"expect_status,omitempty"`
	ExpectSubstring string            `json:"expect_substring,omitempty"`
}

// VerificationSpec declares a bounded, scope-checked verification sequence.
type VerificationSpec struct {
	ID           string             `json:"id"`
	EngagementID string             `json:"engagement_id"`
	Title        string             `json:"title"`
	MaxRequests  int                `json:"max_requests,omitempty"`
	TimeoutSec   int                `json:"timeout_s,omitempty"`
	Steps        []VerificationStep `json:"steps"`
}

// StepOutcome records the observed result of one verification step.
type StepOutcome struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Passed     bool   `json:"passed"`
	Evidence   string `json:"evidence,omitempty"`
	Error      string `json:"error,omitempty"`
}

// VerificationResult summarizes an executed verification run.
type VerificationResult struct {
	SpecID       string        `json:"spec_id"`
	EngagementID string        `json:"engagement_id"`
	Verified     bool          `json:"verified"`
	CompletedAt  string        `json:"completed_at"`
	Outcomes     []StepOutcome `json:"outcomes"`
}

// RunVerification executes a bounded, scope-checked verification spec against authorized HTTP targets.
func (w *Workspace) RunVerification(ctx context.Context, spec VerificationSpec) (VerificationResult, error) {
	if len(spec.Steps) == 0 {
		return VerificationResult{}, NewError("invalid_argument", "verification spec requires at least one step")
	}
	maxReq := spec.MaxRequests
	if maxReq <= 0 {
		maxReq = 20
	}
	if maxReq > 20 || len(spec.Steps) > maxReq {
		return VerificationResult{}, NewLimitError(
			"poc.max_requests",
			fmt.Sprintf("step count %d exceeds hard ceiling %d", len(spec.Steps), maxReq),
			float64(maxReq),
			float64(len(spec.Steps)),
			"steps",
		)
	}
	if w.CustomPoCRunner != nil {
		return w.CustomPoCRunner(ctx, spec)
	}
	timeout := time.Duration(spec.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 30 * time.Second
	}
	client := w.httpClient(timeout)
	maxBytes := w.HTTPMaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultHTTPResponseMaxBytes
	}

	out := VerificationResult{
		SpecID:       spec.ID,
		EngagementID: spec.EngagementID,
		Verified:     true,
		Outcomes:     make([]StepOutcome, 0, len(spec.Steps)),
	}
	for _, step := range spec.Steps {
		if err := w.EnforceURLScope(spec.EngagementID, step.URL, "verify"); err != nil {
			return VerificationResult{}, err
		}
		method := strings.ToUpper(strings.TrimSpace(step.Method))
		if method == "" {
			method = http.MethodGet
		}
		req, err := http.NewRequestWithContext(ctx, method, step.URL, strings.NewReader(step.Body))
		if err != nil {
			out.Verified = false
			out.Outcomes = append(out.Outcomes, StepOutcome{Name: step.Name, URL: step.URL, Passed: false, Error: err.Error()})
			continue
		}
		for k, v := range step.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			out.Verified = false
			out.Outcomes = append(out.Outcomes, StepOutcome{Name: step.Name, URL: step.URL, Passed: false, Error: err.Error()})
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)))
		_ = resp.Body.Close()

		passed := true
		if step.ExpectStatus > 0 && resp.StatusCode != step.ExpectStatus {
			passed = false
		}
		if step.ExpectSubstring != "" && !strings.Contains(string(body), step.ExpectSubstring) {
			passed = false
		}
		if !passed {
			out.Verified = false
		}
		evidence := string(body)
		if len(evidence) > 512 {
			evidence = evidence[:512]
		}
		out.Outcomes = append(out.Outcomes, StepOutcome{
			Name:       step.Name,
			URL:        step.URL,
			StatusCode: resp.StatusCode,
			Passed:     passed,
			Evidence:   evidence,
		})
	}
	out.CompletedAt = ISOUTC(UTCNow())
	w.SafeRecordAudit(spec.EngagementID, map[string]any{
		"action":   "verification_run",
		"spec_id":  spec.ID,
		"verified": out.Verified,
		"steps":    len(out.Outcomes),
	})
	return out, nil
}

// HeaderAuditFinding describes a missing or misconfigured HTTP security response header.
type HeaderAuditFinding struct {
	Header   string `json:"header"`
	Severity string `json:"severity"`
	Issue    string `json:"issue"`
	Observed string `json:"observed,omitempty"`
}

// AuditSecurityHeaders evaluates HTTP response headers against baseline web/API hardening policy.
func AuditSecurityHeaders(h http.Header) []HeaderAuditFinding {
	var findings []HeaderAuditFinding
	required := []struct {
		header   string
		severity string
		issue    string
	}{
		{"Strict-Transport-Security", "medium", "missing HSTS header"},
		{"Content-Security-Policy", "medium", "missing Content-Security-Policy header"},
		{"X-Content-Type-Options", "low", "missing X-Content-Type-Options: nosniff"},
		{"X-Frame-Options", "low", "missing clickjacking protection header"},
	}
	for _, r := range required {
		if strings.TrimSpace(h.Get(r.header)) == "" {
			findings = append(findings, HeaderAuditFinding{
				Header:   r.header,
				Severity: r.severity,
				Issue:    r.issue,
			})
		}
	}
	if acao := strings.TrimSpace(h.Get("Access-Control-Allow-Origin")); acao == "*" &&
		strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true") {
		findings = append(findings, HeaderAuditFinding{
			Header:   "Access-Control-Allow-Origin",
			Severity: "high",
			Issue:    "wildcard CORS origin combined with Access-Control-Allow-Credentials: true",
			Observed: acao,
		})
	}
	return findings
}

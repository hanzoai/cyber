package errors

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net"
	"os"
	"strings"
	"testing"
)

func TestErrorRegistryComplete(t *testing.T) {
	codes := ErrorCodes()
	if len(codes) != 26 {
		t.Fatalf("expected 26 error codes, got %d", len(codes))
	}
	for code, spec := range codes {
		if code != spec.Code {
			t.Errorf("mismatched key %q vs spec.Code %q", code, spec.Code)
		}
		if strings.TrimSpace(spec.Summary) == "" {
			t.Errorf("code %q missing summary", code)
		}
		if strings.TrimSpace(spec.Remediation) == "" {
			t.Errorf("code %q missing remediation", code)
		}
	}

	cats := AllCategories()
	if len(cats) != 12 {
		t.Fatalf("expected 12 categories, got %d", len(cats))
	}

	rows := DescribeCodes()
	if len(rows) != len(codes) {
		t.Fatalf("expected %d described rows, got %d", len(codes), len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Code >= rows[i].Code {
			t.Fatalf("DescribeCodes not strictly sorted at %d: %q >= %q", i, rows[i-1].Code, rows[i].Code)
		}
	}
	if _, err := json.Marshal(rows); err != nil {
		t.Fatalf("DescribeCodes JSON marshal failed: %v", err)
	}
}

func TestErrorSchemaDerivedFromRegistry(t *testing.T) {
	schema := ErrorSchema()
	if ap, ok := schema["additionalProperties"].(bool); !ok || ap {
		t.Fatalf("expected additionalProperties=false, got %v", schema["additionalProperties"])
	}
	props := schema["properties"].(map[string]any)
	codeEnum := props["code"].(map[string]any)["enum"].([]string)
	if len(codeEnum) != len(ErrorCodes()) {
		t.Fatalf("schema code enum count %d != registry count %d", len(codeEnum), len(ErrorCodes()))
	}
	catEnum := props["category"].(map[string]any)["enum"].([]string)
	if len(catEnum) != len(AllCategories()) {
		t.Fatalf("schema category enum count %d != categories count %d", len(catEnum), len(AllCategories()))
	}
	if _, err := json.Marshal(schema); err != nil {
		t.Fatalf("ErrorSchema marshal failed: %v", err)
	}
}

func TestErrorConstructionAndIsolation(t *testing.T) {
	if _, err := NewStrict("not_registered", "nope"); err == nil {
		t.Fatal("expected unregistered code to fail closed in NewStrict")
	}
	if _, err := NewStrict(CodeInvalidArgument, ""); err == nil {
		t.Fatal("expected empty message to fail closed in NewStrict")
	}

	details := map[string]any{"denied": []string{"10.0.0.9"}}
	ocErr, err := NewStrict(
		CodeScopeDenied,
		"host outside scope",
		WithDetails(details),
		WithHint("Add the host to the engagement."),
	)
	if err != nil {
		t.Fatalf("NewStrict failed: %v", err)
	}
	// Mutate caller slice to verify deep copy.
	details["denied"].([]string)[0] = "mutated"
	m := ocErr.ToMap()
	if m["code"] != CodeScopeDenied || m["category"] != string(CategoryDenied) {
		t.Fatalf("unexpected error map: %+v", m)
	}
	if ocErr.Retriable() {
		t.Fatal("scope_denied should not be retryable")
	}
	if ocErr.Hint() != "Add the host to the engagement." {
		t.Fatalf("unexpected hint: %q", ocErr.Hint())
	}
	if got := m["details"].(map[string]any)["denied"].([]string)[0]; got != "10.0.0.9" {
		t.Fatalf("details were aliased: got %q", got)
	}

	// Retryable default and override.
	timeoutErr := New(CodeTimedOut, "exceeded deadline")
	if !timeoutErr.Retriable() {
		t.Fatal("timed_out should default to retryable")
	}
	nonRetry := New(CodeTimedOut, "exceeded deadline", WithRetryable(false))
	if nonRetry.Retriable() {
		t.Fatal("WithRetryable(false) override failed")
	}

	// Fallback for unregistered code in New.
	fallback := New("bogus_code", "something failed")
	if fallback.Code != CodeInternalError {
		t.Fatalf("expected fallback to internal_error, got %q", fallback.Code)
	}
	if fallback.Details["unregistered_code"] != "bogus_code" {
		t.Fatalf("expected unregistered_code detail, got %+v", fallback.Details)
	}
}

func TestTranslate(t *testing.T) {
	orig := New(CodeNotFound, "missing record")
	got, cancelled := Translate(orig)
	if cancelled || got != orig {
		t.Fatalf("expected pass-through *Error, got (%v, %v)", got, cancelled)
	}

	if got, cancelled := Translate(context.Canceled); !cancelled || got != nil {
		t.Fatalf("expected cancellation passthrough, got (%v, %v)", got, cancelled)
	}

	cases := []struct {
		name string
		err  error
		code string
	}{
		{"deadline", context.DeadlineExceeded, CodeTimedOut},
		{"not_exist", os.ErrNotExist, CodeNotFound},
		{"exists", os.ErrExist, CodeAlreadyExists},
		{"permission", os.ErrPermission, CodePermissionDenied},
		{"net_op", &net.OpError{Op: "dial", Net: "tcp", Err: stderrors.New("refused")}, CodeConnectionFailed},
		{"path_err", &os.PathError{Op: "read", Path: "/tmp/x", Err: stderrors.New("io error")}, CodeExecutionFailed},
		{"unexpected", stderrors.New("boom"), CodeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			translated, wasCancelled := Translate(tc.err)
			if wasCancelled {
				t.Fatalf("unexpected cancellation for %s", tc.name)
			}
			if translated.Code != tc.code {
				t.Fatalf("expected %q, got %q", tc.code, translated.Code)
			}
			if !IsCode(translated, tc.code) {
				t.Fatalf("IsCode mismatch for %q", tc.code)
			}
		})
	}
}

func TestLimitsRegistryAndEnvResolution(t *testing.T) {
	all := Limits()
	if len(all) != 18 {
		t.Fatalf("expected 18 registered limits, got %d", len(all))
	}
	for id, lim := range all {
		if lim.ID != id {
			t.Errorf("limit ID mismatch: %q vs %q", id, lim.ID)
		}
		if lim.Minimum != nil && lim.Default < *lim.Minimum {
			t.Errorf("limit %q default < minimum", id)
		}
		if lim.Maximum != nil && lim.Default > *lim.Maximum {
			t.Errorf("limit %q default > maximum", id)
		}
		if lim.Source == LimitSourceArgument && lim.Parameter == "" {
			t.Errorf("argument limit %q must name parameter", id)
		}
		if lim.Source == LimitSourceEnvironment && lim.Env == "" {
			t.Errorf("environment limit %q must name env var", id)
		}
	}

	rows := DescribeLimits()
	if len(rows) != 18 {
		t.Fatalf("expected 18 limit descriptions, got %d", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].ID >= rows[i].ID {
			t.Fatalf("DescribeLimits not sorted at %d", i)
		}
	}

	if len(LimitSettings()) != 5 {
		t.Fatalf("expected 5 env-backed limits, got %d", len(LimitSettings()))
	}

	// Environment override resolution and fail-closed validation.
	httpTimeout, ok := LimitFor("http.timeout")
	if !ok {
		t.Fatal("missing http.timeout limit")
	}
	t.Setenv("OPENCYBER_HTTP_TIMEOUT", "")
	if val, err := httpTimeout.DocumentEffective(); err != nil || val != 30 {
		t.Fatalf("expected default 30, got (%v, %v)", val, err)
	}
	t.Setenv("OPENCYBER_HTTP_TIMEOUT", "45")
	if val, err := httpTimeout.DocumentEffective(); err != nil || val != 45 {
		t.Fatalf("expected override 45, got (%v, %v)", val, err)
	}
	for _, bad := range []string{"soon", "9000", "NaN", "Infinity", "-Infinity", "-1"} {
		t.Setenv("OPENCYBER_HTTP_TIMEOUT", bad)
		if _, err := httpTimeout.DocumentEffective(); !IsCode(err, CodeInvalidArgument) {
			t.Fatalf("expected invalid_argument for %q, got %v", bad, err)
		}
	}

	// Facts & RaiseExceeded.
	eff, req := 4096.0, 8192.0
	limErr := RaiseExceeded("workspace.read_max_bytes", "too big", &eff, &req, "max_bytes", map[string]any{"path": "a.txt"})
	if limErr.Code != CodeLimitExceeded || limErr.Category != CategoryResourceConstraint || !limErr.Retriable() {
		t.Fatalf("unexpected limit error: %+v", limErr)
	}
	if limErr.Limit == nil || limErr.Limit.Effective != 4096 || *limErr.Limit.Requested != 8192 {
		t.Fatalf("unexpected limit facts: %+v", limErr.Limit)
	}
	factsMap := limErr.Limit.ToMap()
	if _, ok := factsMap["effective"].(int64); !ok {
		t.Fatalf("expected whole number effective as int64, got %T", factsMap["effective"])
	}
}

func TestConcurrencyLimiter(t *testing.T) {
	lim := NewConcurrencyLimiter(2)
	rel1, ok := lim.TryAcquire()
	if !ok || lim.Active() != 1 {
		t.Fatalf("first acquire failed: ok=%v active=%d", ok, lim.Active())
	}
	rel2, ok := lim.TryAcquire()
	if !ok || lim.Active() != 2 {
		t.Fatalf("second acquire failed: ok=%v active=%d", ok, lim.Active())
	}
	if _, ok := lim.TryAcquire(); ok {
		t.Fatal("third TryAcquire should fail when at capacity")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lim.Acquire(ctx); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	rel1()
	rel1() // idempotent
	if lim.Active() != 1 {
		t.Fatalf("expected active=1 after idempotent release, got %d", lim.Active())
	}
	rel2()
	if lim.Active() != 0 {
		t.Fatalf("expected active=0, got %d", lim.Active())
	}
}

func TestEnvelopeAndWrap(t *testing.T) {
	meta := ContractMeta{Name: "oc_catalog", ReturnsTargetContent: false, ProvenanceSource: "server"}

	env1 := NewEnvelope(meta, map[string]int{"count": 3})
	env2 := NewEnvelope(meta, map[string]int{"count": 3})
	if !env1.OK {
		t.Fatal("expected OK=true")
	}
	if env1.Evidence.ID == nil || !strings.HasPrefix(*env1.Evidence.ID, EvidencePrefix) {
		t.Fatalf("unexpected evidence ID: %+v", env1.Evidence)
	}
	if env1.Evidence.SHA256 == nil || len(*env1.Evidence.SHA256) != 64 {
		t.Fatalf("unexpected evidence SHA256: %+v", env1.Evidence)
	}
	if *env1.Evidence.SHA256 != *env2.Evidence.SHA256 {
		t.Fatal("expected deterministic evidence digest")
	}

	// CanonicalJSON must not escape HTML chars (<, >, &).
	raw, err := CanonicalJSON(map[string]any{"b": "a<b>c&d", "a": 1})
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if string(raw) != `{"a":1,"b":"a<b>c&d"}` {
		t.Fatalf("unexpected canonical JSON: %s", raw)
	}

	// Oversized evidence reports reason instead of digest.
	bigEv := ComputeEvidence(map[string]string{"v": strings.Repeat("x", 128)}, 64)
	if bigEv.ID != nil || bigEv.Reason != "result_too_large" || bigEv.Bytes == nil || *bigEv.Bytes <= 64 {
		t.Fatalf("unexpected oversized evidence: %+v", bigEv)
	}

	// Wrap propagates cancellation and translates errors into refusals.
	wrappedOK := Wrap(meta, func(context.Context) (string, error) { return "ok", nil })
	res, err := wrappedOK(context.Background())
	if err != nil || !res.OK || res.Data != "ok" {
		t.Fatalf("wrapped success failed: %+v %v", res, err)
	}

	wrappedRefusal := Wrap(meta, func(context.Context) (string, error) {
		return "", New(CodeScopeDenied, "outside scope")
	})
	ref, err := wrappedRefusal(context.Background())
	if err != nil || ref.OK || ref.Error == nil || ref.Error.Code != CodeScopeDenied {
		t.Fatalf("wrapped refusal failed: %+v %v", ref, err)
	}

	wrappedCancel := Wrap(meta, func(context.Context) (string, error) {
		return "", context.Canceled
	})
	if _, err := wrappedCancel(context.Background()); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled to propagate, got %v", err)
	}

	// Additive FinalizeMap keeps legacy keys and forces ok=false on error.
	finalized := FinalizeMap(meta, map[string]any{"success": true, "stdout": "hi", "truncated": true})
	if finalized["ok"] != true || finalized["stdout"] != "hi" {
		t.Fatalf("unexpected finalized map: %+v", finalized)
	}
	if finalized["coverage"].(map[string]any)["status"] != string(CoveragePartial) {
		t.Fatalf("expected partial coverage on truncated payload, got %+v", finalized["coverage"])
	}
	errMap := FinalizeMap(meta, map[string]any{"error": New(CodeNotFound, "gone").ToMap()})
	if errMap["ok"] != false {
		t.Fatalf("expected ok=false when error present")
	}
}

func TestCoverageAccounting(t *testing.T) {
	if _, err := NewCoverage("finished"); err == nil {
		t.Fatal("expected invalid coverage status to fail")
	}
	cov, err := NewCoverage(CoveragePartial, WithExamined(10), WithTotal(20), WithExhausted(false), WithNextOffset(10))
	if err != nil {
		t.Fatalf("NewCoverage failed: %v", err)
	}
	m := cov.ToMap()
	if len(m) != 5 || m["examined"] != 10 || m["next_offset"] != 10 {
		t.Fatalf("unexpected coverage map: %+v", m)
	}

	report := ComputeReferenceCoverage(map[string]string{
		"nmap": "oc_nmap",
		"ffuf": "oc_ffuf",
	})
	if report.Total != len(ReferenceFunctions) || report.Covered["nmap"] != "oc_nmap" || report.Covered["angr"] != "oc_angr_analyze" {
		t.Fatalf("unexpected reference coverage report: %+v", report)
	}
}

func TestIndicatorsAndSecretRedaction(t *testing.T) {
	sample := `
	Found https://api.example.com/v1 and http://10.0.0.5:8080/login
	IPs: 192.168.1.10, invalid 999.1.1.1, version 1.2.3.4.5, IPv6 2001:0db8::1
	Vuln: CVE-2026-12345 and cve-2025-9999
	MD5: d41d8cd98f00b204e9800998ecf8427e
	SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
	SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	Host: app.staging.example.org
	`
	base := ExtractIndicators(sample, false)
	if len(base.URLs) != 2 {
		t.Fatalf("expected 2 URLs, got %v", base.URLs)
	}
	if len(base.IPv4) != 2 || base.IPv4[0] != "10.0.0.5" || base.IPv4[1] != "192.168.1.10" {
		t.Fatalf("unexpected IPv4 list: %v", base.IPv4)
	}
	if len(base.CVEs) != 2 || len(base.MD5) != 1 || len(base.SHA1) != 1 || len(base.SHA256) != 1 {
		t.Fatalf("unexpected hashes/CVEs: %+v", base)
	}
	if base.IPv6 != nil || base.Domains != nil {
		t.Fatalf("extended fields should be omitted when extended=false")
	}

	ext := ExtractIndicators(sample, true)
	if len(ext.IPv6) != 1 || ext.IPv6[0] != "2001:db8::1" {
		t.Fatalf("unexpected IPv6: %v", ext.IPv6)
	}
	foundDomain := false
	for _, d := range ext.Domains {
		if d == "app.staging.example.org" {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatalf("expected app.staging.example.org in domains: %v", ext.Domains)
	}

	// Secret redaction.
	redacted := RedactMap(map[string]any{
		"event":    "test.secret",
		"password": "hunter2",
		"headers":  map[string]any{"Authorization": "Bearer secret-jwt.token", "Accept": "application/json"},
		"note":     "token=deadbeef password=hunter2 Bearer topSecret123",
	})
	if redacted["password"] != "***" {
		t.Fatalf("expected password masked, got %v", redacted["password"])
	}
	hdrs := redacted["headers"].(map[string]any)
	if hdrs["Authorization"] != "***" || hdrs["Accept"] != "application/json" {
		t.Fatalf("unexpected redacted headers: %+v", hdrs)
	}
	note := redacted["note"].(string)
	for _, secret := range []string{"deadbeef", "hunter2", "topSecret123"} {
		if strings.Contains(note, secret) {
			t.Fatalf("secret %q leaked in note: %q", secret, note)
		}
	}
	if !strings.Contains(note, "Bearer ***") {
		t.Fatalf("expected Bearer *** in note: %q", note)
	}

	httpHdrs := RedactHeaders(map[string]string{
		"Authorization": "Bearer abc",
		"X-Api-Key":     "k123",
		"Content-Type":  "application/json",
	})
	if httpHdrs["Authorization"] != RedactedPlaceholder || httpHdrs["X-Api-Key"] != RedactedPlaceholder || httpHdrs["Content-Type"] != "application/json" {
		t.Fatalf("unexpected RedactHeaders output: %+v", httpHdrs)
	}
}

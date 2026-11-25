package analysis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkspaceScopeAuditAndVerification(t *testing.T) {
	ws := NewWorkspace(t.TempDir())
	enforce := true
	ws.EnforceScope = &enforce

	eng, err := ws.CreateEngagement("MDTF Lab", []string{"127.0.0.1", "lab.internal"})
	if err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}
	if _, err := ws.WriteWorkspaceFile(eng.EngagementID, "engagement.json", []byte("{}")); err == nil {
		t.Fatal("expected refusal writing server-managed engagement.json")
	}
	if _, err := ws.WriteWorkspaceFile(eng.EngagementID, "notes/summary.txt", []byte("authorized")); err != nil {
		t.Fatalf("WriteWorkspaceFile: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("status=ok proof=mdtf-verified"))
	}))
	defer srv.Close()

	res, err := ws.RunVerification(context.Background(), VerificationSpec{
		ID:           "ver-1",
		EngagementID: eng.EngagementID,
		Title:        "Verify lab endpoint",
		Steps: []VerificationStep{
			{Name: "health", Method: "GET", URL: srv.URL, ExpectStatus: 200, ExpectSubstring: "mdtf-verified"},
		},
	})
	if err != nil {
		t.Fatalf("RunVerification: %v", err)
	}
	if !res.Verified || len(res.Outcomes) != 1 || !res.Outcomes[0].Passed {
		t.Fatalf("expected verified outcome, got %+v", res)
	}

	// Out-of-scope target must be refused
	if _, err := ws.RunVerification(context.Background(), VerificationSpec{
		ID:           "ver-denied",
		EngagementID: eng.EngagementID,
		Steps:        []VerificationStep{{Name: "oob", Method: "GET", URL: "https://outside.example.org/"}},
	}); err == nil {
		t.Fatal("expected out-of-scope URL refusal")
	}
}

func TestCVEIndexHeadersAndTriage(t *testing.T) {
	idx := NewCVEIndex([]CVERecord{
		{ID: "CVE-2026-0001", Severity: "critical", CVSS: 9.8, Summary: "Auth bypass in gateway", Products: []string{"hanzo-gateway"}},
		{ID: "CVE-2026-0002", Severity: "medium", CVSS: 5.3, Summary: "Verbose error trace", Products: []string{"nginx"}},
	})
	if idx.Count() != 2 {
		t.Fatalf("expected 2 CVEs, got %d", idx.Count())
	}
	hits := idx.Search("auth", "gateway", 9.0, 10)
	if len(hits) != 1 || hits[0].ID != "CVE-2026-0001" {
		t.Fatalf("unexpected CVE search hits: %+v", hits)
	}

	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	hf := AuditSecurityHeaders(h)
	if len(hf) < 4 {
		t.Fatalf("expected missing security headers + CORS finding, got %+v", hf)
	}

	summary := TriageFindings([]TriageFinding{
		{ID: "1", Title: "SQLi", Severity: "high", Target: "api.lab", Verified: false},
		{ID: "2", Title: "SQLi", Severity: "high", Target: "api.lab", Verified: true},
		{ID: "3", Title: "RCE", Severity: "critical", Target: "edge.lab", Verified: true},
	})
	if summary.Unique != 2 || summary.Verified != 2 || summary.Prioritized[0].Severity != "critical" {
		t.Fatalf("unexpected triage summary: %+v", summary)
	}
}

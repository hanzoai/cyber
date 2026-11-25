package exec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSandboxRunnerLeaseRunAndEnd(t *testing.T) {
	var leased, ran, ended bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Org-Id") != "hanzo" {
			t.Errorf("unexpected org header: %q", r.Header.Get("X-Org-Id"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sandbox/lease":
			leased = true
			_ = json.NewEncoder(w).Encode(SandboxLease{
				ID:      "sbx_test_001",
				Class:   "cyber",
				Runtime: "microvm",
				Status:  "running",
			})
		case "/v1/sandbox/run":
			ran = true
			_ = json.NewEncoder(w).Encode(SandboxRunResult{
				ID:         "sbx_test_001",
				ExitCode:   0,
				Stdout:     "ok from microvm\n",
				DurationMS: 12,
			})
		case "/v1/sandbox/end":
			ended = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ended"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	runner := NewSandboxRunner(SandboxConfig{
		BaseURL:            srv.URL,
		Token:              "test-token",
		OrgID:              "hanzo",
		AllowLocalFallback: false,
		HTTPClient:         srv.Client(),
	}, nil)

	ctx := context.Background()
	lease, err := runner.Lease(ctx, LeaseRequest{Class: "cyber", Runtime: "microvm"})
	if err != nil {
		t.Fatalf("Lease failed: %v", err)
	}
	if lease.ID != "sbx_test_001" {
		t.Fatalf("unexpected lease ID: %q", lease.ID)
	}

	res, err := runner.Run(ctx, SandboxRunRequest{ID: lease.ID, Argv: []string{"echo", "ok"}})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "ok from microvm\n" {
		t.Fatalf("unexpected run result: %+v", res)
	}

	if err := runner.End(ctx, lease.ID, true); err != nil {
		t.Fatalf("End failed: %v", err)
	}
	if !leased || !ran || !ended {
		t.Fatalf("expected full microVM lifecycle: leased=%v ran=%v ended=%v", leased, ran, ended)
	}
}

func TestSandboxRunnerOfflineFallbackFailClosed(t *testing.T) {
	runner := NewSandboxRunner(SandboxConfig{
		BaseURL:            "https://api.hanzo.ai",
		Token:              "",
		AllowLocalFallback: false,
	}, nil)
	if _, err := runner.Execute(context.Background(), ExecRequest{
		Executable: "echo",
		Arguments:  []string{"hello"},
	}); err == nil {
		t.Fatal("expected unconfigured sandbox without fallback to fail closed")
	}
}

func TestCanonicalHTTPURLAndScopeValidator(t *testing.T) {
	if _, err := CanonicalHTTPURL("https://example.com/api"); err != nil {
		t.Fatalf("expected valid URL, got %v", err)
	}
	for _, bad := range []string{"", "ftp://example.com", "https://user@example.com/", `https://example.com\evil/`} {
		if _, err := CanonicalHTTPURL(bad); err == nil {
			t.Errorf("expected CanonicalHTTPURL(%q) to fail", bad)
		}
	}
	changed, err := CredentialBoundaryChanged("https://a.example.com/1", "http://a.example.com/2")
	if err != nil || !changed {
		t.Fatalf("expected HTTPS->HTTP downgrade to trip credential boundary: changed=%v err=%v", changed, err)
	}
}

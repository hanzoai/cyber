// Copyright © 2026 Hanzo AI. MIT License.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

var testCfg = zip.TestConfig{Timeout: 10 * time.Second, FailOnTimeout: true}

func newTestApp(t *testing.T, engCfg EngineConfig, mountCfg ...MountConfig) (*zip.App, *Store, *Engine) {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	engine := NewEngine(store, engCfg)
	app := zip.New(zip.Config{
		AppName:               "cyber",
		Logger:                luxlog.New("test"),
		DisableStartupMessage: true,
		OpenAPI: zip.OpenAPIConfig{
			Title:   "Hanzo Cyber Test",
			Version: "1.0.0-beta.2",
		},
		MCP: zip.MCPConfig{
			Name: "hanzo-cyber-test",
		},
	})
	Mount(app, store, engine, mountCfg...)
	return app, store, engine
}

func doReq(t *testing.T, app *zip.App, method, path, org, user string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if org != "" {
		req.Header.Set(zip.HeaderOrg, org)
	}
	if user != "" {
		req.Header.Set(zip.HeaderUser, user)
	}
	resp, err := app.Test(req, testCfg)
	if err != nil {
		t.Fatalf("app.Test %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, b
}

func TestHealthAuthAndTenantIsolation(t *testing.T) {
	app, _, _ := newTestApp(t, EngineConfig{})

	// 1. Health is public.
	code, body := doReq(t, app, http.MethodGet, "/v1/cyber/health", "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/cyber/health = %d (%s), want 200", code, body)
	}
	var hv HealthView
	if err := json.Unmarshal(body, &hv); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if hv.Status != "ok" || hv.Mode != "multi-tenant" {
		t.Fatalf("unexpected health view: %+v", hv)
	}

	// 2. Unauthenticated request refused with 401.
	code, _ = doReq(t, app, http.MethodGet, "/v1/cyber/dashboard", "", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard = %d, want 401", code)
	}

	// 3. X-Org-Id without X-User-Id is refused with 401 (zip.Tenant anti-spoofing rule).
	code, _ = doReq(t, app, http.MethodGet, "/v1/cyber/dashboard", "hanzo", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("org-only dashboard = %d, want 401", code)
	}

	// 4. Seed synthetic MDTF demo for org "hanzo" (idempotent across repeated calls).
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/engagements/seed-demo", "hanzo", "u_hanzo", nil)
	if code != http.StatusCreated {
		t.Fatalf("seed-demo = %d (%s), want 201", code, body)
	}
	var seeded SeedDemoRes
	if err := json.Unmarshal(body, &seeded); err != nil {
		t.Fatalf("unmarshal seed-demo: %v", err)
	}
	if !seeded.Engagement.Synthetic || seeded.Findings != 3 || seeded.Traffic != 3 || seeded.Rules != 3 || seeded.Approvals != 2 {
		t.Fatalf("unexpected seed counts: %+v", seeded)
	}
	// Second seed must remain idempotent.
	code, _ = doReq(t, app, http.MethodPost, "/v1/cyber/engagements/seed-demo", "hanzo", "u_hanzo", nil)
	if code != http.StatusCreated {
		t.Fatalf("second seed-demo = %d, want 201", code)
	}
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/engagements", "hanzo", "u_hanzo", nil)
	var hanzoEngs EngagementList
	_ = json.Unmarshal(body, &hanzoEngs)
	if len(hanzoEngs.Data) != 1 {
		t.Fatalf("expected idempotent 1 seeded engagement, got %d", len(hanzoEngs.Data))
	}

	// 5. Another org cannot read hanzo's seeded data.
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/engagements", "partner", "u_partner", nil)
	if code != http.StatusOK {
		t.Fatalf("partner engagements = %d, want 200", code)
	}
	var partnerEngs EngagementList
	_ = json.Unmarshal(body, &partnerEngs)
	if len(partnerEngs.Data) != 0 {
		t.Fatalf("tenant isolation breach: partner saw %d engagements, want 0", len(partnerEngs.Data))
	}

	// 6. Cross-tenant task graph, finding verify, and rule delete all return 404.
	code, _ = doReq(t, app, http.MethodGet, "/v1/cyber/tasks/tsk_mdtf_audit_hanzo/graph", "partner", "u_partner", nil)
	if code != http.StatusNotFound {
		t.Fatalf("cross-tenant task graph = %d, want 404", code)
	}
	code, _ = doReq(t, app, http.MethodPost, "/v1/cyber/findings/fnd_mdtf_1_hanzo/verify", "partner", "u_partner", map[string]any{})
	if code != http.StatusNotFound {
		t.Fatalf("cross-tenant finding verify = %d, want 404", code)
	}
	code, _ = doReq(t, app, http.MethodDelete, "/v1/cyber/intercept/rules/rul_mdtf_1_hanzo", "partner", "u_partner", nil)
	if code != http.StatusNotFound {
		t.Fatalf("cross-tenant rule delete = %d, want 404", code)
	}
}

func TestStandaloneLocalMode(t *testing.T) {
	app, _, _ := newTestApp(t, EngineConfig{Standalone: true}, MountConfig{Standalone: true})

	code, body := doReq(t, app, http.MethodGet, "/v1/cyber/dashboard", "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("standalone dashboard = %d (%s), want 200", code, body)
	}
	var dash DashboardView
	_ = json.Unmarshal(body, &dash)
	if dash.Org != "local" {
		t.Fatalf("standalone dashboard org = %q, want local", dash.Org)
	}
}

func TestEndToEndCRUDVerbatimProofAndKaiGovernance(t *testing.T) {
	app, _, _ := newTestApp(t, EngineConfig{})
	const org, user = "hanzo", "operator@hanzo.ai"

	// Create engagement.
	code, body := doReq(t, app, http.MethodPost, "/v1/cyber/engagements", org, user, CreateEngagementReq{
		Name:   "Enclave Alpha",
		Target: "api.alpha.test",
		Scope:  []string{"api.alpha.test", "*.alpha.test"},
		Mode:   "enclave",
	})
	if code != http.StatusCreated {
		t.Fatalf("create engagement = %d (%s)", code, body)
	}
	var eng EngagementView
	_ = json.Unmarshal(body, &eng)

	// Create task and verify root GOAL node + added INTENT node.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/tasks", org, user, CreateTaskReq{
		EngagementID: eng.ID,
		Title:        "Verify Debug Auth Boundary",
		Goal:         "Confirm /debug cannot be accessed without admin credentials",
		Phase:        "verify",
	})
	if code != http.StatusCreated {
		t.Fatalf("create task = %d (%s)", code, body)
	}
	var task TaskView
	_ = json.Unmarshal(body, &task)

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/tasks/"+task.ID+"/nodes", org, user, map[string]any{
		"kind":   "intent",
		"label":  "Probe /debug endpoint",
		"detail": "Send unauthenticated GET request to https://api.alpha.test/debug",
		"status": "done",
	})
	if code != http.StatusCreated {
		t.Fatalf("add node = %d (%s)", code, body)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/tasks/"+task.ID+"/graph", org, user, nil)
	if code != http.StatusOK {
		t.Fatalf("get task graph = %d (%s)", code, body)
	}
	var graph TaskGraphView
	_ = json.Unmarshal(body, &graph)
	if len(graph.Nodes) != 2 || graph.Nodes[0].Kind != "goal" || graph.Nodes[1].Kind != "intent" {
		t.Fatalf("unexpected task graph nodes: %+v", graph.Nodes)
	}

	// Record captured HTTP exchange.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/traffic", org, user, RecordTrafficReq{
		EngagementID: eng.ID,
		TaskID:       task.ID,
		Method:       "GET",
		URL:          "https://api.alpha.test/debug",
		StatusCode:   200,
		ResponseBody: `{"debug":true,"role":"admin_bypass"}`,
	})
	if code != http.StatusCreated {
		t.Fatalf("record traffic = %d (%s)", code, body)
	}
	var tr TrafficView
	_ = json.Unmarshal(body, &tr)
	if tr.Host != "api.alpha.test" {
		t.Fatalf("parsed traffic host = %q, want api.alpha.test", tr.Host)
	}

	// Create finding bound to captured traffic.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/findings", org, user, CreateFindingReq{
		EngagementID:   eng.ID,
		TaskID:         task.ID,
		Title:          "Debug Bypass Exposed",
		Severity:       "critical",
		Category:       "Broken Access Control",
		CWE:            "CWE-284",
		MitreTechnique: "T1190",
		MitreTactic:    "Initial Access",
		Target:         "https://api.alpha.test/debug",
		EvidenceQuote:  `"role":"admin_bypass"`,
		TrafficID:      tr.ID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create finding = %d (%s)", code, body)
	}
	var f FindingView
	_ = json.Unmarshal(body, &f)
	if f.Verified {
		t.Fatal("finding must start unverified before explicit verify call")
	}

	// Update remediation via PATCH.
	code, body = doReq(t, app, http.MethodPatch, "/v1/cyber/findings/"+f.ID, org, user, map[string]any{
		"remediation": "Disable /debug outside loopback and enforce Hanzo IAM admin policy.",
	})
	if code != http.StatusOK {
		t.Fatalf("patch finding = %d (%s)", code, body)
	}

	// Deterministic verbatim proof verification succeeds on exact substring.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/findings/"+f.ID+"/verify", org, user, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("verify finding = %d (%s)", code, body)
	}
	_ = json.Unmarshal(body, &f)
	if !f.Verified || f.Status != "verified" {
		t.Fatalf("expected verified finding, got verified=%v status=%q note=%q", f.Verified, f.Status, f.VerificationNote)
	}

	// Non-matching quote must fail verification cleanly (verified=false).
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/findings/"+f.ID+"/verify", org, user, map[string]any{
		"evidenceQuote": "NOT_IN_RESPONSE_BODY",
	})
	if code != http.StatusOK {
		t.Fatalf("verify mismatch = %d (%s)", code, body)
	}
	_ = json.Unmarshal(body, &f)
	if f.Verified || f.Status == "verified" {
		t.Fatalf("mismatched quote must never verify: %+v", f)
	}

	// Kai risk scoring & human always_allow decision -> auto-creates allow intercept rule.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/approvals", org, user, SubmitApprovalReq{
		EngagementID: eng.ID,
		TaskID:       task.ID,
		Action:       "Run active exploit payload injection test",
		Target:       "api.alpha.test",
		Tool:         "cyber_http_exploit",
	})
	if code != http.StatusCreated {
		t.Fatalf("submit approval = %d (%s)", code, body)
	}
	var apr ApprovalView
	_ = json.Unmarshal(body, &apr)
	if apr.RiskScore < 70 || (apr.RiskLevel != "high" && apr.RiskLevel != "critical") {
		t.Fatalf("expected high/critical Kai risk score, got %d (%s)", apr.RiskScore, apr.RiskLevel)
	}

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/approvals/"+apr.ID+"/decide", org, user, map[string]any{
		"decision": "always_allow",
	})
	if code != http.StatusOK {
		t.Fatalf("decide approval = %d (%s)", code, body)
	}
	_ = json.Unmarshal(body, &apr)
	if apr.Status != "always_allow" || apr.DecidedBy != user {
		t.Fatalf("expected always_allow + decidedBy=%q, got %+v", user, apr)
	}

	// Confirm always_allow created an allow intercept rule.
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/intercept/rules?engagementId="+eng.ID, org, user, nil)
	if code != http.StatusOK {
		t.Fatalf("list rules = %d (%s)", code, body)
	}
	var rules RuleList
	_ = json.Unmarshal(body, &rules)
	if len(rules.Data) != 1 || rules.Data[0].Action != "allow" || rules.Data[0].MatchHost != "api.alpha.test" {
		t.Fatalf("expected auto-created always_allow rule, got %+v", rules.Data)
	}

	// Create and delete an explicit intercept rule.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/intercept/rules", org, user, CreateRuleReq{
		EngagementID: eng.ID,
		Name:         "Block prod payments",
		MatchHost:    "pay.alpha.test",
		MatchPath:    "/v1/charge/*",
		Action:       "block",
	})
	if code != http.StatusCreated {
		t.Fatalf("create rule = %d (%s)", code, body)
	}
	var createdRule RuleView
	_ = json.Unmarshal(body, &createdRule)

	code, body = doReq(t, app, http.MethodDelete, "/v1/cyber/intercept/rules/"+createdRule.ID, org, user, nil)
	if code != http.StatusOK {
		t.Fatalf("delete rule = %d (%s)", code, body)
	}
	var delRes DeleteRes
	_ = json.Unmarshal(body, &delRes)
	if !delRes.Deleted || delRes.ID != createdRule.ID {
		t.Fatalf("unexpected delete response: %+v", delRes)
	}

	// Verify ATT&CK, CoA, Hardening, Dashboard, and Tools endpoints.
	for _, ep := range []string{
		"/v1/cyber/attack?engagementId=" + eng.ID,
		"/v1/cyber/coa?engagementId=" + eng.ID,
		"/v1/cyber/hardening?engagementId=" + eng.ID,
		"/v1/cyber/dashboard?engagementId=" + eng.ID,
		"/v1/cyber/tools",
		"/v1/cyber/tools?group=verify",
	} {
		code, body = doReq(t, app, http.MethodGet, ep, org, user, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", ep, code, body)
		}
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/attack?engagementId="+eng.ID, org, user, nil)
	var atk AttackMatrixView
	_ = json.Unmarshal(body, &atk)
	if len(atk.Techniques) != 1 || atk.Techniques[0].TechniqueID != "T1190" {
		t.Fatalf("unexpected ATT&CK matrix: %+v", atk)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/coa?engagementId="+eng.ID, org, user, nil)
	var coa CoAView
	_ = json.Unmarshal(body, &coa)
	if len(coa.Data) != 1 || coa.Data[0].Priority != "P0" {
		t.Fatalf("expected P0 CoA for critical finding, got %+v", coa.Data)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/hardening?engagementId="+eng.ID, org, user, nil)
	var hard HardeningView
	_ = json.Unmarshal(body, &hard)
	if !hard.ScopeEnforced || hard.OpenCritical != 1 || len(hard.Checks) != 5 {
		t.Fatalf("unexpected hardening posture: %+v", hard)
	}
}

func TestOperatorChatOfflineAndMockRouter(t *testing.T) {
	// 1. Offline grounded chat fallback.
	app, _, _ := newTestApp(t, EngineConfig{})
	const org, user = "hanzo", "operator@hanzo.ai"

	code, body := doReq(t, app, http.MethodPost, "/v1/cyber/engagements/seed-demo", org, user, nil)
	if code != http.StatusCreated {
		t.Fatalf("seed-demo = %d (%s)", code, body)
	}
	var seeded SeedDemoRes
	_ = json.Unmarshal(body, &seeded)

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/chat", org, user, ChatSendReq{
		EngagementID: seeded.Engagement.ID,
		Message:      "Summarize current findings and next verification step.",
		Model:        "zen-max",
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /v1/cyber/chat = %d (%s)", code, body)
	}
	var turn ChatTurnView
	_ = json.Unmarshal(body, &turn)
	if !turn.Offline || turn.Operator.Role != "operator" || turn.Assistant.Role != "assistant" {
		t.Fatalf("unexpected offline chat turn: %+v", turn)
	}
	if !strings.Contains(turn.Assistant.Content, "MDTF Tactical Enclave") {
		t.Fatalf("offline reply not grounded in engagement state: %q", turn.Assistant.Content)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/chat?engagementId="+seeded.Engagement.ID, org, user, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/cyber/chat = %d (%s)", code, body)
	}
	var hist ChatList
	_ = json.Unmarshal(body, &hist)
	if len(hist.Data) != 2 || hist.Data[0].Role != "operator" || hist.Data[1].Role != "assistant" {
		t.Fatalf("unexpected chat history: %+v", hist.Data)
	}

	// 2. Live Hanzo Router mock.
	var gotAuth, gotOrg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotOrg = r.Header.Get("X-Org-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"enso-auto","choices":[{"message":{"content":"Verified 2 critical/high findings; hold active replay until commander sign-off."}}],"usage":{"prompt_tokens":140,"completion_tokens":28}}`))
	}))
	defer srv.Close()

	liveApp, _, _ := newTestApp(t, EngineConfig{
		RouterURL:  srv.URL + "/v1",
		APIKey:     "hk-test-token",
		HTTPClient: srv.Client(),
	})
	code, body = doReq(t, liveApp, http.MethodPost, "/v1/cyber/chat", org, user, ChatSendReq{
		Message: "Status check",
	})
	if code != http.StatusCreated {
		t.Fatalf("live chat = %d (%s)", code, body)
	}
	var liveTurn ChatTurnView
	_ = json.Unmarshal(body, &liveTurn)
	if liveTurn.Offline || liveTurn.Assistant.OutputTokens != 28 || liveTurn.Assistant.InputTokens != 140 {
		t.Fatalf("unexpected live chat turn: %+v", liveTurn)
	}
	if gotAuth != "Bearer hk-test-token" || gotOrg != org {
		t.Fatalf("router headers wrong: auth=%q org=%q", gotAuth, gotOrg)
	}
}

func TestGovernorScopeRulesAndSandboxGating(t *testing.T) {
	if !MatchHostPattern("*.mdtf.test", "tak.mdtf.test") {
		t.Fatal("wildcard subdomain should match")
	}
	if !MatchHostPattern("!*.mdtf.test", "evil.external.test") {
		t.Fatal("negated host pattern should match out-of-scope host")
	}
	if MatchHostPattern("!*.mdtf.test", "c2.mdtf.test") {
		t.Fatal("negated host pattern must not match in-scope host")
	}
	if !MatchHostPattern("10.42.0.0/16", "10.42.9.5") {
		t.Fatal("CIDR pattern should match IP")
	}
	if !MatchPathPattern("/v1/dispatch/*", "/v1/dispatch/override") {
		t.Fatal("path prefix wildcard should match")
	}

	rules := []InterceptRule{
		{ID: "r1", Name: "allow", MatchHost: "*.mdtf.test", MatchPath: "/*", Action: "allow", Enabled: true},
		{ID: "r2", Name: "block-out", MatchHost: "!*.mdtf.test", MatchPath: "/*", Action: "block", Enabled: true},
		{ID: "r3", Name: "gate-c2", MatchHost: "c2.mdtf.test", MatchPath: "/v1/dispatch/*", Action: "require_approval", Enabled: true},
	}
	if d := EvaluateRules(rules, "https://outside.example.com/x"); d.Action != "block" {
		t.Fatalf("out-of-scope decision = %q, want block", d.Action)
	}
	if d := EvaluateRules(rules, "https://c2.mdtf.test/v1/dispatch/override"); d.Action != "require_approval" {
		t.Fatalf("c2 write path decision = %q, want require_approval", d.Action)
	}
	if d := EvaluateRules(rules, "https://enclave.mdtf.test/health"); d.Action != "allow" {
		t.Fatalf("in-scope read decision = %q, want allow", d.Action)
	}

	// Sandbox microVM gating via Engine.RunInSandbox.
	_, store, engine := newTestApp(t, EngineConfig{})
	ctx := context.Background()
	now := nowMS()
	eng := Engagement{
		ID: "eng_sbx", Org: "hanzo", Name: "Sandbox Lab", Target: "enclave.mdtf.test",
		Scope: []string{"*.mdtf.test"}, Mode: "enclave", Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.SaveEngagement(ctx, eng); err != nil {
		t.Fatalf("SaveEngagement: %v", err)
	}
	for _, r := range rules {
		r.Org = "hanzo"
		r.EngagementID = eng.ID
		if err := store.SaveRule(ctx, r); err != nil {
			t.Fatalf("SaveRule: %v", err)
		}
	}

	// Out-of-scope target is blocked fail-closed.
	blocked, err := engine.RunInSandbox(ctx, "hanzo", SandboxRunRequest{
		EngagementID: eng.ID, Tool: "cyber_http_probe", Action: "GET /", Target: "https://external.invalid/",
	})
	if err != nil || blocked.Status != "blocked" {
		t.Fatalf("expected blocked out-of-scope run, got %+v err=%v", blocked, err)
	}

	// Gated path creates pending Kai approval.
	held, err := engine.RunInSandbox(ctx, "hanzo", SandboxRunRequest{
		EngagementID: eng.ID, Tool: "cyber_http_exploit", Action: "Run exploit payload on dispatch", Target: "https://c2.mdtf.test/v1/dispatch/override",
	})
	if err != nil || held.Status != "awaiting_approval" || held.ApprovalID == "" {
		t.Fatalf("expected awaiting_approval + ApprovalID, got %+v err=%v", held, err)
	}

	// Allowed in-scope low-risk probe completes offline dry-run cleanly.
	sim, err := engine.RunInSandbox(ctx, "hanzo", SandboxRunRequest{
		EngagementID: eng.ID, Tool: "cyber_tls_audit", Action: "Inspect TLS handshake", Target: "https://enclave.mdtf.test/",
	})
	if err != nil || sim.Status != "simulated" || !sim.Offline {
		t.Fatalf("expected offline simulated dry-run, got %+v err=%v", sim, err)
	}
}

func TestZipProjectionsMCPOpenAPIAndOpCallPlane(t *testing.T) {
	app, _, _ := newTestApp(t, EngineConfig{Standalone: true}, MountConfig{Standalone: true})

	// 1. OpenAPI 3.1 endpoint /.well-known/openapi.json is live and contains all /v1/cyber/* routes.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openapi.json", nil)
	resp, err := app.Test(req, testCfg)
	if err != nil {
		t.Fatalf("GET /.well-known/openapi.json: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("openapi status = %d (%s), want 200", resp.StatusCode, body)
	}
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("unmarshal openapi: %v", err)
	}
	paths, _ := spec["paths"].(map[string]any)
	opCount := 0
	for p, rawItem := range paths {
		if !strings.HasPrefix(p, "/v1/cyber") {
			continue
		}
		item, _ := rawItem.(map[string]any)
		for method, rawOp := range item {
			opObj, _ := rawOp.(map[string]any)
			desc, _ := opObj["description"].(string)
			if strings.TrimSpace(desc) == "" {
				t.Errorf("OpenAPI op %s %s missing zipdoc description", strings.ToUpper(method), p)
			}
			opCount++
		}
	}
	if opCount != 30 {
		t.Fatalf("expected 30 typed /v1/cyber operations in OpenAPI, got %d", opCount)
	}

	// 2. MCP /mcp endpoint is live: initialize + tools/list + tools/call.
	mcpCall := func(payload string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(zip.HeaderOrg, "local")
		r.Header.Set(zip.HeaderUser, "mcp-tester")
		res, err := app.Test(r, testCfg)
		if err != nil {
			t.Fatalf("POST /mcp: %v", err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST /mcp = %d (%s), want 200", res.StatusCode, b)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal /mcp response: %v (%s)", err, b)
		}
		return out
	}

	initRes := mcpCall(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if initRes["result"].(map[string]any)["protocolVersion"] == nil {
		t.Fatalf("MCP initialize missing protocolVersion: %v", initRes)
	}

	listRes := mcpCall(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := listRes["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 30 {
		t.Fatalf("MCP tools/list returned %d tools, want 30", len(tools))
	}
	healthToolName := zip.ID("GET", "/v1/cyber/health")
	foundHealth := false
	for _, rawTool := range tools {
		tool := rawTool.(map[string]any)
		if strings.TrimSpace(tool["description"].(string)) == "" {
			t.Errorf("MCP tool %v missing description from zipdoc", tool["name"])
		}
		if tool["name"] == healthToolName {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Fatalf("MCP tools/list missing %q", healthToolName)
	}

	callPayload := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"` + healthToolName + `","arguments":{}}}`
	callRes := mcpCall(callPayload)
	content := callRes["result"].(map[string]any)["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"status":"ok"`) {
		t.Fatalf("MCP tools/call health unexpected output: %q", text)
	}

	// 3. ZAP op-call plane /.well-known/zip/op/<op> is live on the zip.App.
	// Calling the registered health op over ZAP content-type must succeed (200 application/zap),
	// and an unknown op must return a structured 404 call fault (not an unmounted route).
	opReq := httptest.NewRequest(http.MethodPost, zip.CallPath+healthToolName, nil)
	opReq.Header.Set("Content-Type", zip.CallContentType)
	opResp, err := app.Test(opReq, testCfg)
	if err != nil {
		t.Fatalf("POST %s%s: %v", zip.CallPath, healthToolName, err)
	}
	opBody, _ := io.ReadAll(opResp.Body)
	_ = opResp.Body.Close()
	if opResp.StatusCode != http.StatusOK {
		t.Fatalf("ZAP op-call %s%s = %d (ct=%q len=%d), want 200", zip.CallPath, healthToolName, opResp.StatusCode, opResp.Header.Get("Content-Type"), len(opBody))
	}
	if opResp.Header.Get("Content-Type") != zip.CallContentType {
		t.Fatalf("ZAP op-call content-type = %q, want %q", opResp.Header.Get("Content-Type"), zip.CallContentType)
	}

	// Also exercise in-process zip.Here directly against the same registered op.
	hv, err := zip.Here[NoIn, HealthView](context.Background(), app, healthToolName, &NoIn{})
	if err != nil || hv == nil || hv.Status != "ok" {
		t.Fatalf("zip.Here(%s) = %+v, err=%v", healthToolName, hv, err)
	}
}

func TestAuditHashChainTamperDetectionAndGovernedRun(t *testing.T) {
	app, store, _ := newTestApp(t, EngineConfig{})
	const org, user = "hanzo", "auditor@hanzo.ai"

	// 1. Create engagement -> appends seq=1 audit event.
	code, body := doReq(t, app, http.MethodPost, "/v1/cyber/engagements", org, user, CreateEngagementReq{
		Name:   "Audit Chain Lab",
		Target: "enclave.local.test",
		Scope:  []string{"enclave.local.test", "127.0.0.1"},
		Mode:   "airgap",
	})
	if code != http.StatusCreated {
		t.Fatalf("create engagement = %d (%s)", code, body)
	}
	var eng EngagementView
	_ = json.Unmarshal(body, &eng)

	// 2. Governed run against out-of-scope target is blocked fail-closed and recorded as seq=2.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/runs", org, user, ExecuteRunReq{
		EngagementID: eng.ID,
		Tool:         "cyber_probe_ports",
		Action:       "Scan unauthorized host",
		Target:       "outside.evil.test",
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /v1/cyber/runs = %d (%s)", code, body)
	}
	var blocked SandboxRunResult
	_ = json.Unmarshal(body, &blocked)
	if blocked.Status != "blocked" {
		t.Fatalf("expected out-of-scope run blocked, got %+v", blocked)
	}

	// 3. List and verify clean SHA-256 hash chain.
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/audit?engagementId="+eng.ID, org, user, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/cyber/audit = %d (%s)", code, body)
	}
	var list AuditListView
	_ = json.Unmarshal(body, &list)
	if len(list.Data) != 2 || list.Data[0].Seq != 1 || list.Data[1].Seq != 2 || list.Data[1].PrevHash != list.Data[0].Hash {
		t.Fatalf("unexpected hash-chained audit events: %+v", list.Data)
	}

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/audit/verify", org, user, AuditVerifyReq{EngagementID: eng.ID})
	if code != http.StatusOK {
		t.Fatalf("POST /v1/cyber/audit/verify = %d (%s)", code, body)
	}
	var rep AuditVerifyReport
	_ = json.Unmarshal(body, &rep)
	if !rep.Valid || rep.Events != 2 || rep.LastHash != list.Data[1].Hash {
		t.Fatalf("expected valid 2-event audit chain, got %+v", rep)
	}

	// 4. Simulate 1-byte tamper in SQLite and confirm immediate detection at seq=2.
	if _, err := store.db.Exec(`UPDATE cyber_audit_events SET payload_json = replace(payload_json, 'blocked', 'allowed') WHERE org=$1 AND engagement_id=$2 AND seq=2`, org, eng.ID); err != nil {
		t.Fatalf("tamper SQL: %v", err)
	}
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/audit/verify", org, user, AuditVerifyReq{EngagementID: eng.ID})
	if code != http.StatusOK {
		t.Fatalf("verify tampered = %d (%s)", code, body)
	}
	_ = json.Unmarshal(body, &rep)
	if rep.Valid || rep.FirstInvalidSeq != 2 {
		t.Fatalf("expected tamper detection at seq=2, got %+v", rep)
	}
}

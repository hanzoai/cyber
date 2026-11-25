// Copyright © 2026 Hanzo AI. MIT License.

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestFullAgenticLocalPrivateLLMAndNativeToolsE2E verifies the complete zero-stub
// end-to-end loop:
//  1. Configure Local Private LLM via PUT /v1/cyber/llm with ZERO API key.
//  2. Discover live models via GET /v1/cyber/models.
//  3. Execute a multi-turn autonomous agentic chat round (runRound=true):
//     - Turn 1: LLM calls cyber_http_probe against a real local target -> captures real HTTP traffic into SQLite.
//     - Turn 2: LLM calls record_and_verify_finding -> deterministic verbatim proof confirms finding!
//     - Turn 3: LLM attempts cyber_http_exploit -> Kai risk gate intercepts & queues pending approval!
//     - Turn 4: LLM summarizes verified finding + pending Kai approval.
//  4. Execute real native TLS audit against httptest.NewTLSServer and real DNS enum on localhost.
//  5. Verify the full SHA-256 hash-chained audit trail across every agentic action.
func TestFullAgenticLocalPrivateLLMAndNativeToolsE2E(t *testing.T) {
	// Real local vulnerable loopback HTTP fixture.
	vulnTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Enclave-Node", "loopback-fixture-01")
		_, _ = w.Write([]byte(`{"service":"tdp-gateway","mtls_required":false,"debug_token_leak":"exposed_internal_state"}`))
	}))
	defer vulnTarget.Close()

	// Real local TLS fixture for cyber_tls_audit.
	tlsFixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsFixture.Close()

	// Real local private OpenAI-compatible LLM server (NO API key required).
	var turnCount atomic.Int32
	var sawAuthHeader atomic.Bool
	var capturedTrafficID atomic.Value
	localLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthHeader.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "zen-coder-local-32b", "owned_by": "local-private"},
					{"id": "qwen3-coder-30b-a3b", "owned_by": "local-private"},
				},
			})
			return
		}
		var reqBody struct {
			Messages []map[string]any `json:"messages"`
			Tools    []map[string]any `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		if len(reqBody.Tools) == 0 {
			t.Errorf("expected agentic tool specs in runRound chat request")
		}
		step := turnCount.Add(1)
		switch step {
		case 1:
			// Ask control plane to probe our real HTTP fixture.
			argsJSON, _ := json.Marshal(map[string]any{"url": vulnTarget.URL + "/status", "method": "GET"})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": "zen-coder-local-32b",
				"choices": []map[string]any{{
					"message": map[string]any{
						"content": "",
						"tool_calls": []map[string]any{{
							"id":   "call_1",
							"type": "function",
							"function": map[string]any{
								"name":      "cyber_http_probe",
								"arguments": string(argsJSON),
							},
						}},
					},
				}},
			})
		case 2:
			// Extract trafficId from the framed <<<UNTRUSTED-...>>> tool response.
			last := reqBody.Messages[len(reqBody.Messages)-1]["content"].(string)
			if !strings.Contains(last, "<<<UNTRUSTED-") {
				t.Errorf("tool output was not framed in UNTRUSTED nonce boundary: %q", last)
			}
			idx := strings.Index(last, "trf_")
			if idx < 0 {
				t.Fatalf("expected captured trafficId in tool output: %q", last)
			}
			trID := last[idx : idx+20]
			capturedTrafficID.Store(trID)
			argsJSON, _ := json.Marshal(map[string]any{
				"title":          "Unauthenticated TDP Gateway mTLS Disabled",
				"severity":       "critical",
				"target":         vulnTarget.URL + "/status",
				"trafficId":      trID,
				"evidenceQuote":  `"mtls_required":false`,
				"cwe":            "CWE-306",
				"mitreTechnique": "T1190",
				"remediation":    "Require mutual TLS client certificates on all TDP gateway routes.",
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": "zen-coder-local-32b",
				"choices": []map[string]any{{
					"message": map[string]any{
						"content": "",
						"tool_calls": []map[string]any{{
							"id":   "call_2",
							"type": "function",
							"function": map[string]any{
								"name":      "record_and_verify_finding",
								"arguments": string(argsJSON),
							},
						}},
					},
				}},
			})
		case 3:
			// Attempt active exploit -> must be intercepted by Kai risk gate!
			argsJSON, _ := json.Marshal(map[string]any{
				"target": vulnTarget.URL + "/status",
				"action": "Execute active exploit payload against TDP gateway",
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": "zen-coder-local-32b",
				"choices": []map[string]any{{
					"message": map[string]any{
						"content": "",
						"tool_calls": []map[string]any{{
							"id":   "call_3",
							"type": "function",
							"function": map[string]any{
								"name":      "cyber_http_exploit",
								"arguments": string(argsJSON),
							},
						}},
					},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"model": "zen-coder-local-32b",
				"choices": []map[string]any{{
					"message": map[string]any{
						"content": "Verified critical mTLS bypass verbatim against captured HTTP traffic; active exploit verification held in Kai approval queue.",
					},
				}},
				"usage": map[string]any{"prompt_tokens": 310, "completion_tokens": 24},
			})
		}
	}))
	defer localLLM.Close()

	app, _, _ := newTestApp(t, EngineConfig{Standalone: true}, MountConfig{Standalone: true})

	// 1. Configure Local Private LLM with ZERO API key.
	code, body := doReq(t, app, http.MethodPut, "/v1/cyber/llm", "", "", UpdateLLMConfigReq{
		Provider:    LLMProviderLocalPrivate,
		BaseURL:     localLLM.URL + "/v1",
		Model:       "zen-coder-local-32b",
		ClearAPIKey: true,
	})
	if code != http.StatusOK {
		t.Fatalf("PUT /v1/cyber/llm = %d (%s)", code, body)
	}
	var llmCfg LLMConfigView
	_ = json.Unmarshal(body, &llmCfg)
	if llmCfg.Provider != LLMProviderLocalPrivate || !llmCfg.Ready || llmCfg.APIKeyConfigured {
		t.Fatalf("unexpected local private LLM config: %+v", llmCfg)
	}

	// 2. Discover live models from Local Private LLM.
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/models", "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/cyber/models = %d (%s)", code, body)
	}
	var models ModelListView
	_ = json.Unmarshal(body, &models)
	if len(models.Models) != 2 || models.Models[0].ID != "zen-coder-local-32b" {
		t.Fatalf("unexpected discovered models: %+v", models)
	}

	// 3. Create engagement scoped to 127.0.0.1 + allow rule + task.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/engagements", "", "", CreateEngagementReq{
		Name:   "Private Local Agentic E2E",
		Target: "127.0.0.1",
		Scope:  []string{"127.0.0.1", "localhost"},
		Mode:   "airgap",
	})
	if code != http.StatusCreated {
		t.Fatalf("create engagement = %d (%s)", code, body)
	}
	var eng EngagementView
	_ = json.Unmarshal(body, &eng)

	for _, host := range []string{"127.0.0.1", "localhost"} {
		code, _ = doReq(t, app, http.MethodPost, "/v1/cyber/intercept/rules", "", "", CreateRuleReq{
			EngagementID: eng.ID,
			Name:         "Allow local loopback assessment (" + host + ")",
			MatchHost:    host,
			MatchPath:    "/*",
			Action:       "allow",
		})
		if code != http.StatusCreated {
			t.Fatalf("create rule (%s) = %d", host, code)
		}
	}

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/tasks", "", "", CreateTaskReq{
		EngagementID: eng.ID,
		Title:        "Autonomous Local TDP Gateway Audit",
		Goal:         "Probe, verify verbatim proof, and gate active exploit",
		Phase:        "verify",
	})
	var task TaskView
	_ = json.Unmarshal(body, &task)

	// 4. Execute real multi-turn agentic round!
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/chat", "", "", ChatSendReq{
		EngagementID: eng.ID,
		TaskID:       task.ID,
		Message:      "Audit the local TDP gateway endpoint, verify any auth defect verbatim, and check exploitability.",
		RunRound:     true,
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /v1/cyber/chat (agentic) = %d (%s)", code, body)
	}
	var turn ChatTurnView
	_ = json.Unmarshal(body, &turn)
	if turn.Offline || turn.Provider != LLMProviderLocalPrivate || len(turn.ToolRuns) != 3 {
		t.Fatalf("unexpected agentic turn: offline=%v provider=%q runs=%d (%+v)", turn.Offline, turn.Provider, len(turn.ToolRuns), turn.ToolRuns)
	}
	if sawAuthHeader.Load() {
		t.Fatal("local private LLM should not receive an Authorization header when no API key is configured")
	}
	if turn.ToolRuns[0].Status != "completed" || turn.ToolRuns[0].Runtime != "native-http" {
		t.Fatalf("expected run[0] native-http completed, got %+v", turn.ToolRuns[0])
	}
	if turn.ToolRuns[1].Status != "verified" || turn.ToolRuns[1].Runtime != "verbatim-verifier" {
		t.Fatalf("expected run[1] verbatim verified finding, got %+v", turn.ToolRuns[1])
	}
	if turn.ToolRuns[2].Status != "awaiting_approval" || turn.ToolRuns[2].ApprovalID == "" {
		t.Fatalf("expected run[2] exploit held in Kai approval queue, got %+v", turn.ToolRuns[2])
	}

	// Verify captured traffic, verified finding, pending approval, and task reasoning graph nodes!
	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/findings?engagementId="+eng.ID, "", "", nil)
	var fnds FindingList
	_ = json.Unmarshal(body, &fnds)
	if len(fnds.Data) != 1 || !fnds.Data[0].Verified {
		t.Fatalf("expected 1 verbatim-verified finding, got %+v", fnds.Data)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/approvals?engagementId="+eng.ID+"&status=pending", "", "", nil)
	var aprs ApprovalList
	_ = json.Unmarshal(body, &aprs)
	if len(aprs.Data) != 1 {
		t.Fatalf("expected 1 Kai pending approval, got %+v", aprs.Data)
	}

	code, body = doReq(t, app, http.MethodGet, "/v1/cyber/tasks/"+task.ID+"/graph", "", "", nil)
	var graph TaskGraphView
	_ = json.Unmarshal(body, &graph)
	if len(graph.Nodes) < 4 {
		t.Fatalf("expected >=4 graph nodes (goal + action + finding + kai hint), got %d", len(graph.Nodes))
	}

	// 5. Real native TLS audit against httptest.NewTLSServer + real DNS enum on localhost.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/runs", "", "", ExecuteRunReq{
		EngagementID: eng.ID,
		Tool:         "cyber_tls_audit",
		Action:       "Audit TLS handshake on local fixture",
		Target:       tlsFixture.URL,
	})
	if code != http.StatusCreated {
		t.Fatalf("cyber_tls_audit = %d (%s)", code, body)
	}
	var tlsRun SandboxRunResult
	_ = json.Unmarshal(body, &tlsRun)
	if tlsRun.Status != "completed" || !strings.Contains(tlsRun.Output, "TLS 1.") {
		t.Fatalf("expected real TLS handshake output, got %+v", tlsRun)
	}

	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/runs", "", "", ExecuteRunReq{
		EngagementID: eng.ID,
		Tool:         "cyber_dns_enum",
		Action:       "Resolve localhost DNS",
		Target:       "localhost",
	})
	var dnsRun SandboxRunResult
	_ = json.Unmarshal(body, &dnsRun)
	if dnsRun.Status != "completed" || !strings.Contains(dnsRun.Output, "127.0.0.1") {
		t.Fatalf("expected real DNS resolution of localhost, got %+v", dnsRun)
	}

	// 6. Verify entire SHA-256 hash-chained audit trail across all recorded events.
	code, body = doReq(t, app, http.MethodPost, "/v1/cyber/audit/verify", "", "", AuditVerifyReq{EngagementID: eng.ID})
	var aud AuditVerifyReport
	_ = json.Unmarshal(body, &aud)
	if !aud.Valid || aud.Events < 5 {
		t.Fatalf("expected valid SHA-256 audit chain with >=5 events, got %+v", aud)
	}
}

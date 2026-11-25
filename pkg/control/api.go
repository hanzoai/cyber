// Copyright © 2026 Hanzo AI. MIT License.

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zap-proto/zip"
)

// MountConfig tunes tenant resolution and runtime metadata for Mount.
type MountConfig struct {
	// Standalone enables local single-operator mode, defaulting missing identity
	// headers to DefaultOrg ("local") instead of refusing with 401.
	Standalone bool
	// DefaultOrg sets the fallback org in Standalone mode (defaults to "local").
	DefaultOrg string
	// Backend identifies the control plane runtime reported by GET /v1/cyber/health.
	Backend string
}

// Mount registers all typed Hanzo Cyber control plane operations under /v1/cyber
// on app, exposing REST, OpenAPI 3.1, MCP (/mcp), and ZAP op-call (/.well-known/zip/op/)
// projections from one typed Go handler surface.
//
//go:generate go run github.com/zap-proto/zip/cmd/zipdoc
func Mount(app *zip.App, store *Store, engine *Engine, cfgs ...MountConfig) {
	if app == nil || store == nil {
		return
	}
	if engine == nil {
		engine = NewEngine(store, EngineConfig{})
	}
	var cfg MountConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	if engine.cfg.Standalone {
		cfg.Standalone = true
	}
	if strings.TrimSpace(cfg.DefaultOrg) == "" {
		cfg.DefaultOrg = "local"
	}
	if strings.TrimSpace(cfg.Backend) == "" {
		if cfg.Standalone {
			cfg.Backend = "hanzo-cyber-local"
		} else {
			cfg.Backend = "hanzo-cyber"
		}
	}

	g := app.Group("/v1/cyber").Tag("cyber")
	o := ops{
		store:      store,
		engine:     engine,
		standalone: cfg.Standalone,
		defaultOrg: cfg.DefaultOrg,
		backend:    cfg.Backend,
	}

	g.Get("/health", o.health)
	g.Get("/dashboard", o.dashboard)

	g.Get("/engagements", o.listEngagements)
	g.Post("/engagements", o.createEngagement, zip.WithStatus(http.StatusCreated))
	g.Post("/engagements/seed-demo", o.seedDemo, zip.WithStatus(http.StatusCreated))

	g.Get("/tasks", o.listTasks)
	g.Post("/tasks", o.createTask, zip.WithStatus(http.StatusCreated))
	g.Get("/tasks/:id/graph", o.getTaskGraph)
	g.Post("/tasks/:id/nodes", o.addGraphNode, zip.WithStatus(http.StatusCreated))

	g.Get("/findings", o.listFindings)
	g.Post("/findings", o.createFinding, zip.WithStatus(http.StatusCreated))
	g.Patch("/findings/:id", o.updateFinding)
	g.Post("/findings/:id/verify", o.verifyFinding)

	g.Get("/traffic", o.listTraffic)
	g.Post("/traffic", o.recordTraffic, zip.WithStatus(http.StatusCreated))

	g.Get("/approvals", o.listApprovals)
	g.Post("/approvals", o.submitApproval, zip.WithStatus(http.StatusCreated))
	g.Post("/approvals/:id/decide", o.decideApproval)

	g.Get("/intercept/rules", o.listRules)
	g.Post("/intercept/rules", o.createRule, zip.WithStatus(http.StatusCreated))
	g.Delete("/intercept/rules/:id", o.deleteRule)

	g.Get("/attack", o.attackMatrix)
	g.Get("/coa", o.courseOfAction)
	g.Get("/hardening", o.hardeningPosture)

	g.Get("/chat", o.listChat)
	g.Post("/chat", o.sendChat, zip.WithStatus(http.StatusCreated))

	g.Post("/runs", o.executeRun, zip.WithStatus(http.StatusCreated))
	g.Get("/audit", o.listAudit)
	g.Post("/audit/verify", o.verifyAudit)

	g.Get("/tools", o.listTools)
}

type ops struct {
	store      *Store
	engine     *Engine
	standalone bool
	defaultOrg string
	backend    string
}

func (o ops) authorize(ctx context.Context) (org, actor string, err error) {
	if tenant, ok := zip.Tenant(ctx); ok {
		c := zip.CallerOf(ctx)
		actor = strings.TrimSpace(c.User)
		if actor == "" {
			actor = tenant
		}
		return tenant, actor, nil
	}
	if o.standalone {
		c := zip.CallerOf(ctx)
		org = strings.TrimSpace(c.Org)
		if org == "" {
			org = o.defaultOrg
		}
		actor = strings.TrimSpace(c.User)
		if actor == "" {
			actor = "local-operator"
		}
		return org, actor, nil
	}
	return "", "", zip.ErrUnauthorized("X-Org-Id and X-User-Id identity headers are required")
}

var lastNowMS atomic.Int64

func nowMS() int64 {
	for {
		prev := lastNowMS.Load()
		cur := time.Now().UnixMilli()
		if cur <= prev {
			cur = prev + 1
		}
		if lastNowMS.CompareAndSwap(prev, cur) {
			return cur
		}
	}
}

// ---- Wire Types ----

// NoIn is an empty input type for parameterless operations.
type NoIn struct{}

// HealthView reports liveness and runtime metadata for the Hanzo Cyber control plane.
type HealthView struct {
	// Status is "ok" when the cyber control store is open and accepting requests.
	Status string `json:"status"`
	// Backend names the native zip runtime serving /v1/cyber.
	Backend string `json:"backend"`
	// Mode reports whether the control plane is running in standalone or multi-tenant mode.
	Mode string `json:"mode"`
	// RouterReady reports whether live Hanzo Router credentials are configured.
	RouterReady bool `json:"routerReady"`
	// SandboxReady reports whether live Hanzo /v1/sandbox microVM credentials are configured.
	SandboxReady bool `json:"sandboxReady"`
	// ProbeReady reports whether the local zero-dependency Rust cyber-probe scanner binary is available.
	ProbeReady bool `json:"probeReady"`
}

// EngagementFilter scopes queries to a single engagement when provided.
type EngagementFilter struct {
	// EngagementID narrows results to one engagement when non-empty.
	EngagementID string `json:"engagementId"`
}

// DashboardView summarizes an org's cyber posture and operational counts.
type DashboardView struct {
	// Org is the authenticated caller organization.
	Org string `json:"org"`
	// Stage marks the release stage of Hanzo Cyber.
	Stage string `json:"stage"`
	// Engagements is the total number of authorized engagements in the org.
	Engagements int `json:"engagements"`
	// Tasks is the number of cyber tasks across the selected scope.
	Tasks int `json:"tasks"`
	// FindingsTotal is the total number of recorded security findings.
	FindingsTotal int `json:"findingsTotal"`
	// FindingsVerified is the number of findings backed by verbatim captured proof.
	FindingsVerified int `json:"findingsVerified"`
	// Critical is the count of critical-severity findings.
	Critical int `json:"critical"`
	// High is the count of high-severity findings.
	High int `json:"high"`
	// Medium is the count of medium-severity findings.
	Medium int `json:"medium"`
	// Low is the count of low-severity findings.
	Low int `json:"low"`
	// PendingApprovals is the number of Kai-gated actions waiting on human approval.
	PendingApprovals int `json:"pendingApprovals"`
	// TrafficCount is the number of captured HTTP exchanges available for proof binding.
	TrafficCount int `json:"trafficCount"`
	// RulesCount is the number of active scope and intercept governance rules.
	RulesCount int `json:"rulesCount"`
	// VerificationRate is the percentage (0-100) of findings verified verbatim against traffic.
	VerificationRate int `json:"verificationRate"`
}

// EngagementView is one authorized cyber engagement workspace.
type EngagementView struct {
	// ID uniquely identifies the engagement.
	ID string `json:"id"`
	// Name is the human-readable engagement title.
	Name string `json:"name"`
	// Target is the primary host, CIDR, or enclave under assessment.
	Target string `json:"target"`
	// Scope lists authorized hostnames, CIDRs, or environments.
	Scope []string `json:"scope"`
	// Mode describes the execution posture (enclave, cloud, hybrid, airgap).
	Mode string `json:"mode"`
	// Status is the engagement lifecycle state (active, paused, completed).
	Status string `json:"status"`
	// Synthetic marks lab/demonstration engagements using synthetic targets.
	Synthetic bool `json:"synthetic"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
	// UpdatedAt is the last update timestamp in Unix milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
}

// EngagementList returns an org's engagements.
type EngagementList struct {
	// Data holds the engagements ordered newest first.
	Data []EngagementView `json:"data"`
}

// CreateEngagementReq defines a new authorized cyber engagement.
type CreateEngagementReq struct {
	// Name is the engagement display name.
	Name string `json:"name" validate:"required"`
	// Target is the primary system or enclave host under test.
	Target string `json:"target" validate:"required"`
	// Scope enumerates authorized targets within Rules of Engagement.
	Scope []string `json:"scope"`
	// Mode sets execution mode: enclave, cloud, hybrid, or airgap.
	Mode string `json:"mode"`
	// Synthetic marks lab/demo engagements explicitly.
	Synthetic bool `json:"synthetic"`
}

// SeedDemoRes returns the seeded synthetic lab engagement and record counts.
type SeedDemoRes struct {
	// Engagement is the seeded synthetic MDTF tactical enclave lab engagement.
	Engagement EngagementView `json:"engagement"`
	// Tasks is the number of tasks seeded.
	Tasks int `json:"tasks"`
	// Findings is the number of findings seeded.
	Findings int `json:"findings"`
	// Traffic is the number of captured HTTP traffic records seeded.
	Traffic int `json:"traffic"`
	// Approvals is the number of Kai approval records seeded.
	Approvals int `json:"approvals"`
	// Rules is the number of scope/intercept rules seeded.
	Rules int `json:"rules"`
}

// TaskView is an autonomous or operator-guided cyber objective.
type TaskView struct {
	// ID uniquely identifies the task.
	ID string `json:"id"`
	// EngagementID links the task to its parent engagement.
	EngagementID string `json:"engagementId"`
	// Title is the concise task name.
	Title string `json:"title"`
	// Goal states the verification objective.
	Goal string `json:"goal"`
	// Status is active, paused, completed, or blocked.
	Status string `json:"status"`
	// Phase is recon, enumerate, verify, govern, or report.
	Phase string `json:"phase"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
	// UpdatedAt is the last update timestamp in Unix milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
}

// TaskList returns tasks scoped to an org or engagement.
type TaskList struct {
	// Data holds the tasks ordered newest first.
	Data []TaskView `json:"data"`
}

// CreateTaskReq creates a task and its root GOAL graph node.
type CreateTaskReq struct {
	// EngagementID identifies the parent engagement.
	EngagementID string `json:"engagementId" validate:"required"`
	// Title names the cyber task.
	Title string `json:"title" validate:"required"`
	// Goal states the desired verification outcome.
	Goal string `json:"goal"`
	// Phase sets the starting operational phase (defaults to recon).
	Phase string `json:"phase"`
}

// TaskRef addresses a single task by path parameter.
type TaskRef struct {
	// ID is the task identifier from the URL path.
	ID string `json:"id"`
}

// GraphNodeView is one node in a task reasoning graph.
type GraphNodeView struct {
	// ID uniquely identifies the node.
	ID string `json:"id"`
	// TaskID links the node to its task.
	TaskID string `json:"taskId"`
	// Kind is goal, intent, finding, hint, or action.
	Kind string `json:"kind"`
	// Label is the concise node caption rendered on the graph canvas.
	Label string `json:"label"`
	// Detail carries full technical context or rationale.
	Detail string `json:"detail"`
	// Status is active, verified, pending, blocked, or done.
	Status string `json:"status"`
	// Severity carries finding severity when kind is finding.
	Severity string `json:"severity,omitempty"`
	// ParentID links to the upstream node in the reasoning chain.
	ParentID string `json:"parentId,omitempty"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// TaskGraphView returns a task together with its ordered reasoning nodes.
type TaskGraphView struct {
	// Task is the root task metadata.
	Task TaskView `json:"task"`
	// Nodes is the ordered list of GOAL, INTENT, FINDING, HINT, and ACTION nodes.
	Nodes []GraphNodeView `json:"nodes"`
}

// AddGraphNodeReq appends a node to a task's reasoning graph.
type AddGraphNodeReq struct {
	// ID is the task identifier from the URL path.
	ID string `json:"id"`
	// Kind is goal, intent, finding, hint, or action.
	Kind string `json:"kind" validate:"required"`
	// Label is the short node title shown on the graph.
	Label string `json:"label" validate:"required"`
	// Detail provides operator or agent rationale.
	Detail string `json:"detail"`
	// Status sets the node status (defaults to active).
	Status string `json:"status"`
	// Severity sets optional severity for finding nodes.
	Severity string `json:"severity"`
	// ParentID connects this node to an existing upstream node.
	ParentID string `json:"parentId"`
}

// FindingFilter filters finding queries.
type FindingFilter struct {
	// EngagementID narrows findings to one engagement.
	EngagementID string `json:"engagementId"`
	// Severity narrows findings to critical, high, medium, low, or info.
	Severity string `json:"severity"`
	// Status narrows findings to open, verified, remediated, or false_positive.
	Status string `json:"status"`
}

// FindingView is a recorded security finding with verbatim proof state.
type FindingView struct {
	// ID uniquely identifies the finding.
	ID string `json:"id"`
	// EngagementID links the finding to its engagement.
	EngagementID string `json:"engagementId"`
	// TaskID links the finding to the originating task when set.
	TaskID string `json:"taskId,omitempty"`
	// Title summarizes the vulnerability or misconfiguration.
	Title string `json:"title"`
	// Severity ranks impact: critical, high, medium, low, or info.
	Severity string `json:"severity"`
	// Category classifies the vulnerability family.
	Category string `json:"category"`
	// CWE records the Common Weakness Enumeration identifier.
	CWE string `json:"cwe,omitempty"`
	// MitreTechnique records the MITRE ATT&CK technique ID (for example T1078).
	MitreTechnique string `json:"mitreTechnique,omitempty"`
	// MitreTactic records the MITRE ATT&CK tactic name.
	MitreTactic string `json:"mitreTactic,omitempty"`
	// Status is open, verified, remediated, or false_positive.
	Status string `json:"status"`
	// Target names the affected endpoint, host, or service.
	Target string `json:"target"`
	// EvidenceQuote is the exact substring expected verbatim in bound HTTP traffic.
	EvidenceQuote string `json:"evidenceQuote,omitempty"`
	// TrafficID references the captured HTTP exchange backing this finding.
	TrafficID string `json:"trafficId,omitempty"`
	// Verified is true only when EvidenceQuote matched bound traffic verbatim.
	Verified bool `json:"verified"`
	// VerificationNote explains the outcome of verbatim proof verification.
	VerificationNote string `json:"verificationNote,omitempty"`
	// Remediation describes concrete fix steps.
	Remediation string `json:"remediation,omitempty"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
	// UpdatedAt is the last update timestamp in Unix milliseconds.
	UpdatedAt int64 `json:"updatedAt"`
}

// FindingList returns filtered findings.
type FindingList struct {
	// Data holds the matching findings ordered newest first.
	Data []FindingView `json:"data"`
}

// CreateFindingReq records a new finding inside an engagement.
type CreateFindingReq struct {
	// EngagementID identifies the engagement.
	EngagementID string `json:"engagementId" validate:"required"`
	// TaskID optionally binds the finding to a task.
	TaskID string `json:"taskId"`
	// Title summarizes the finding.
	Title string `json:"title" validate:"required"`
	// Severity is critical, high, medium, low, or info.
	Severity string `json:"severity"`
	// Category names the weakness class.
	Category string `json:"category"`
	// CWE records the CWE identifier.
	CWE string `json:"cwe"`
	// MitreTechnique records the ATT&CK technique ID.
	MitreTechnique string `json:"mitreTechnique"`
	// MitreTactic records the ATT&CK tactic.
	MitreTactic string `json:"mitreTactic"`
	// Target names the affected host or endpoint.
	Target string `json:"target"`
	// EvidenceQuote is the exact proof substring to verify against traffic.
	EvidenceQuote string `json:"evidenceQuote"`
	// TrafficID binds a captured traffic record for verbatim verification.
	TrafficID string `json:"trafficId"`
	// Remediation records concrete remediation guidance.
	Remediation string `json:"remediation"`
}

// UpdateFindingReq updates finding workflow status, evidence, or remediation.
type UpdateFindingReq struct {
	// ID is the finding identifier from the URL path.
	ID string `json:"id"`
	// Status transitions the finding to open, verified, remediated, or false_positive.
	Status string `json:"status"`
	// EvidenceQuote updates the proof substring.
	EvidenceQuote string `json:"evidenceQuote"`
	// TrafficID updates the bound captured HTTP exchange.
	TrafficID string `json:"trafficId"`
	// Remediation updates remediation guidance.
	Remediation string `json:"remediation"`
}

// VerifyFindingReq triggers deterministic verbatim proof verification against traffic.
type VerifyFindingReq struct {
	// ID is the finding identifier from the URL path.
	ID string `json:"id"`
	// TrafficID optionally binds a captured traffic record before verifying.
	TrafficID string `json:"trafficId"`
	// EvidenceQuote optionally supplies the exact proof quote before verifying.
	EvidenceQuote string `json:"evidenceQuote"`
}

// TrafficFilter narrows captured HTTP traffic queries.
type TrafficFilter struct {
	// EngagementID narrows records to one engagement.
	EngagementID string `json:"engagementId"`
	// Host filters captured exchanges by hostname.
	Host string `json:"host"`
}

// TrafficView is one captured HTTP request/response exchange.
type TrafficView struct {
	// ID uniquely identifies the captured traffic record.
	ID string `json:"id"`
	// EngagementID links the exchange to its engagement.
	EngagementID string `json:"engagementId"`
	// TaskID links the exchange to a task when present.
	TaskID string `json:"taskId,omitempty"`
	// Method is the HTTP verb.
	Method string `json:"method"`
	// URL is the full request URL.
	URL string `json:"url"`
	// Host is the extracted target hostname.
	Host string `json:"host"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"statusCode"`
	// RequestHeaders holds raw request headers.
	RequestHeaders string `json:"requestHeaders"`
	// RequestBody holds raw request payload.
	RequestBody string `json:"requestBody"`
	// ResponseHeaders holds raw response headers.
	ResponseHeaders string `json:"responseHeaders"`
	// ResponseBody holds raw response payload used for verbatim proof checks.
	ResponseBody string `json:"responseBody"`
	// LatencyMS is the observed round-trip latency in milliseconds.
	LatencyMS int `json:"latencyMs"`
	// CreatedAt is the capture timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// TrafficList returns captured HTTP exchanges.
type TrafficList struct {
	// Data holds captured exchanges ordered newest first.
	Data []TrafficView `json:"data"`
}

// RecordTrafficReq ingests a captured HTTP exchange for inspection and proof binding.
type RecordTrafficReq struct {
	// EngagementID identifies the engagement.
	EngagementID string `json:"engagementId" validate:"required"`
	// TaskID optionally links the exchange to a task.
	TaskID string `json:"taskId"`
	// Method is the HTTP verb (defaults to GET).
	Method string `json:"method"`
	// URL is the target URL.
	URL string `json:"url" validate:"required"`
	// Host overrides the parsed hostname when provided.
	Host string `json:"host"`
	// StatusCode is the HTTP status code (defaults to 200).
	StatusCode int `json:"statusCode"`
	// RequestHeaders captures serialized request headers.
	RequestHeaders string `json:"requestHeaders"`
	// RequestBody captures the request body.
	RequestBody string `json:"requestBody"`
	// ResponseHeaders captures serialized response headers.
	ResponseHeaders string `json:"responseHeaders"`
	// ResponseBody captures the response body.
	ResponseBody string `json:"responseBody"`
	// LatencyMS records request duration in milliseconds.
	LatencyMS int `json:"latencyMs"`
}

// ApprovalFilter narrows Kai approval queue queries.
type ApprovalFilter struct {
	// EngagementID narrows approvals to one engagement.
	EngagementID string `json:"engagementId"`
	// Status narrows approvals to pending, approved, denied, or always_allow.
	Status string `json:"status"`
}

// ApprovalView is one Kai risk-scored action gate.
type ApprovalView struct {
	// ID uniquely identifies the approval request.
	ID string `json:"id"`
	// EngagementID links the request to its engagement.
	EngagementID string `json:"engagementId"`
	// TaskID links the request to its task when present.
	TaskID string `json:"taskId,omitempty"`
	// Action describes the proposed command, probe, or mutation.
	Action string `json:"action"`
	// Target names the host or endpoint affected.
	Target string `json:"target"`
	// Tool names the Hanzo Cyber tool or module requesting execution.
	Tool string `json:"tool"`
	// RiskScore is Kai's deterministic risk score from 0 to 100.
	RiskScore int `json:"riskScore"`
	// RiskLevel categorizes the score as low, medium, high, or critical.
	RiskLevel string `json:"riskLevel"`
	// KaiRationale explains why Kai assigned the risk score and required review.
	KaiRationale string `json:"kaiRationale"`
	// Status is pending, approved, denied, or always_allow.
	Status string `json:"status"`
	// DecidedBy records the authenticated IAM subject who made the decision.
	DecidedBy string `json:"decidedBy,omitempty"`
	// DecidedAt records when the decision occurred in Unix milliseconds.
	DecidedAt int64 `json:"decidedAt,omitempty"`
	// CreatedAt is when the action entered the queue in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// ApprovalList returns Kai approvals.
type ApprovalList struct {
	// Data holds approval items ordered newest first.
	Data []ApprovalView `json:"data"`
}

// SubmitApprovalReq queues an action for Kai deterministic risk scoring.
type SubmitApprovalReq struct {
	// EngagementID identifies the engagement.
	EngagementID string `json:"engagementId" validate:"required"`
	// TaskID optionally links the action to a task.
	TaskID string `json:"taskId"`
	// Action describes the exact command or operation to evaluate.
	Action string `json:"action" validate:"required"`
	// Target names the host, service, or asset.
	Target string `json:"target" validate:"required"`
	// Tool names the tool requesting execution.
	Tool string `json:"tool"`
}

// DecideApprovalReq records a human decision on a Kai-gated action.
type DecideApprovalReq struct {
	// ID is the approval identifier from the URL path.
	ID string `json:"id"`
	// Decision must be approved, denied, or always_allow.
	Decision string `json:"decision" validate:"required"`
}

// RuleView is one scope or intercept governance rule.
type RuleView struct {
	// ID uniquely identifies the rule.
	ID string `json:"id"`
	// EngagementID scopes the rule to an engagement, or empty for org-wide.
	EngagementID string `json:"engagementId,omitempty"`
	// Name labels the rule.
	Name string `json:"name"`
	// MatchHost is the hostname pattern matched by this rule.
	MatchHost string `json:"matchHost"`
	// MatchPath is the URL path prefix or wildcard matched by this rule.
	MatchPath string `json:"matchPath"`
	// Action is allow, block, require_approval, or tag.
	Action string `json:"action"`
	// Enabled reports whether the rule is enforced.
	Enabled bool `json:"enabled"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// RuleList returns intercept and scope rules.
type RuleList struct {
	// Data holds rules ordered newest first.
	Data []RuleView `json:"data"`
}

// CreateRuleReq creates a scope or intercept rule.
type CreateRuleReq struct {
	// EngagementID optionally limits the rule to one engagement.
	EngagementID string `json:"engagementId"`
	// Name describes the rule.
	Name string `json:"name" validate:"required"`
	// MatchHost sets the target host pattern (defaults to *).
	MatchHost string `json:"matchHost"`
	// MatchPath sets the target path pattern (defaults to /*).
	MatchPath string `json:"matchPath"`
	// Action is allow, block, require_approval, or tag.
	Action string `json:"action"`
}

// RuleRef addresses a single intercept rule by path parameter.
type RuleRef struct {
	// ID is the rule identifier from the URL path.
	ID string `json:"id"`
}

// DeleteRes confirms deletion of a record.
type DeleteRes struct {
	// Deleted is true when the record was removed.
	Deleted bool `json:"deleted"`
	// ID is the deleted record identifier.
	ID string `json:"id"`
}

// AttackTechniqueView maps observed findings to one MITRE ATT&CK technique.
type AttackTechniqueView struct {
	// TechniqueID is the MITRE ATT&CK technique ID (for example T1190).
	TechniqueID string `json:"techniqueId"`
	// Tactic is the parent MITRE ATT&CK tactic.
	Tactic string `json:"tactic"`
	// Name summarizes the observed technique or finding class.
	Name string `json:"name"`
	// FindingCount is the number of findings mapped to this technique.
	FindingCount int `json:"findingCount"`
	// VerifiedCount is the number of verbatim-verified findings mapped here.
	VerifiedCount int `json:"verifiedCount"`
	// MaxSeverity is the highest severity observed for this technique.
	MaxSeverity string `json:"maxSeverity"`
}

// AttackMatrixView summarizes MITRE ATT&CK coverage across an org or engagement.
type AttackMatrixView struct {
	// Tactics lists unique MITRE ATT&CK tactics observed.
	Tactics []string `json:"tactics"`
	// Techniques lists observed ATT&CK techniques ranked by severity.
	Techniques []AttackTechniqueView `json:"techniques"`
}

// CoAItemView is a prioritized Course of Action remediation option.
type CoAItemView struct {
	// ID identifies the course of action.
	ID string `json:"id"`
	// Title names the remediation action.
	Title string `json:"title"`
	// Priority is P0, P1, P2, or P3.
	Priority string `json:"priority"`
	// RiskReduction estimates percentage risk reduction (1-100).
	RiskReduction int `json:"riskReduction"`
	// Effort estimates implementation complexity (low, medium, high).
	Effort string `json:"effort"`
	// MitreTechnique names the ATT&CK technique mitigated.
	MitreTechnique string `json:"mitreTechnique,omitempty"`
	// FindingIDs lists finding identifiers closed by this action.
	FindingIDs []string `json:"findingIds"`
	// Summary describes the concrete operational change.
	Summary string `json:"summary"`
}

// CoAView returns prioritized Courses of Action computed from open findings.
type CoAView struct {
	// Data holds prioritized courses of action ordered highest priority first.
	Data []CoAItemView `json:"data"`
}

// HardeningCheckView reports one enclave hardening or governance control check.
type HardeningCheckView struct {
	// ID uniquely identifies the control check.
	ID string `json:"id"`
	// Control names the security control or NIST/DoD baseline check.
	Control string `json:"control"`
	// Status is pass, warn, or fail.
	Status string `json:"status"`
	// Detail explains the live evidence behind the check status.
	Detail string `json:"detail"`
}

// HardeningView summarizes enclave hardening, governance, and proof posture.
type HardeningView struct {
	// Score is the aggregate hardening readiness score from 0 to 100.
	Score int `json:"score"`
	// ScopeEnforced reports whether explicit intercept/scope rules are configured.
	ScopeEnforced bool `json:"scopeEnforced"`
	// VerbatimVerified reports how many findings carry verbatim captured proof.
	VerbatimVerified int `json:"verbatimVerified"`
	// OpenCritical reports how many unmitigated critical findings remain.
	OpenCritical int `json:"openCritical"`
	// Checks lists individual posture control evaluations.
	Checks []HardeningCheckView `json:"checks"`
}

// ChatFilter narrows persisted Enso/Zen operator chat history queries.
type ChatFilter struct {
	// EngagementID narrows chat messages to one engagement.
	EngagementID string `json:"engagementId"`
	// TaskID narrows chat messages to one task.
	TaskID string `json:"taskId"`
}

// ChatMessageView is one persisted operator or assistant chat message.
type ChatMessageView struct {
	// ID uniquely identifies the message.
	ID string `json:"id"`
	// EngagementID links the message to its engagement when set.
	EngagementID string `json:"engagementId,omitempty"`
	// TaskID links the message to its task when set.
	TaskID string `json:"taskId,omitempty"`
	// Role is "operator" or "assistant".
	Role string `json:"role"`
	// Content holds the message body.
	Content string `json:"content"`
	// Model records the Enso/Zen model that produced or received the message.
	Model string `json:"model,omitempty"`
	// InputTokens records prompt tokens consumed when routed through Hanzo Router.
	InputTokens int `json:"inputTokens,omitempty"`
	// OutputTokens records completion tokens generated when routed through Hanzo Router.
	OutputTokens int `json:"outputTokens,omitempty"`
	// CreatedAt is the message timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// ChatList returns persisted Enso/Zen operator chat messages in chronological order.
type ChatList struct {
	// Data holds chat messages ordered oldest to newest.
	Data []ChatMessageView `json:"data"`
}

// ChatSendReq submits an operator message to the autonomous Enso/Zen cyber operator.
type ChatSendReq struct {
	// EngagementID grounds the operator turn in a specific engagement.
	EngagementID string `json:"engagementId"`
	// TaskID optionally scopes the operator turn to a task.
	TaskID string `json:"taskId"`
	// Message is the operator prompt text.
	Message string `json:"message" validate:"required"`
	// Model optionally selects a specific Enso/Zen model (defaults to enso-auto).
	Model string `json:"model"`
}

// ChatTurnView returns both the recorded operator message and the Enso/Zen reply.
type ChatTurnView struct {
	// Operator is the persisted operator message.
	Operator ChatMessageView `json:"operator"`
	// Assistant is the persisted Enso/Zen assistant reply.
	Assistant ChatMessageView `json:"assistant"`
	// Offline is true when the deterministic local fallback synthesized the reply.
	Offline bool `json:"offline"`
}

// ToolFilter narrows the Hanzo Cyber tool catalog query.
type ToolFilter struct {
	// Group optionally filters tools to one category (recon, web, network, verify, govern, sandbox, analysis).
	Group string `json:"group"`
}

// ToolCatalogView summarizes the available Hanzo Cyber tools grouped by domain.
type ToolCatalogView struct {
	// Tools holds the matching tool descriptors.
	Tools []ToolDescriptor `json:"tools"`
	// Total is the number of tools returned.
	Total int `json:"total"`
	// ByGroup maps each tool group name to its tool count.
	ByGroup map[string]int `json:"byGroup"`
}

// ExecuteRunReq requests a governed tool or cyber-probe execution gated by Kai risk scoring and intercept rules.
type ExecuteRunReq struct {
	// EngagementID binds the run to an authorized engagement and its Rules of Engagement scope.
	EngagementID string `json:"engagementId" validate:"required"`
	// TaskID optionally associates the run with a reasoning task.
	TaskID string `json:"taskId"`
	// Tool names the cyber tool or native cyber-probe command (for example cyber_probe_ports, cyber_probe_secrets, cyber_probe_hash).
	Tool string `json:"tool" validate:"required"`
	// Action describes the proposed operation evaluated by Kai.
	Action string `json:"action" validate:"required"`
	// Target names the in-scope host, URL, or workspace path.
	Target string `json:"target" validate:"required"`
	// Args carries structured tool parameters such as ports or path.
	Args map[string]any `json:"args"`
}

// AuditFilter narrows hash-chained audit trail queries.
type AuditFilter struct {
	// EngagementID narrows audit events to one engagement chain.
	EngagementID string `json:"engagementId"`
	// Limit bounds the maximum number of audit records returned (1-1000, default 200).
	Limit int `json:"limit"`
}

// AuditListView returns credential-redacted, SHA-256 hash-chained audit events.
type AuditListView struct {
	// Data holds audit records ordered chronologically by sequence number.
	Data []AuditEvent `json:"data"`
}

// AuditVerifyReq identifies the org/engagement audit chain to verify cryptographically.
type AuditVerifyReq struct {
	// EngagementID selects the engagement audit chain to verify (empty verifies the org-level chain).
	EngagementID string `json:"engagementId"`
}

// ---- Conversions ----

func toEngagementView(e Engagement) EngagementView {
	scope := e.Scope
	if scope == nil {
		scope = []string{}
	}
	return EngagementView{
		ID: e.ID, Name: e.Name, Target: e.Target, Scope: scope, Mode: e.Mode,
		Status: e.Status, Synthetic: e.Synthetic, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
	}
}

func toTaskView(t Task) TaskView {
	return TaskView{
		ID: t.ID, EngagementID: t.EngagementID, Title: t.Title, Goal: t.Goal,
		Status: t.Status, Phase: t.Phase, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

func toNodeView(n GraphNode) GraphNodeView {
	return GraphNodeView{
		ID: n.ID, TaskID: n.TaskID, Kind: n.Kind, Label: n.Label, Detail: n.Detail,
		Status: n.Status, Severity: n.Severity, ParentID: n.ParentID, CreatedAt: n.CreatedAt,
	}
}

func toFindingView(f Finding) FindingView {
	return FindingView{
		ID: f.ID, EngagementID: f.EngagementID, TaskID: f.TaskID, Title: f.Title,
		Severity: f.Severity, Category: f.Category, CWE: f.CWE,
		MitreTechnique: f.MitreTechnique, MitreTactic: f.MitreTactic,
		Status: f.Status, Target: f.Target, EvidenceQuote: f.EvidenceQuote,
		TrafficID: f.TrafficID, Verified: f.Verified, VerificationNote: f.VerificationNote,
		Remediation: f.Remediation, CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
}

func toTrafficView(tr TrafficRecord) TrafficView {
	return TrafficView{
		ID: tr.ID, EngagementID: tr.EngagementID, TaskID: tr.TaskID, Method: tr.Method,
		URL: tr.URL, Host: tr.Host, StatusCode: tr.StatusCode,
		RequestHeaders: tr.RequestHeaders, RequestBody: tr.RequestBody,
		ResponseHeaders: tr.ResponseHeaders, ResponseBody: tr.ResponseBody,
		LatencyMS: tr.LatencyMS, CreatedAt: tr.CreatedAt,
	}
}

func toApprovalView(a Approval) ApprovalView {
	return ApprovalView{
		ID: a.ID, EngagementID: a.EngagementID, TaskID: a.TaskID, Action: a.Action,
		Target: a.Target, Tool: a.Tool, RiskScore: a.RiskScore, RiskLevel: a.RiskLevel,
		KaiRationale: a.KaiRationale, Status: a.Status, DecidedBy: a.DecidedBy,
		DecidedAt: a.DecidedAt, CreatedAt: a.CreatedAt,
	}
}

func toRuleView(r InterceptRule) RuleView {
	return RuleView{
		ID: r.ID, EngagementID: r.EngagementID, Name: r.Name, MatchHost: r.MatchHost,
		MatchPath: r.MatchPath, Action: r.Action, Enabled: r.Enabled, CreatedAt: r.CreatedAt,
	}
}

func toChatMessageView(m ChatMessage) ChatMessageView {
	return ChatMessageView{
		ID: m.ID, EngagementID: m.EngagementID, TaskID: m.TaskID, Role: m.Role,
		Content: m.Content, Model: m.Model, InputTokens: m.InputTokens,
		OutputTokens: m.OutputTokens, CreatedAt: m.CreatedAt,
	}
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "medium"
	}
}

// ---- Typed Handlers ----

// health returns liveness status and runtime readiness for the Hanzo Cyber control plane.
func (o ops) health(ctx context.Context, _ *NoIn) (*HealthView, error) {
	if err := o.store.Ping(ctx); err != nil {
		return nil, zip.Errorf(503, "store unavailable: %v", err)
	}
	mode := "multi-tenant"
	if o.standalone {
		mode = "standalone"
	}
	return &HealthView{
		Status:       "ok",
		Backend:      o.backend,
		Mode:         mode,
		RouterReady:  o.engine.RouterConfigured(),
		SandboxReady: o.engine.SandboxConfigured(),
		ProbeReady:   o.engine.ProbeConfigured(),
	}, nil
}

func (o ops) recordAudit(ctx context.Context, org, engID, event, actor string, payload map[string]any) {
	_, _ = o.store.AppendAuditEvent(ctx, org, engID, event, actor, payload)
}

// dashboard aggregates engagements, findings, verbatim proof coverage, Kai approvals, and traffic counts for the authenticated org.
func (o ops) dashboard(ctx context.Context, in *EngagementFilter) (*DashboardView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	engs, err := o.store.ListEngagements(ctx, org)
	if err != nil {
		return nil, zip.Errorf(500, "list engagements: %v", err)
	}
	tasks, err := o.store.ListTasks(ctx, org, engID)
	if err != nil {
		return nil, zip.Errorf(500, "list tasks: %v", err)
	}
	findings, err := o.store.ListFindings(ctx, org, engID, "", "")
	if err != nil {
		return nil, zip.Errorf(500, "list findings: %v", err)
	}
	approvals, err := o.store.ListApprovals(ctx, org, engID, "pending")
	if err != nil {
		return nil, zip.Errorf(500, "list approvals: %v", err)
	}
	traffic, err := o.store.ListTraffic(ctx, org, engID, "")
	if err != nil {
		return nil, zip.Errorf(500, "list traffic: %v", err)
	}
	rules, err := o.store.ListRules(ctx, org, engID)
	if err != nil {
		return nil, zip.Errorf(500, "list rules: %v", err)
	}

	out := &DashboardView{
		Org:              org,
		Stage:            "beta",
		Engagements:      len(engs),
		Tasks:            len(tasks),
		FindingsTotal:    len(findings),
		PendingApprovals: len(approvals),
		TrafficCount:     len(traffic),
		RulesCount:       len(rules),
	}
	for _, f := range findings {
		if f.Verified {
			out.FindingsVerified++
		}
		switch f.Severity {
		case "critical":
			out.Critical++
		case "high":
			out.High++
		case "medium":
			out.Medium++
		case "low":
			out.Low++
		}
	}
	if out.FindingsTotal > 0 {
		out.VerificationRate = (out.FindingsVerified * 100) / out.FindingsTotal
	}
	return out, nil
}

// listEngagements returns every authorized cyber engagement belonging to the caller's org.
func (o ops) listEngagements(ctx context.Context, _ *NoIn) (*EngagementList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListEngagements(ctx, org)
	if err != nil {
		return nil, zip.Errorf(500, "list engagements: %v", err)
	}
	out := make([]EngagementView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEngagementView(r))
	}
	return &EngagementList{Data: out}, nil
}

// createEngagement creates a new org-scoped cyber engagement workspace with explicit target scope.
func (o ops) createEngagement(ctx context.Context, in *CreateEngagementReq) (*EngagementView, error) {
	org, actor, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	target := strings.TrimSpace(in.Target)
	if name == "" || target == "" {
		return nil, zip.ErrBadRequest("name and target are required")
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "enclave"
	}
	scope := in.Scope
	if len(scope) == 0 {
		scope = []string{target}
	}
	now := nowMS()
	eng := Engagement{
		ID: genID("eng"), Org: org, Name: name, Target: target,
		Scope: scope, Mode: mode, Status: "active", Synthetic: in.Synthetic,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := o.store.SaveEngagement(ctx, eng); err != nil {
		return nil, zip.Errorf(500, "save engagement: %v", err)
	}
	o.recordAudit(ctx, org, eng.ID, "engagement.created", actor, map[string]any{
		"engagement_id": eng.ID,
		"target":        eng.Target,
		"scope":         eng.Scope,
		"mode":          eng.Mode,
	})
	v := toEngagementView(eng)
	return &v, nil
}

// seedDemo idempotently seeds a synthetic MDTF Tactical Enclave (Lab) engagement for testing and defense demonstrations.
func (o ops) seedDemo(ctx context.Context, _ *NoIn) (*SeedDemoRes, error) {
	org, actor, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	now := nowMS()
	engID := "eng_mdtf_lab_" + org
	taskID := "tsk_mdtf_audit_" + org
	tr1ID := "trf_mdtf_tak_" + org
	tr2ID := "trf_mdtf_c2_" + org
	tr3ID := "trf_mdtf_enclave_" + org

	eng := Engagement{
		ID: engID, Org: org, Name: "MDTF Tactical Enclave (Lab)",
		Target: "enclave.mdtf.test",
		Scope:  []string{"enclave.mdtf.test", "c2.mdtf.test", "tak.mdtf.test"},
		Mode:   "airgap", Status: "active", Synthetic: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := o.store.SaveEngagement(ctx, eng); err != nil {
		return nil, zip.Errorf(500, "seed engagement: %v", err)
	}

	task := Task{
		ID: taskID, Org: org, EngagementID: engID,
		Title: "Tactical C2 & TAK Gateway Zero-Trust Verification",
		Goal:  "Verify authentication boundaries, token scopes, and lateral movement resistance across enclave.mdtf.test, c2.mdtf.test, and tak.mdtf.test with verbatim HTTP proof.",
		Status: "active", Phase: "verify", CreatedAt: now, UpdatedAt: now,
	}
	if err := o.store.SaveTask(ctx, task); err != nil {
		return nil, zip.Errorf(500, "seed task: %v", err)
	}

	nodes := []GraphNode{
		{ID: "nod_goal_" + org, Org: org, TaskID: taskID, Kind: "goal", Label: "Verify MDTF Tactical Enclave Zero-Trust Boundary", Detail: task.Goal, Status: "active", CreatedAt: now},
		{ID: "nod_int1_" + org, Org: org, TaskID: taskID, Kind: "intent", Label: "Enumerate TAK Relay Federation Endpoints", Detail: "Inspect /api/v1/relay/federation and mTLS enforcement on tak.mdtf.test", Status: "done", ParentID: "nod_goal_" + org, CreatedAt: now + 1},
		{ID: "nod_int2_" + org, Org: org, TaskID: taskID, Kind: "intent", Label: "Audit C2 Dispatch Role Enforcement", Detail: "Validate operator JWT audience & role enforcement on c2.mdtf.test/v1/dispatch", Status: "done", ParentID: "nod_goal_" + org, CreatedAt: now + 2},
		{ID: "nod_fnd1_" + org, Org: org, TaskID: taskID, Kind: "finding", Label: "Unauthenticated TAK Telemetry Replay Endpoint", Detail: "Verbatim response returned federation key metadata without client certificate.", Status: "verified", Severity: "critical", ParentID: "nod_int1_" + org, CreatedAt: now + 3},
		{ID: "nod_fnd2_" + org, Org: org, TaskID: taskID, Kind: "finding", Label: "Over-Privileged C2 Service Token Scope", Detail: "Read-only observer JWT accepted on /v1/dispatch/override dry-run.", Status: "verified", Severity: "high", ParentID: "nod_int2_" + org, CreatedAt: now + 4},
		{ID: "nod_hnt1_" + org, Org: org, TaskID: taskID, Kind: "hint", Label: "Kai Gate: Active Relay Fuzzing Held for Operator Sign-Off", Detail: "Risk score 88/100 (critical): requires human commander authorization before active state mutation.", Status: "pending", ParentID: "nod_fnd1_" + org, CreatedAt: now + 5},
	}
	for _, n := range nodes {
		if err := o.store.SaveNode(ctx, n); err != nil {
			return nil, zip.Errorf(500, "seed node: %v", err)
		}
	}

	traffics := []TrafficRecord{
		{
			ID: tr1ID, Org: org, EngagementID: engID, TaskID: taskID,
			Method: "GET", URL: "https://tak.mdtf.test/api/v1/relay/federation/status", Host: "tak.mdtf.test",
			StatusCode: 200,
			RequestHeaders:  "Host: tak.mdtf.test\nUser-Agent: Hanzo-Cyber-Verifier/1.0\nAccept: application/json",
			ResponseHeaders: "HTTP/1.1 200 OK\nContent-Type: application/json\nX-Enclave-Node: tak-relay-01",
			ResponseBody:    `{"enclave":"mdtf-lab","mtls_required":false,"federation_peer":"c2.mdtf.test","signing_kid":"tak-sim-key-01","status":"open_relay"}`,
			LatencyMS: 18, CreatedAt: now,
		},
		{
			ID: tr2ID, Org: org, EngagementID: engID, TaskID: taskID,
			Method: "POST", URL: "https://c2.mdtf.test/v1/dispatch/override?dryRun=true", Host: "c2.mdtf.test",
			StatusCode: 200,
			RequestHeaders:  "Host: c2.mdtf.test\nAuthorization: Bearer <redacted-observer-token>\nContent-Type: application/json",
			RequestBody:     `{"mission":"sim-alpha","mode":"dry_run"}`,
			ResponseHeaders: "HTTP/1.1 200 OK\nContent-Type: application/json",
			ResponseBody:    `{"accepted":true,"caller_role":"observer","enforced_role":"commander","bypass_reason":"legacy_dryrun_allowlist"}`,
			LatencyMS: 24, CreatedAt: now + 1,
		},
		{
			ID: tr3ID, Org: org, EngagementID: engID, TaskID: taskID,
			Method: "GET", URL: "https://enclave.mdtf.test/.well-known/security-posture", Host: "enclave.mdtf.test",
			StatusCode: 200,
			RequestHeaders:  "Host: enclave.mdtf.test\nAccept: application/json",
			ResponseHeaders: "HTTP/1.1 200 OK\nContent-Type: application/json\nStrict-Transport-Security: max-age=31536000",
			ResponseBody:    `{"enclave":"mdtf-lab","fips_mode":true,"pqc_kem":"ML-KEM-768","debug_metrics_exposed":true}`,
			LatencyMS: 11, CreatedAt: now + 2,
		},
	}
	for _, tr := range traffics {
		if err := o.store.SaveTraffic(ctx, tr); err != nil {
			return nil, zip.Errorf(500, "seed traffic: %v", err)
		}
	}

	findings := []Finding{
		{
			ID: "fnd_mdtf_1_" + org, Org: org, EngagementID: engID, TaskID: taskID,
			Title: "Unauthenticated TAK Federation Relay Metadata Exposure",
			Severity: "critical", Category: "Broken Authentication", CWE: "CWE-306",
			MitreTechnique: "T1190", MitreTactic: "Initial Access",
			Status: "verified", Target: "https://tak.mdtf.test/api/v1/relay/federation/status",
			EvidenceQuote: `"mtls_required":false,"federation_peer":"c2.mdtf.test"`,
			TrafficID: tr1ID, Verified: true,
			VerificationNote: "Verbatim substring confirmed in response body of " + tr1ID,
			Remediation: "Enforce mutual TLS (client cert pinning) on all TAK relay endpoints and disable unauthenticated federation status disclosure.",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fnd_mdtf_2_" + org, Org: org, EngagementID: engID, TaskID: taskID,
			Title: "Observer JWT Accepted on C2 Dispatch Override Route",
			Severity: "high", Category: "Broken Access Control", CWE: "CWE-863",
			MitreTechnique: "T1078", MitreTactic: "Privilege Escalation",
			Status: "verified", Target: "https://c2.mdtf.test/v1/dispatch/override",
			EvidenceQuote: `"caller_role":"observer","enforced_role":"commander","bypass_reason":"legacy_dryrun_allowlist"`,
			TrafficID: tr2ID, Verified: true,
			VerificationNote: "Verbatim substring confirmed in response body of " + tr2ID,
			Remediation: "Remove legacy_dryrun_allowlist and require explicit commander role claim via Hanzo IAM / Zanzibar Authz before route entry.",
			CreatedAt: now + 1, UpdatedAt: now + 1,
		},
		{
			ID: "fnd_mdtf_3_" + org, Org: org, EngagementID: engID, TaskID: taskID,
			Title: "Enclave Debug Metrics Flag Enabled on Edge Gateway",
			Severity: "medium", Category: "Security Misconfiguration", CWE: "CWE-215",
			MitreTechnique: "T1082", MitreTactic: "Discovery",
			Status: "open", Target: "https://enclave.mdtf.test/.well-known/security-posture",
			EvidenceQuote: `"debug_metrics_exposed":true`,
			TrafficID: tr3ID, Verified: false,
			VerificationNote: "Awaiting operator verbatim verification click",
			Remediation: "Disable debug_metrics_exposed in production enclave configuration and bind diagnostics to loopback only.",
			CreatedAt: now + 2, UpdatedAt: now + 2,
		},
	}
	for _, f := range findings {
		if err := o.store.SaveFinding(ctx, f); err != nil {
			return nil, zip.Errorf(500, "seed finding: %v", err)
		}
	}

	approvals := []Approval{
		{
			ID: "apr_mdtf_1_" + org, Org: org, EngagementID: engID, TaskID: taskID,
			Action: "Run active mTLS downgrade & relay replay verification payload against tak.mdtf.test/api/v1/relay",
			Target: "tak.mdtf.test", Tool: "cyber_http_replay_verify",
			RiskScore: 88, RiskLevel: "critical",
			KaiRationale: "Kai risk gate: active mutation/exploitation signal (payload); active probing on sensitive surface (c2/relay); requires human operator approval.",
			Status: "pending", CreatedAt: now,
		},
		{
			ID: "apr_mdtf_2_" + org, Org: org, EngagementID: engID, TaskID: taskID,
			Action: "Passive TLS cipher suite & ML-KEM-768 PQC handshake inspection on enclave.mdtf.test",
			Target: "enclave.mdtf.test", Tool: "cyber_tls_audit",
			RiskScore: 18, RiskLevel: "low",
			KaiRationale: "Kai risk gate: read-only reconnaissance within declared engagement scope.",
			Status: "approved", DecidedBy: actor, DecidedAt: now, CreatedAt: now - 60000,
		},
	}
	for _, a := range approvals {
		if err := o.store.SaveApproval(ctx, a); err != nil {
			return nil, zip.Errorf(500, "seed approval: %v", err)
		}
	}

	rules := []InterceptRule{
		{ID: "rul_mdtf_1_" + org, Org: org, EngagementID: engID, Name: "Enclave Authorized Scope Allowlist", MatchHost: "*.mdtf.test", MatchPath: "/*", Action: "allow", Enabled: true, CreatedAt: now},
		{ID: "rul_mdtf_2_" + org, Org: org, EngagementID: engID, Name: "Require Kai Human Sign-Off on C2 Write Paths", MatchHost: "c2.mdtf.test", MatchPath: "/v1/dispatch/*", Action: "require_approval", Enabled: true, CreatedAt: now + 1},
		{ID: "rul_mdtf_3_" + org, Org: org, EngagementID: engID, Name: "Block Out-of-Scope Egress", MatchHost: "!*.mdtf.test", MatchPath: "/*", Action: "block", Enabled: true, CreatedAt: now + 2},
	}
	for _, r := range rules {
		if err := o.store.SaveRule(ctx, r); err != nil {
			return nil, zip.Errorf(500, "seed rule: %v", err)
		}
	}

	return &SeedDemoRes{
		Engagement: toEngagementView(eng),
		Tasks:      1,
		Findings:   len(findings),
		Traffic:    len(traffics),
		Approvals:  len(approvals),
		Rules:      len(rules),
	}, nil
}

// listTasks returns cyber tasks belonging to the caller's org, optionally filtered by engagementId.
func (o ops) listTasks(ctx context.Context, in *EngagementFilter) (*TaskList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListTasks(ctx, org, strings.TrimSpace(in.EngagementID))
	if err != nil {
		return nil, zip.Errorf(500, "list tasks: %v", err)
	}
	out := make([]TaskView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toTaskView(r))
	}
	return &TaskList{Data: out}, nil
}

// createTask creates a cyber task and initializes its root GOAL node in the reasoning graph.
func (o ops) createTask(ctx context.Context, in *CreateTaskReq) (*TaskView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	title := strings.TrimSpace(in.Title)
	if engID == "" || title == "" {
		return nil, zip.ErrBadRequest("engagementId and title are required")
	}
	if _, err := o.store.GetEngagement(ctx, org, engID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, zip.ErrNotFound("engagement not found")
		}
		return nil, zip.Errorf(500, "get engagement: %v", err)
	}
	phase := strings.TrimSpace(in.Phase)
	if phase == "" {
		phase = "recon"
	}
	now := nowMS()
	task := Task{
		ID: genID("tsk"), Org: org, EngagementID: engID,
		Title: title, Goal: strings.TrimSpace(in.Goal),
		Status: "active", Phase: phase, CreatedAt: now, UpdatedAt: now,
	}
	if err := o.store.SaveTask(ctx, task); err != nil {
		return nil, zip.Errorf(500, "save task: %v", err)
	}
	root := GraphNode{
		ID: genID("nod"), Org: org, TaskID: task.ID, Kind: "goal",
		Label: task.Title, Detail: task.Goal, Status: "active", CreatedAt: now,
	}
	if err := o.store.SaveNode(ctx, root); err != nil {
		return nil, zip.Errorf(500, "save root node: %v", err)
	}
	v := toTaskView(task)
	return &v, nil
}

// getTaskGraph returns a task together with its ordered GOAL -> INTENT -> FINDING -> HINT reasoning graph.
func (o ops) getTaskGraph(ctx context.Context, in *TaskRef) (*TaskGraphView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	t, err := o.store.GetTask(ctx, org, strings.TrimSpace(in.ID))
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("task not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get task: %v", err)
	}
	nodes, err := o.store.ListNodes(ctx, org, t.ID)
	if err != nil {
		return nil, zip.Errorf(500, "list nodes: %v", err)
	}
	nv := make([]GraphNodeView, 0, len(nodes))
	for _, n := range nodes {
		nv = append(nv, toNodeView(n))
	}
	return &TaskGraphView{Task: toTaskView(t), Nodes: nv}, nil
}

// addGraphNode appends a goal, intent, finding, hint, or action node to a task's reasoning graph.
func (o ops) addGraphNode(ctx context.Context, in *AddGraphNodeReq) (*GraphNodeView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	t, err := o.store.GetTask(ctx, org, strings.TrimSpace(in.ID))
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("task not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get task: %v", err)
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	switch kind {
	case "goal", "intent", "finding", "hint", "action":
	default:
		return nil, zip.ErrBadRequest("kind must be goal|intent|finding|hint|action")
	}
	label := strings.TrimSpace(in.Label)
	if label == "" {
		return nil, zip.ErrBadRequest("label is required")
	}
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = "active"
	}
	node := GraphNode{
		ID: genID("nod"), Org: org, TaskID: t.ID, Kind: kind,
		Label: label, Detail: strings.TrimSpace(in.Detail), Status: status,
		Severity: strings.TrimSpace(in.Severity), ParentID: strings.TrimSpace(in.ParentID),
		CreatedAt: nowMS(),
	}
	if err := o.store.SaveNode(ctx, node); err != nil {
		return nil, zip.Errorf(500, "save node: %v", err)
	}
	v := toNodeView(node)
	return &v, nil
}

// listFindings returns org-scoped findings optionally filtered by engagementId, severity, and status.
func (o ops) listFindings(ctx context.Context, in *FindingFilter) (*FindingList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	sev := strings.ToLower(strings.TrimSpace(in.Severity))
	if sev != "" && severityRank(sev) == 0 {
		return nil, zip.ErrBadRequest("severity must be critical|high|medium|low|info")
	}
	rows, err := o.store.ListFindings(ctx, org, strings.TrimSpace(in.EngagementID), sev, strings.TrimSpace(in.Status))
	if err != nil {
		return nil, zip.Errorf(500, "list findings: %v", err)
	}
	out := make([]FindingView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toFindingView(r))
	}
	return &FindingList{Data: out}, nil
}

// createFinding records a security finding inside an authorized engagement.
func (o ops) createFinding(ctx context.Context, in *CreateFindingReq) (*FindingView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	title := strings.TrimSpace(in.Title)
	if engID == "" || title == "" {
		return nil, zip.ErrBadRequest("engagementId and title are required")
	}
	if _, err := o.store.GetEngagement(ctx, org, engID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, zip.ErrNotFound("engagement not found")
		}
		return nil, zip.Errorf(500, "get engagement: %v", err)
	}
	now := nowMS()
	f := Finding{
		ID: genID("fnd"), Org: org, EngagementID: engID, TaskID: strings.TrimSpace(in.TaskID),
		Title: title, Severity: normalizeSeverity(in.Severity),
		Category: strings.TrimSpace(in.Category), CWE: strings.TrimSpace(in.CWE),
		MitreTechnique: strings.TrimSpace(in.MitreTechnique), MitreTactic: strings.TrimSpace(in.MitreTactic),
		Status: "open", Target: strings.TrimSpace(in.Target),
		EvidenceQuote: strings.TrimSpace(in.EvidenceQuote), TrafficID: strings.TrimSpace(in.TrafficID),
		Remediation: strings.TrimSpace(in.Remediation), CreatedAt: now, UpdatedAt: now,
	}
	if err := o.store.SaveFinding(ctx, f); err != nil {
		return nil, zip.Errorf(500, "save finding: %v", err)
	}
	v := toFindingView(f)
	return &v, nil
}

// updateFinding updates a finding's status, bound traffic, evidence quote, or remediation text.
func (o ops) updateFinding(ctx context.Context, in *UpdateFindingReq) (*FindingView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	f, err := o.store.GetFinding(ctx, org, strings.TrimSpace(in.ID))
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("finding not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get finding: %v", err)
	}
	if st := strings.TrimSpace(in.Status); st != "" {
		switch st {
		case "open", "verified", "remediated", "false_positive":
			f.Status = st
		default:
			return nil, zip.ErrBadRequest("status must be open|verified|remediated|false_positive")
		}
	}
	if in.EvidenceQuote != "" {
		f.EvidenceQuote = strings.TrimSpace(in.EvidenceQuote)
		f.Verified = false
	}
	if in.TrafficID != "" {
		f.TrafficID = strings.TrimSpace(in.TrafficID)
		f.Verified = false
	}
	if in.Remediation != "" {
		f.Remediation = strings.TrimSpace(in.Remediation)
	}
	f.UpdatedAt = nowMS()
	if err := o.store.SaveFinding(ctx, f); err != nil {
		return nil, zip.Errorf(500, "save finding: %v", err)
	}
	v := toFindingView(f)
	return &v, nil
}

// verifyFinding performs deterministic verbatim substring verification of a finding's evidenceQuote against its bound captured HTTP traffic record.
func (o ops) verifyFinding(ctx context.Context, in *VerifyFindingReq) (*FindingView, error) {
	org, actor, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	f, err := o.store.GetFinding(ctx, org, strings.TrimSpace(in.ID))
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("finding not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get finding: %v", err)
	}
	if strings.TrimSpace(in.TrafficID) != "" {
		f.TrafficID = strings.TrimSpace(in.TrafficID)
	}
	if strings.TrimSpace(in.EvidenceQuote) != "" {
		f.EvidenceQuote = strings.TrimSpace(in.EvidenceQuote)
	}
	if f.TrafficID == "" || f.EvidenceQuote == "" {
		return nil, zip.ErrBadRequest("trafficId and evidenceQuote are required for verbatim verification")
	}
	tr, err := o.store.GetTraffic(ctx, org, f.TrafficID)
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("bound traffic record not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get traffic: %v", err)
	}

	corpus := tr.RequestHeaders + "\n" + tr.RequestBody + "\n" + tr.ResponseHeaders + "\n" + tr.ResponseBody
	if strings.Contains(corpus, f.EvidenceQuote) {
		f.Verified = true
		f.Status = "verified"
		f.VerificationNote = fmt.Sprintf("Verbatim substring confirmed in captured traffic %s (%s %s)", tr.ID, tr.Method, tr.URL)
	} else {
		f.Verified = false
		if f.Status == "verified" {
			f.Status = "open"
		}
		f.VerificationNote = fmt.Sprintf("Verification failed: exact evidenceQuote not present in traffic %s", tr.ID)
	}
	f.UpdatedAt = nowMS()
	if err := o.store.SaveFinding(ctx, f); err != nil {
		return nil, zip.Errorf(500, "save finding: %v", err)
	}
	o.recordAudit(ctx, org, f.EngagementID, "finding.verified", actor, map[string]any{
		"finding_id": f.ID,
		"traffic_id": f.TrafficID,
		"verified":   f.Verified,
		"status":     f.Status,
	})
	v := toFindingView(f)
	return &v, nil
}

// listTraffic returns captured HTTP exchanges belonging to the caller's org.
func (o ops) listTraffic(ctx context.Context, in *TrafficFilter) (*TrafficList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListTraffic(ctx, org, strings.TrimSpace(in.EngagementID), strings.TrimSpace(in.Host))
	if err != nil {
		return nil, zip.Errorf(500, "list traffic: %v", err)
	}
	out := make([]TrafficView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toTrafficView(r))
	}
	return &TrafficList{Data: out}, nil
}

// recordTraffic stores a captured HTTP exchange for inspection and verbatim finding proof binding.
func (o ops) recordTraffic(ctx context.Context, in *RecordTrafficReq) (*TrafficView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	rawURL := strings.TrimSpace(in.URL)
	if engID == "" || rawURL == "" {
		return nil, zip.ErrBadRequest("engagementId and url are required")
	}
	if _, err := o.store.GetEngagement(ctx, org, engID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, zip.ErrNotFound("engagement not found")
		}
		return nil, zip.Errorf(500, "get engagement: %v", err)
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		if u, parseErr := url.Parse(rawURL); parseErr == nil {
			host = u.Hostname()
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "GET"
	}
	statusCode := in.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}
	tr := TrafficRecord{
		ID: genID("trf"), Org: org, EngagementID: engID, TaskID: strings.TrimSpace(in.TaskID),
		Method: method, URL: rawURL, Host: host, StatusCode: statusCode,
		RequestHeaders: in.RequestHeaders, RequestBody: in.RequestBody,
		ResponseHeaders: in.ResponseHeaders, ResponseBody: in.ResponseBody,
		LatencyMS: in.LatencyMS, CreatedAt: nowMS(),
	}
	if err := o.store.SaveTraffic(ctx, tr); err != nil {
		return nil, zip.Errorf(500, "save traffic: %v", err)
	}
	v := toTrafficView(tr)
	return &v, nil
}

// listApprovals returns Kai risk-scored action approvals for the caller's org.
func (o ops) listApprovals(ctx context.Context, in *ApprovalFilter) (*ApprovalList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListApprovals(ctx, org, strings.TrimSpace(in.EngagementID), strings.TrimSpace(in.Status))
	if err != nil {
		return nil, zip.Errorf(500, "list approvals: %v", err)
	}
	out := make([]ApprovalView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toApprovalView(r))
	}
	return &ApprovalList{Data: out}, nil
}

// submitApproval evaluates a proposed cyber action with Kai deterministic risk scoring and queues it for human approval.
func (o ops) submitApproval(ctx context.Context, in *SubmitApprovalReq) (*ApprovalView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	action := strings.TrimSpace(in.Action)
	target := strings.TrimSpace(in.Target)
	if engID == "" || action == "" || target == "" {
		return nil, zip.ErrBadRequest("engagementId, action, and target are required")
	}
	eng, err := o.store.GetEngagement(ctx, org, engID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, zip.ErrNotFound("engagement not found")
		}
		return nil, zip.Errorf(500, "get engagement: %v", err)
	}
	rules, err := o.store.ListRules(ctx, org, engID)
	if err != nil {
		return nil, zip.Errorf(500, "list rules: %v", err)
	}
	risk, _ := EvaluateAction(&eng, rules, action, target, strings.TrimSpace(in.Tool))
	a := Approval{
		ID: genID("apr"), Org: org, EngagementID: engID, TaskID: strings.TrimSpace(in.TaskID),
		Action: action, Target: target, Tool: strings.TrimSpace(in.Tool),
		RiskScore: risk.Score, RiskLevel: risk.Level, KaiRationale: risk.Rationale,
		Status: "pending", CreatedAt: nowMS(),
	}
	if err := o.store.SaveApproval(ctx, a); err != nil {
		return nil, zip.Errorf(500, "save approval: %v", err)
	}
	v := toApprovalView(a)
	return &v, nil
}

// decideApproval records a human Approve, Deny, or Always-Allow decision on a queued Kai approval.
func (o ops) decideApproval(ctx context.Context, in *DecideApprovalReq) (*ApprovalView, error) {
	org, actor, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	a, err := o.store.GetApproval(ctx, org, strings.TrimSpace(in.ID))
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("approval not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "get approval: %v", err)
	}
	dec := strings.ToLower(strings.TrimSpace(in.Decision))
	switch dec {
	case "approved", "denied", "always_allow":
	default:
		return nil, zip.ErrBadRequest("decision must be approved|denied|always_allow")
	}
	now := nowMS()
	a.Status = dec
	a.DecidedBy = actor
	a.DecidedAt = now
	if err := o.store.SaveApproval(ctx, a); err != nil {
		return nil, zip.Errorf(500, "save approval: %v", err)
	}
	if dec == "always_allow" {
		ruleName := "Always-Allow: " + a.Tool
		if strings.TrimSpace(a.Tool) == "" {
			ruleName = "Always-Allow: " + a.Target
		}
		host, _ := ExtractHostPath(a.Target)
		if host == "" {
			host = a.Target
		}
		_ = o.store.SaveRule(ctx, InterceptRule{
			ID: genID("rul"), Org: org, EngagementID: a.EngagementID,
			Name: ruleName, MatchHost: host, MatchPath: "/*",
			Action: "allow", Enabled: true, CreatedAt: now,
		})
	}
	o.recordAudit(ctx, org, a.EngagementID, "approval.decided", actor, map[string]any{
		"approval_id": a.ID,
		"decision":    a.Status,
		"tool":        a.Tool,
		"target":      a.Target,
		"risk_score":  a.RiskScore,
	})
	v := toApprovalView(a)
	return &v, nil
}

// listRules returns scope and intercept governance rules for the caller's org.
func (o ops) listRules(ctx context.Context, in *EngagementFilter) (*RuleList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListRules(ctx, org, strings.TrimSpace(in.EngagementID))
	if err != nil {
		return nil, zip.Errorf(500, "list rules: %v", err)
	}
	out := make([]RuleView, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRuleView(r))
	}
	return &RuleList{Data: out}, nil
}

// createRule adds a scope or intercept governance rule for the caller's org.
func (o ops) createRule(ctx context.Context, in *CreateRuleReq) (*RuleView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, zip.ErrBadRequest("name is required")
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		action = "require_approval"
	}
	switch action {
	case "allow", "block", "require_approval", "tag":
	default:
		return nil, zip.ErrBadRequest("action must be allow|block|require_approval|tag")
	}
	host := strings.TrimSpace(in.MatchHost)
	if host == "" {
		host = "*"
	}
	reqPath := strings.TrimSpace(in.MatchPath)
	if reqPath == "" {
		reqPath = "/*"
	}
	rule := InterceptRule{
		ID: genID("rul"), Org: org, EngagementID: strings.TrimSpace(in.EngagementID),
		Name: name, MatchHost: host, MatchPath: reqPath, Action: action,
		Enabled: true, CreatedAt: nowMS(),
	}
	if err := o.store.SaveRule(ctx, rule); err != nil {
		return nil, zip.Errorf(500, "save rule: %v", err)
	}
	v := toRuleView(rule)
	return &v, nil
}

// deleteRule removes an org-scoped intercept rule.
func (o ops) deleteRule(ctx context.Context, in *RuleRef) (*DeleteRes, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	err = o.store.DeleteRule(ctx, org, id)
	if errors.Is(err, ErrNotFound) {
		return nil, zip.ErrNotFound("rule not found")
	}
	if err != nil {
		return nil, zip.Errorf(500, "delete rule: %v", err)
	}
	return &DeleteRes{Deleted: true, ID: id}, nil
}

// attackMatrix projects the org's findings onto MITRE ATT&CK tactics and techniques.
func (o ops) attackMatrix(ctx context.Context, in *EngagementFilter) (*AttackMatrixView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := o.store.ListFindings(ctx, org, strings.TrimSpace(in.EngagementID), "", "")
	if err != nil {
		return nil, zip.Errorf(500, "list findings: %v", err)
	}
	byTech := map[string]*AttackTechniqueView{}
	tacticsSet := map[string]bool{}
	for _, f := range findings {
		tid := strings.TrimSpace(f.MitreTechnique)
		if tid == "" {
			tid = "UNMAPPED"
		}
		tactic := strings.TrimSpace(f.MitreTactic)
		if tactic == "" {
			tactic = "Discovery"
		}
		tacticsSet[tactic] = true
		cur, ok := byTech[tid]
		if !ok {
			cur = &AttackTechniqueView{
				TechniqueID: tid, Tactic: tactic, Name: f.Category, MaxSeverity: f.Severity,
			}
			if cur.Name == "" {
				cur.Name = f.Title
			}
			byTech[tid] = cur
		}
		cur.FindingCount++
		if f.Verified {
			cur.VerifiedCount++
		}
		if severityRank(f.Severity) > severityRank(cur.MaxSeverity) {
			cur.MaxSeverity = f.Severity
		}
	}
	tactics := make([]string, 0, len(tacticsSet))
	for k := range tacticsSet {
		tactics = append(tactics, k)
	}
	sort.Strings(tactics)
	techs := make([]AttackTechniqueView, 0, len(byTech))
	for _, v := range byTech {
		techs = append(techs, *v)
	}
	sort.Slice(techs, func(i, j int) bool {
		ri, rj := severityRank(techs[i].MaxSeverity), severityRank(techs[j].MaxSeverity)
		if ri != rj {
			return ri > rj
		}
		return techs[i].TechniqueID < techs[j].TechniqueID
	})
	return &AttackMatrixView{Tactics: tactics, Techniques: techs}, nil
}

// courseOfAction computes prioritized remediation Courses of Action from active findings.
func (o ops) courseOfAction(ctx context.Context, in *EngagementFilter) (*CoAView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := o.store.ListFindings(ctx, org, strings.TrimSpace(in.EngagementID), "", "")
	if err != nil {
		return nil, zip.Errorf(500, "list findings: %v", err)
	}
	items := make([]CoAItemView, 0, len(findings))
	for _, f := range findings {
		if f.Status == "remediated" || f.Status == "false_positive" {
			continue
		}
		priority, reduction, effort := "P2", 45, "medium"
		switch f.Severity {
		case "critical":
			priority, reduction, effort = "P0", 92, "low"
		case "high":
			priority, reduction, effort = "P1", 76, "medium"
		case "low", "info":
			priority, reduction, effort = "P3", 20, "low"
		}
		summary := f.Remediation
		if summary == "" {
			summary = fmt.Sprintf("Patch %s on %s and re-run verbatim proof verification.", f.Title, f.Target)
		}
		items = append(items, CoAItemView{
			ID: "coa_" + f.ID, Title: "Remediate: " + f.Title, Priority: priority,
			RiskReduction: reduction, Effort: effort, MitreTechnique: f.MitreTechnique,
			FindingIDs: []string{f.ID}, Summary: summary,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority != items[j].Priority {
			return items[i].Priority < items[j].Priority
		}
		return items[i].RiskReduction > items[j].RiskReduction
	})
	return &CoAView{Data: items}, nil
}

// hardeningPosture evaluates enclave scope enforcement, verbatim proof coverage, and unresolved critical risk.
func (o ops) hardeningPosture(ctx context.Context, in *EngagementFilter) (*HardeningView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	findings, err := o.store.ListFindings(ctx, org, engID, "", "")
	if err != nil {
		return nil, zip.Errorf(500, "list findings: %v", err)
	}
	rules, err := o.store.ListRules(ctx, org, engID)
	if err != nil {
		return nil, zip.Errorf(500, "list rules: %v", err)
	}
	approvals, err := o.store.ListApprovals(ctx, org, engID, "pending")
	if err != nil {
		return nil, zip.Errorf(500, "list approvals: %v", err)
	}

	verifiedCount, openCrit := 0, 0
	for _, f := range findings {
		if f.Verified {
			verifiedCount++
		}
		if f.Severity == "critical" && f.Status != "remediated" && f.Status != "false_positive" {
			openCrit++
		}
	}
	scopeEnforced := len(rules) > 0
	score := 100
	if !scopeEnforced {
		score -= 20
	}
	score -= openCrit * 25
	if len(approvals) > 0 {
		score -= 10
	}
	if score < 0 {
		score = 0
	}

	checks := []HardeningCheckView{
		{
			ID: "chk_iam", Control: "Hanzo IAM (hanzo.id) Identity & Tenant Isolation", Status: "pass",
			Detail: fmt.Sprintf("Every /v1/cyber operation is tenant-scoped to org %q.", org),
		},
		{
			ID: "chk_scope", Control: "Rules of Engagement Scope & Intercept Guardrails",
			Status: map[bool]string{true: "pass", false: "warn"}[scopeEnforced],
			Detail: fmt.Sprintf("%d active scope/intercept governance rule(s) enforced.", len(rules)),
		},
		{
			ID: "chk_proof", Control: "Deterministic Verbatim Proof Verification",
			Status: map[bool]string{true: "pass", false: "warn"}[len(findings) == 0 || verifiedCount > 0],
			Detail: fmt.Sprintf("%d/%d finding(s) verified verbatim against captured HTTP traffic.", verifiedCount, len(findings)),
		},
		{
			ID: "chk_crit", Control: "Zero Unmitigated Critical Findings",
			Status: map[bool]string{true: "pass", false: "fail"}[openCrit == 0],
			Detail: fmt.Sprintf("%d unmitigated critical finding(s) remaining.", openCrit),
		},
		{
			ID: "chk_kai", Control: "Kai Human-in-the-Loop Risk Gate",
			Status: map[bool]string{true: "pass", false: "warn"}[len(approvals) == 0],
			Detail: fmt.Sprintf("%d high-risk action(s) currently held for operator approval.", len(approvals)),
		},
	}

	return &HardeningView{
		Score:            score,
		ScopeEnforced:    scopeEnforced,
		VerbatimVerified: verifiedCount,
		OpenCritical:     openCrit,
		Checks:           checks,
	}, nil
}

// listChat returns chronological Enso/Zen operator chat messages for an org or engagement.
func (o ops) listChat(ctx context.Context, in *ChatFilter) (*ChatList, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListChatMessages(ctx, org, strings.TrimSpace(in.EngagementID), strings.TrimSpace(in.TaskID))
	if err != nil {
		return nil, zip.Errorf(500, "list chat messages: %v", err)
	}
	out := make([]ChatMessageView, 0, len(rows))
	for _, m := range rows {
		out = append(out, toChatMessageView(m))
	}
	return &ChatList{Data: out}, nil
}

// sendChat persists an operator prompt, routes it to the Enso/Zen operator engine grounded in engagement state, and returns both turns.
func (o ops) sendChat(ctx context.Context, in *ChatSendReq) (*ChatTurnView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	msg := strings.TrimSpace(in.Message)
	if msg == "" {
		return nil, zip.ErrBadRequest("message is required")
	}
	engID := strings.TrimSpace(in.EngagementID)
	if engID != "" {
		if _, err := o.store.GetEngagement(ctx, org, engID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, zip.ErrNotFound("engagement not found")
			}
			return nil, zip.Errorf(500, "get engagement: %v", err)
		}
	}
	res, err := o.engine.Chat(ctx, org, engID, strings.TrimSpace(in.TaskID), msg, strings.TrimSpace(in.Model))
	if err != nil {
		return nil, zip.Errorf(502, "operator chat failed: %v", err)
	}
	return &ChatTurnView{
		Operator:  toChatMessageView(res.Operator),
		Assistant: toChatMessageView(res.Assistant),
		Offline:   res.Offline,
	}, nil
}

// executeRun enforces Kai risk scoring and Rules of Engagement intercept rules before running a native cyber-probe scan or delegating to Hanzo /v1/sandbox.
func (o ops) executeRun(ctx context.Context, in *ExecuteRunReq) (*SandboxRunResult, error) {
	org, actor, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	engID := strings.TrimSpace(in.EngagementID)
	tool := strings.TrimSpace(in.Tool)
	action := strings.TrimSpace(in.Action)
	target := strings.TrimSpace(in.Target)
	if engID == "" || tool == "" || action == "" || target == "" {
		return nil, zip.ErrBadRequest("engagementId, tool, action, and target are required")
	}
	if _, err := o.store.GetEngagement(ctx, org, engID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, zip.ErrNotFound("engagement not found")
		}
		return nil, zip.Errorf(500, "get engagement: %v", err)
	}
	res, err := o.engine.RunInSandbox(ctx, org, SandboxRunRequest{
		EngagementID: engID,
		TaskID:       strings.TrimSpace(in.TaskID),
		Tool:         tool,
		Action:       action,
		Target:       target,
		Args:         in.Args,
	})
	if err != nil {
		return nil, zip.Errorf(502, "governed execution failed: %v", err)
	}
	o.recordAudit(ctx, org, engID, "run."+res.Status, actor, map[string]any{
		"run_id":      res.ID,
		"tool":        tool,
		"target":      target,
		"runtime":     res.Runtime,
		"status":      res.Status,
		"risk_score":  res.RiskScore,
		"risk_level":  res.RiskLevel,
		"approval_id": res.ApprovalID,
	})
	return &res, nil
}

// listAudit returns credential-redacted, SHA-256 hash-chained audit events for the caller's org or engagement.
func (o ops) listAudit(ctx context.Context, in *AuditFilter) (*AuditListView, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := o.store.ListAuditEvents(ctx, org, strings.TrimSpace(in.EngagementID), in.Limit)
	if err != nil {
		return nil, zip.Errorf(500, "list audit events: %v", err)
	}
	if rows == nil {
		rows = []AuditEvent{}
	}
	return &AuditListView{Data: rows}, nil
}

// verifyAudit recomputes the full SHA-256 hash chain for an org or engagement and detects any record tampering or sequence gap.
func (o ops) verifyAudit(ctx context.Context, in *AuditVerifyReq) (*AuditVerifyReport, error) {
	org, _, err := o.authorize(ctx)
	if err != nil {
		return nil, err
	}
	rep, err := o.store.VerifyAuditChain(ctx, org, strings.TrimSpace(in.EngagementID))
	if err != nil {
		return nil, zip.Errorf(500, "verify audit chain: %v", err)
	}
	return &rep, nil
}

// listTools returns the Hanzo Cyber tool catalog summary grouped by operational domain.
func (o ops) listTools(ctx context.Context, in *ToolFilter) (*ToolCatalogView, error) {
	if _, _, err := o.authorize(ctx); err != nil {
		return nil, err
	}
	all, _ := CatalogSummary()
	groupFilter := strings.ToLower(strings.TrimSpace(in.Group))
	filtered := make([]ToolDescriptor, 0, len(all))
	byGroup := map[string]int{}
	for _, t := range all {
		if groupFilter != "" && strings.ToLower(t.Group) != groupFilter {
			continue
		}
		filtered = append(filtered, t)
		byGroup[t.Group]++
	}
	return &ToolCatalogView{
		Tools:   filtered,
		Total:   len(filtered),
		ByGroup: byGroup,
	}, nil
}

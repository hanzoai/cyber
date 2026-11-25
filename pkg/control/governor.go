// Copyright © 2026 Hanzo AI. MIT License.

package control

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strings"
)

// RiskAssessment is the deterministic output of Kai pre-execution risk scoring.
type RiskAssessment struct {
	// Score is the deterministic risk score from 0 to 100.
	Score int
	// Level categorizes the score as low, medium, high, or critical.
	Level string
	// Rationale explains the signals that determined Score and Level.
	Rationale string
	// Signals lists the individual risk signals detected in the proposed action.
	Signals []string
}

// RuleDecision is the outcome of matching a target against scope/intercept rules.
type RuleDecision struct {
	// Action is allow, block, require_approval, or tag.
	Action string
	// Matched reports whether an explicit rule matched the target.
	Matched bool
	// Rule points to the winning rule when Matched is true.
	Rule *InterceptRule
	// Reason summarizes why Action was selected.
	Reason string
}

var (
	kaiHighTokens = []string{
		"exploit", "payload", "rce", "exec", "shell", "sqlmap", "write",
		"delete", "drop", "inject", "credential", "dump", "modify", "patch", "lateral",
	}
	kaiMedTokens = []string{
		"brute", "fuzz", "post", "put", "scan", "enum", "nuclei",
		"nikto", "ffuf", "c2", "admin", "auth",
	}
)

// ScoreKaiRisk deterministically scores a proposed cyber action (0–100) before execution.
func ScoreKaiRisk(action, target, tool string) RiskAssessment {
	blob := strings.ToLower(action + " " + target + " " + tool)
	score := 25
	var reasons []string

	for _, tok := range kaiHighTokens {
		if strings.Contains(blob, tok) {
			score += 25
			reasons = append(reasons, fmt.Sprintf("active mutation/exploitation signal (%s)", tok))
		}
	}
	for _, tok := range kaiMedTokens {
		if strings.Contains(blob, tok) {
			score += 12
			reasons = append(reasons, fmt.Sprintf("active probing on sensitive surface (%s)", tok))
		}
	}
	if score > 98 {
		score = 98
	}
	if score < 0 {
		score = 0
	}

	level := riskLevelFor(score)
	if len(reasons) == 0 {
		reasons = append(reasons, "read-only reconnaissance within declared engagement scope")
	}
	return RiskAssessment{
		Score:     score,
		Level:     level,
		Rationale: "Kai risk gate: " + strings.Join(reasons, "; "),
		Signals:   reasons,
	}
}

func riskLevelFor(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// ExtractHostPath splits a URL, host/path, or bare host into normalized lowercase host and path.
func ExtractHostPath(target string) (host, reqPath string) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return "", "/"
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
			p := u.EscapedPath()
			if p == "" {
				p = "/"
			}
			return h, p
		}
	}
	if idx := strings.IndexByte(raw, '/'); idx >= 0 {
		h := raw[:idx]
		p := raw[idx:]
		if u, err := url.Parse("https://" + h); err == nil && u.Hostname() != "" {
			h = u.Hostname()
		}
		if p == "" {
			p = "/"
		}
		return strings.ToLower(strings.TrimSuffix(h, ".")), p
	}
	if u, err := url.Parse("https://" + raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), "/"
	}
	return strings.ToLower(strings.TrimSuffix(raw, ".")), "/"
}

// MatchHostPattern matches a host against a pattern supporting "*", "*.domain",
// "!pattern" negation, exact case-insensitive hosts, and CIDR ranges.
func MatchHostPattern(pattern, host string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if pat == "" || pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "!") {
		return !MatchHostPattern(pat[1:], h)
	}
	if h == "" {
		return false
	}
	if strings.Contains(pat, "/") {
		if pfx, err := netip.ParsePrefix(pat); err == nil {
			if addr, err := netip.ParseAddr(h); err == nil {
				return pfx.Contains(addr)
			}
		}
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[2:]
		return h == suffix || strings.HasSuffix(h, "."+suffix)
	}
	if strings.ContainsAny(pat, "*?") {
		matched, err := path.Match(pat, h)
		return err == nil && matched
	}
	return h == pat
}

// MatchPathPattern matches a request path against "*", "/*", prefix wildcards
// like "/v1/dispatch/*", exact paths, or glob patterns.
func MatchPathPattern(pattern, reqPath string) bool {
	pat := strings.TrimSpace(pattern)
	p := strings.TrimSpace(reqPath)
	if pat == "" || pat == "*" || pat == "/*" {
		return true
	}
	if p == "" {
		p = "/"
	}
	if strings.HasSuffix(pat, "/*") {
		prefix := strings.TrimSuffix(pat, "/*")
		return p == prefix || strings.HasPrefix(p, prefix+"/")
	}
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(p, strings.TrimSuffix(pat, "*"))
	}
	if strings.ContainsAny(pat, "*?") {
		matched, err := path.Match(pat, p)
		return err == nil && matched
	}
	return p == pat
}

// InEngagementScope reports whether target's host is authorized by an engagement's Rules of Engagement scope.
func InEngagementScope(scope []string, target string) bool {
	if len(scope) == 0 {
		return false
	}
	host, _ := ExtractHostPath(target)
	if host == "" {
		return false
	}
	for _, entry := range scope {
		e := strings.TrimSpace(entry)
		if e == "" {
			continue
		}
		if strings.Contains(e, "://") {
			e, _ = ExtractHostPath(e)
		}
		if MatchHostPattern(e, host) {
			return true
		}
	}
	return false
}

// EvaluateRules matches target against enabled intercept rules using fail-closed
// precedence: block > require_approval > allow > tag.
func EvaluateRules(rules []InterceptRule, target string) RuleDecision {
	host, reqPath := ExtractHostPath(target)

	var (
		requireRule *InterceptRule
		allowRule   *InterceptRule
		tagRule     *InterceptRule
	)

	for i := range rules {
		r := rules[i]
		if !r.Enabled {
			continue
		}
		if !MatchHostPattern(r.MatchHost, host) || !MatchPathPattern(r.MatchPath, reqPath) {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(r.Action))
		ruleCopy := r
		switch action {
		case "block":
			return RuleDecision{
				Action:  "block",
				Matched: true,
				Rule:    &ruleCopy,
				Reason:  fmt.Sprintf("blocked by intercept rule %q (%s %s)", r.Name, r.MatchHost, r.MatchPath),
			}
		case "require_approval":
			if requireRule == nil {
				requireRule = &ruleCopy
			}
		case "allow":
			if allowRule == nil {
				allowRule = &ruleCopy
			}
		case "tag":
			if tagRule == nil {
				tagRule = &ruleCopy
			}
		}
	}

	if requireRule != nil {
		return RuleDecision{
			Action:  "require_approval",
			Matched: true,
			Rule:    requireRule,
			Reason:  fmt.Sprintf("approval required by rule %q (%s %s)", requireRule.Name, requireRule.MatchHost, requireRule.MatchPath),
		}
	}
	if allowRule != nil {
		return RuleDecision{
			Action:  "allow",
			Matched: true,
			Rule:    allowRule,
			Reason:  fmt.Sprintf("permitted by rule %q (%s %s)", allowRule.Name, allowRule.MatchHost, allowRule.MatchPath),
		}
	}
	if tagRule != nil {
		return RuleDecision{
			Action:  "tag",
			Matched: true,
			Rule:    tagRule,
			Reason:  fmt.Sprintf("tagged by rule %q (%s %s)", tagRule.Name, tagRule.MatchHost, tagRule.MatchPath),
		}
	}
	return RuleDecision{
		Action:  "require_approval",
		Matched: false,
		Reason:  "no explicit intercept rule matched; defaulting to Kai risk review",
	}
}

// EvaluateAction runs deterministic Kai risk scoring combined with engagement scope
// validation and intercept rule matching.
func EvaluateAction(eng *Engagement, rules []InterceptRule, action, target, tool string) (RiskAssessment, RuleDecision) {
	risk := ScoreKaiRisk(action, target, tool)
	decision := EvaluateRules(rules, target)

	if eng != nil && len(eng.Scope) > 0 && !InEngagementScope(eng.Scope, target) {
		risk.Score += 25
		if risk.Score > 99 {
			risk.Score = 99
		}
		risk.Level = riskLevelFor(risk.Score)
		sig := fmt.Sprintf("target %q outside declared engagement scope", target)
		risk.Signals = append(risk.Signals, sig)
		risk.Rationale += "; " + sig
		if decision.Action != "block" {
			decision = RuleDecision{
				Action:  "block",
				Matched: false,
				Reason:  sig,
			}
		}
	}
	return risk, decision
}

// RateProfile defines per-host request pacing guardrails for scanners and HTTP probes.
type RateProfile struct {
	Name              string  `json:"profile"`
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
	Inflight          int     `json:"inflight"`
	Jitter            float64 `json:"jitter"`
}

// RateProfiles holds the canonical low-and-slow traffic pacing profiles.
var RateProfiles = map[string]RateProfile{
	"off":        {Name: "off", RequestsPerSecond: 0, Burst: 0, Inflight: 0, Jitter: 0},
	"quiet":      {Name: "quiet", RequestsPerSecond: 0.5, Burst: 1, Inflight: 1, Jitter: 0.35},
	"balanced":   {Name: "balanced", RequestsPerSecond: 2.0, Burst: 4, Inflight: 4, Jitter: 0.15},
	"aggressive": {Name: "aggressive", RequestsPerSecond: 10.0, Burst: 20, Inflight: 16, Jitter: 0},
}

// LowAndSlowFlags returns advisory scanner pacing flags for the named rate profile.
func LowAndSlowFlags(profile string) map[string]string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "off":
		return map[string]string{}
	case "quiet":
		return map[string]string{
			"nmap":   "-T2",
			"ffuf":   "-rate 5 -p 1",
			"nuclei": "-rate-limit 5 -bulk-size 1",
			"httpx":  "-rl 5",
		}
	case "aggressive":
		return map[string]string{
			"nmap":   "-T4",
			"ffuf":   "-rate 100 -p 10",
			"nuclei": "-rate-limit 100 -bulk-size 25",
			"httpx":  "-rl 100",
		}
	default:
		return map[string]string{
			"nmap":   "-T3",
			"ffuf":   "-rate 20 -p 2",
			"nuclei": "-rate-limit 20 -bulk-size 5",
			"httpx":  "-rl 20",
		}
	}
}

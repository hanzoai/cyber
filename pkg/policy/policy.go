package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const (
	// ScopeEnv enables Rules of Engagement scope enforcement when truthy.
	ScopeEnv = "OPENCYBER_ENFORCE_SCOPE"

	// UnscopedEnv permits arbitrary-code executables (bash, python, shell wrappers) under enforcement.
	UnscopedEnv = "OPENCYBER_ALLOW_UNSCOPED_EXECUTION"

	// OfflineEnv activates airgapped offline mode when truthy.
	OfflineEnv = "OPENCYBER_OFFLINE"

	// OfflineNetworkAllowEnv overrides offline blocking for internet-only executables.
	OfflineNetworkAllowEnv = "OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS"
)

// OfflineNetworkExecutables lists internet-only executables blocked while OPENCYBER_OFFLINE=1.
var OfflineNetworkExecutables = map[string]struct{}{
	"shodan":       {},
	"censys":       {},
	"subfinder":    {},
	"theHarvester": {},
	"sherlock":     {},
}

// UnscopedExecutables lists arbitrary-code interpreters refused under scope enforcement.
var UnscopedExecutables = map[string]struct{}{
	"bash":    {},
	"python3": {},
	"python":  {},
}

// ShellWrappers is the published set of 27 dangerous wrapper/shell executables
// refused by argv policy matching and scope enforcement (from control/intercept.py).
var ShellWrappers = map[string]struct{}{
	"sudo":     {},
	"doas":     {},
	"runuser":  {},
	"env":      {},
	"timeout":  {},
	"nice":     {},
	"ionice":   {},
	"nohup":    {},
	"xargs":    {},
	"watch":    {},
	"sh":       {},
	"bash":     {},
	"zsh":      {},
	"dash":     {},
	"ksh":      {},
	"ash":      {},
	"eval":     {},
	"exec":     {},
	"command":  {},
	"builtin":  {},
	"parallel": {},
	"stdbuf":   {},
	"time":     {},
	"flock":    {},
	"chroot":   {},
	"setsid":   {},
	"script":   {},
}

var (
	shellMetaTokens = map[string]struct{}{
		"|": {}, "||": {}, "&&": {}, "&": {}, ";": {}, ";;": {},
		">": {}, ">>": {}, "<": {}, "<<": {}, ">&": {}, "<&": {},
		"(": {}, ")": {}, "{": {}, "}": {},
	}
	shellExpansionRe = regexp.MustCompile("[$`*?\\[\\]{}~]")

	ambiguousAuthorityRe = regexp.MustCompile(`[\\\s\x00-\x1f\x7f@]`)
	urlCandidateRe       = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>]+`)
	ipv4CandidateRe      = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
	hostnameRe           = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

	fileExtensions = map[string]struct{}{
		"txt": {}, "json": {}, "yaml": {}, "yml": {}, "xml": {}, "csv": {}, "tsv": {}, "log": {},
		"md": {}, "html": {}, "htm": {}, "js": {}, "css": {}, "php": {}, "asp": {}, "aspx": {},
		"jsp": {}, "sh": {}, "py": {}, "pl": {}, "rb": {}, "go": {}, "rs": {}, "c": {}, "h": {},
		"cpp": {}, "nse": {}, "lua": {}, "conf": {}, "config": {}, "ini": {}, "db": {}, "sqlite": {},
		"sqlite3": {}, "bin": {}, "elf": {}, "exe": {}, "dll": {}, "so": {}, "img": {}, "iso": {},
		"tar": {}, "gz": {}, "tgz": {}, "bz2": {}, "xz": {}, "zip": {}, "7z": {}, "pcap": {},
		"pcapng": {}, "cap": {}, "der": {}, "pem": {}, "crt": {}, "key": {}, "pub": {}, "lst": {},
		"dict": {}, "rules": {}, "service": {}, "proto": {}, "war": {}, "jar": {}, "apk": {},
		"dex": {}, "o": {}, "a": {}, "ko": {},
	}
)

const trailingPunct = ",;:)]}'\""

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// EnforcementEnabled reports whether OPENCYBER_ENFORCE_SCOPE is truthy.
func EnforcementEnabled() bool {
	return isTruthy(os.Getenv(ScopeEnv))
}

// UnscopedExecutionAllowed reports whether OPENCYBER_ALLOW_UNSCOPED_EXECUTION is truthy.
func UnscopedExecutionAllowed() bool {
	return isTruthy(os.Getenv(UnscopedEnv))
}

// OfflineEnabled reports whether OPENCYBER_OFFLINE is truthy.
func OfflineEnabled() bool {
	return isTruthy(os.Getenv(OfflineEnv))
}

// IsShellWrapper reports whether executable (or its basename) is one of the 27
// dangerous shell/process wrappers refused by policy.
func IsShellWrapper(executable string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(executable)))
	_, ok := ShellWrappers[base]
	return ok
}

// IsUnscopedExecutable reports whether executable cannot be statically scope-checked
// (any of the 27 ShellWrappers or python/python3).
func IsUnscopedExecutable(executable string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(executable)))
	if _, ok := UnscopedExecutables[base]; ok {
		return true
	}
	_, ok := ShellWrappers[base]
	return ok
}

// ParseSimpleArgv parses script into argv tokens ONLY when script is a single
// simple command with no shell metacharacters, no variable/glob expansions,
// no env assignments, no newlines/backslashes, and not starting with any of
// the 27 ShellWrappers. Returns (nil, false) otherwise.
func ParseSimpleArgv(script string) ([]string, bool) {
	if strings.TrimSpace(script) == "" {
		return nil, false
	}
	if strings.ContainsAny(script, "\n\r\\") {
		return nil, false
	}
	tokens, ok := splitPOSIXSimple(script)
	if !ok || len(tokens) == 0 {
		return nil, false
	}
	for _, tok := range tokens {
		if tok == "" {
			return nil, false
		}
		if _, meta := shellMetaTokens[tok]; meta {
			return nil, false
		}
		if strings.ContainsAny(tok, "|&;<>()") {
			return nil, false
		}
		if shellExpansionRe.MatchString(tok) {
			return nil, false
		}
	}
	first := tokens[0]
	if strings.Contains(first, "=") && !strings.HasPrefix(first, "-") {
		return nil, false
	}
	if IsShellWrapper(first) {
		return nil, false
	}
	return tokens, true
}

// splitPOSIXSimple performs POSIX quote-aware splitting (matching shlex.shlex
// with posix=True and no backslash escapes since backslashes are already rejected).
func splitPOSIXSimple(s string) ([]string, bool) {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	hasToken := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else {
				cur.WriteByte(c)
			}
		default:
			switch c {
			case '\'':
				inSingle = true
				hasToken = true
			case '"':
				inDouble = true
				hasToken = true
			case ' ', '\t':
				if hasToken {
					tokens = append(tokens, cur.String())
					cur.Reset()
					hasToken = false
				}
			default:
				cur.WriteByte(c)
				hasToken = true
			}
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	if hasToken {
		tokens = append(tokens, cur.String())
	}
	return tokens, true
}

// BlocklistKind identifies how a BlocklistRule matches a target host or URL.
type BlocklistKind string

const (
	BlockExactDomain BlocklistKind = "exact_domain"
	BlockFuzzyDomain BlocklistKind = "fuzzy_domain"
	BlockExactIP     BlocklistKind = "exact_ip"
	BlockFuzzyIP     BlocklistKind = "fuzzy_ip"
	BlockExactURL    BlocklistKind = "exact_url"
	BlockFuzzyURL    BlocklistKind = "fuzzy_url"
	BlockCIDR        BlocklistKind = "cidr"
)

// ValidBlocklistKind reports whether kind is one of the 7 supported blocklist rule kinds.
func ValidBlocklistKind(kind BlocklistKind) bool {
	switch kind {
	case BlockExactDomain, BlockFuzzyDomain, BlockExactIP, BlockFuzzyIP, BlockExactURL, BlockFuzzyURL, BlockCIDR:
		return true
	default:
		return false
	}
}

// BlocklistRule is one explicit deny rule evaluated before scope allowlists.
type BlocklistRule struct {
	Kind    BlocklistKind `json:"kind"`
	Pattern string        `json:"pattern"`
	Note    string        `json:"note,omitempty"`
	Enabled bool          `json:"enabled"`
}

// Blocklist holds ordered deny rules that supersede allowlists.
type Blocklist struct {
	Rules []BlocklistRule
}

// Add validates and appends an enabled deny rule to the blocklist.
func (b *Blocklist) Add(kind BlocklistKind, pattern, note string) error {
	if !ValidBlocklistKind(kind) {
		return ocerrors.New(ocerrors.CodeInvalidArgument, fmt.Sprintf("unknown blocklist kind %q", kind))
	}
	p := strings.TrimSpace(pattern)
	if p == "" {
		return ocerrors.New(ocerrors.CodeInvalidArgument, "blocklist pattern must not be empty")
	}
	if kind == BlockCIDR {
		if _, err := netip.ParsePrefix(p); err != nil {
			return ocerrors.New(ocerrors.CodeInvalidArgument, fmt.Sprintf("invalid blocklist CIDR %q: %v", p, err))
		}
	}
	b.Rules = append(b.Rules, BlocklistRule{
		Kind:    kind,
		Pattern: p,
		Note:    note,
		Enabled: true,
	})
	return nil
}

// Match returns the first enabled BlocklistRule matching host or rawURL.
func (b *Blocklist) Match(host, rawURL string) (*BlocklistRule, bool) {
	if b == nil || len(b.Rules) == 0 {
		return nil, false
	}
	normHost := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	normURL := strings.ToLower(strings.TrimSpace(rawURL))
	for i := range b.Rules {
		rule := &b.Rules[i]
		if !rule.Enabled {
			continue
		}
		pattern := strings.TrimRight(strings.ToLower(strings.TrimSpace(rule.Pattern)), ".")
		matched := false
		switch rule.Kind {
		case BlockExactDomain, BlockExactIP:
			matched = normHost != "" && normHost == pattern
		case BlockFuzzyDomain:
			matched = normHost != "" && (normHost == pattern || strings.HasSuffix(normHost, "."+pattern))
		case BlockFuzzyIP:
			matched = normHost != "" && (normHost == pattern || strings.HasPrefix(normHost, pattern))
		case BlockExactURL:
			matched = normURL != "" && normURL == strings.ToLower(strings.TrimSpace(rule.Pattern))
		case BlockFuzzyURL:
			matched = normURL != "" && strings.Contains(normURL, strings.ToLower(strings.TrimSpace(rule.Pattern)))
		case BlockCIDR:
			if addr, err := netip.ParseAddr(normHost); err == nil {
				if pfx, perr := netip.ParsePrefix(pattern); perr == nil {
					matched = pfx.Contains(addr.Unmap())
				}
			}
		}
		if matched {
			return rule, true
		}
	}
	return nil, false
}

// CanonicalHTTPURL validates an HTTP(S) URL so the parsed authority cannot
// diverge from the wire authority (rejecting backslash, userinfo '@',
// percent-encoded separators '%', whitespace, control characters, and bad ports).
func CanonicalHTTPURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL must be a non-empty string")
	}
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd <= 0 {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL must use http or https")
	}
	scheme := strings.ToLower(rawURL[:schemeEnd])
	if scheme != "http" && scheme != "https" {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL must use http or https")
	}
	rest := rawURL[schemeEnd+3:]
	authEnd := strings.IndexAny(rest, "/?#")
	rawAuth := rest
	if authEnd >= 0 {
		rawAuth = rest[:authEnd]
	}
	if rawAuth == "" {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL must include an authority")
	}
	if ambiguousAuthorityRe.MatchString(rawAuth) || strings.Contains(rawAuth, "%") {
		return "", ocerrors.New(
			ocerrors.CodeInvalidArgument,
			"URL authority is ambiguous: backslash, userinfo, whitespace, control characters and encoded separators are refused",
		)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, fmt.Sprintf("invalid URL: %v", err), ocerrors.WithCause(err))
	}
	if u.Hostname() == "" {
		return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL must include a host")
	}
	if p := u.Port(); p != "" {
		port, perr := strconv.Atoi(p)
		if perr != nil || port <= 0 || port >= 65536 {
			return "", ocerrors.New(ocerrors.CodeInvalidArgument, "URL port is out of range")
		}
	}
	return rawURL, nil
}

// CredentialBoundaryChanged reports whether a redirect hop must strip
// Authorization and Cookie headers (different host or HTTPS-to-HTTP downgrade;
// same-host HTTP-to-HTTPS upgrade retains credentials).
func CredentialBoundaryChanged(currentURL, nextURL string) (bool, error) {
	cStr, err := CanonicalHTTPURL(currentURL)
	if err != nil {
		return true, err
	}
	nStr, err := CanonicalHTTPURL(nextURL)
	if err != nil {
		return true, err
	}
	cur, _ := url.Parse(cStr)
	nxt, _ := url.Parse(nStr)
	if !strings.EqualFold(cur.Hostname(), nxt.Hostname()) {
		return true, nil
	}
	return strings.EqualFold(cur.Scheme, "https") && strings.EqualFold(nxt.Scheme, "http"), nil
}

// NormalizeHost extracts a normalized lowercase host, IP, or CIDR from a URL,
// host:port, wildcard, or bare hostname string.
func NormalizeHost(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	// Preserve bare or bracketed IPv6 addresses/CIDRs (e.g. "::1", "2001:db8::")
	// before trimming trailing punctuation that includes ':'.
	unbracketed := strings.Trim(text, "[]")
	if addr, ok := parseAddr(unbracketed); ok {
		return strings.ToLower(addr.String())
	}
	if pfx, err := netip.ParsePrefix(unbracketed); err == nil {
		return strings.ToLower(pfx.String())
	}

	text = strings.Trim(text, trailingPunct)
	text = strings.Trim(text, "[]")
	text = strings.ToLower(text)
	text = strings.TrimRight(text, ".")
	if text == "" {
		return ""
	}
	if strings.Contains(text, "://") {
		u, err := url.Parse(text)
		if err != nil {
			return ""
		}
		text = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	}
	text = strings.TrimPrefix(text, "*.")
	if idx := strings.LastIndex(text, "@"); idx >= 0 {
		text = text[idx+1:]
	}
	if strings.HasPrefix(text, "[") {
		if end := strings.Index(text, "]"); end > 0 {
			text = text[1:end]
		}
	} else if strings.Count(text, ":") == 1 {
		host, port, _ := strings.Cut(text, ":")
		if isAllDigits(port) {
			text = host
		}
	}
	return strings.TrimRight(text, ".")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// TargetMatches reports whether host falls within the declared scope target
// (wildcard "*", CIDR block, exact IP, or exact domain / subdomain).
func TargetMatches(host, target string) bool {
	normHost := NormalizeHost(host)
	normTarget := NormalizeHost(target)
	if normHost == "" || normTarget == "" {
		return false
	}
	if normTarget == "*" {
		return true
	}
	if strings.Contains(normTarget, "/") {
		pfx, err := netip.ParsePrefix(normTarget)
		if err != nil {
			return false
		}
		// Allow CIDR-within-CIDR check as well as IP-in-CIDR.
		if strings.Contains(normHost, "/") {
			hostPfx, herr := netip.ParsePrefix(normHost)
			if herr != nil {
				return false
			}
			return prefixWithin(hostPfx, pfx)
		}
		addr, ok := parseAddr(normHost)
		return ok && pfx.Contains(addr)
	}
	targetIP, targetIsIP := parseAddr(normTarget)
	hostIP, hostIsIP := parseAddr(normHost)
	if targetIsIP || hostIsIP {
		return targetIsIP && hostIsIP && hostIP == targetIP
	}
	return normHost == normTarget || strings.HasSuffix(normHost, "."+normTarget)
}

func prefixWithin(sub, super netip.Prefix) bool {
	sub = sub.Masked()
	super = super.Masked()
	if sub.Addr().Is4() != super.Addr().Is4() {
		return false
	}
	return super.Bits() <= sub.Bits() && super.Contains(sub.Addr())
}

func isValidHostname(token string) bool {
	if len(token) == 0 || len(token) > 253 {
		return false
	}
	lower := strings.ToLower(token)
	if lower == "localhost" {
		return true
	}
	if !hostnameRe.MatchString(lower) {
		return false
	}
	labels := strings.Split(lower, ".")
	for _, lbl := range labels {
		if lbl == "" || lbl == "localhost" {
			return false
		}
	}
	if _, isExt := fileExtensions[labels[len(labels)-1]]; isExt {
		return false
	}
	for _, prefix := range []string{"http-", "https-", "dns-", "ssl-"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

// ExtractCandidates extracts plausible network targets (URLs, IPv4/CIDR, and
// dotted hostnames that are not known file extensions) from argv tokens.
func ExtractCandidates(arguments []string) []string {
	candidates := make([]string, 0)
	seen := make(map[string]struct{})

	add := func(val string) {
		cleaned := strings.Trim(strings.TrimSpace(val), trailingPunct)
		cleaned = strings.Trim(cleaned, "[]")
		if cleaned == "" {
			return
		}
		if _, dup := seen[cleaned]; dup {
			return
		}
		host := NormalizeHost(cleaned)
		if host == "" {
			return
		}
		if strings.Contains(cleaned, "/") && !strings.Contains(cleaned, "://") {
			if _, err := netip.ParsePrefix(cleaned); err != nil {
				return
			}
		} else {
			_, isIP := parseAddr(host)
			if !isIP && !isValidHostname(host) {
				return
			}
		}
		seen[cleaned] = struct{}{}
		candidates = append(candidates, cleaned)
	}

	for _, raw := range arguments {
		for _, m := range urlCandidateRe.FindAllString(raw, -1) {
			add(m)
		}
		for _, loc := range ipv4CandidateRe.FindAllStringIndex(raw, -1) {
			start, end := loc[0], loc[1]
			if start > 0 && isWordOrDotByte(raw[start-1]) {
				continue
			}
			if end < len(raw) && isWordOrDotByte(raw[end]) {
				continue
			}
			add(raw[start:end])
		}
		stripped := strings.Trim(strings.TrimSpace(raw), trailingPunct)
		if stripped != "" && !strings.HasPrefix(stripped, "-") && !strings.Contains(stripped, "=") {
			host := NormalizeHost(stripped)
			if host != "" && isValidHostname(host) {
				add(stripped)
			}
		}
	}
	return candidates
}

func isWordOrDotByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.'
}

// ScopeCheckResult is returned by ScopeEnforcer.ScopeCheck.
type ScopeCheckResult struct {
	EngagementID   string   `json:"engagement_id"`
	Value          string   `json:"value"`
	Host           string   `json:"host"`
	Allowed        bool     `json:"allowed"`
	MatchedTarget  string   `json:"matched_target,omitempty"`
	BlockedByRule  string   `json:"blocked_by_rule,omitempty"`
	Targets        []string `json:"targets"`
}

// OfflineDecision is returned by ScopeEnforcer.OfflineNetworkDecision.
type OfflineDecision struct {
	Offline    bool   `json:"offline"`
	Executable string `json:"executable"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
}

// CommandScopeDecision is returned by ScopeEnforcer.EnforcementDecision and EnforceScope.
type CommandScopeDecision struct {
	EngagementID       string   `json:"engagement_id"`
	Executable         string   `json:"executable"`
	Enforced           bool     `json:"enforced"`
	Allowed            bool     `json:"allowed"`
	Candidates         []string `json:"candidates"`
	Denied             []string `json:"denied"`
	UnscopedExecutable bool     `json:"unscoped_executable"`
	ShellWrapper       bool     `json:"shell_wrapper"`
	Reason             string   `json:"reason,omitempty"`
}

// URLScopeDecisionResult is returned by ScopeEnforcer.URLScopeDecision and EnforceURLScope.
type URLScopeDecisionResult struct {
	Enforced      bool     `json:"enforced"`
	Allowed       bool     `json:"allowed"`
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	MatchedTarget string   `json:"matched_target,omitempty"`
	BlockedByRule string   `json:"blocked_by_rule,omitempty"`
	Targets       []string `json:"targets"`
	Reason        string   `json:"reason,omitempty"`
}

// ScopeEnforcer enforces engagement Rules of Engagement (allowlist, blocklist,
// offline airgap policy, and shell wrapper refusal).
type ScopeEnforcer struct {
	Store               *EngagementStore
	Blocklist           *Blocklist
	EnforceOverride     *bool
	AllowUnscoped       *bool
	OfflineOverride     *bool
	AllowOfflineNetwork *bool
}

// NewScopeEnforcer creates a ScopeEnforcer backed by store and optional blocklist.
func NewScopeEnforcer(store *EngagementStore, blocklist *Blocklist) *ScopeEnforcer {
	if store == nil {
		store = NewEngagementStore("")
	}
	return &ScopeEnforcer{Store: store, Blocklist: blocklist}
}

func (e *ScopeEnforcer) isEnforced() bool {
	if e != nil && e.EnforceOverride != nil {
		return *e.EnforceOverride
	}
	return EnforcementEnabled()
}

func (e *ScopeEnforcer) isUnscopedAllowed() bool {
	if e != nil && e.AllowUnscoped != nil {
		return *e.AllowUnscoped
	}
	return UnscopedExecutionAllowed()
}

func (e *ScopeEnforcer) isOffline() bool {
	if e != nil && e.OfflineOverride != nil {
		return *e.OfflineOverride
	}
	return OfflineEnabled()
}

func (e *ScopeEnforcer) isOfflineNetworkAllowed() bool {
	if e != nil && e.AllowOfflineNetwork != nil {
		return *e.AllowOfflineNetwork
	}
	return isTruthy(os.Getenv(OfflineNetworkAllowEnv))
}

// ScopeCheck evaluates one target value against the engagement's allowlist and blocklist.
// Blocklist rules always override allowlist matches.
func (e *ScopeEnforcer) ScopeCheck(engagementID, value string) (ScopeCheckResult, error) {
	eng, err := e.Store.Get(engagementID)
	if err != nil {
		return ScopeCheckResult{}, err
	}
	host := NormalizeHost(value)
	res := ScopeCheckResult{
		EngagementID: engagementID,
		Value:        value,
		Host:         host,
		Targets:      append([]string(nil), eng.Targets...),
	}
	if host == "" {
		return res, nil
	}
	rawURL := ""
	if strings.Contains(value, "://") {
		rawURL = value
	}
	if rule, blocked := e.Blocklist.Match(host, rawURL); blocked {
		res.Allowed = false
		res.BlockedByRule = fmt.Sprintf("%s:%s", rule.Kind, rule.Pattern)
		return res, nil
	}
	for _, target := range eng.Targets {
		if TargetMatches(host, target) {
			res.Allowed = true
			res.MatchedTarget = target
			return res, nil
		}
	}
	return res, nil
}

// OfflineNetworkDecision refuses internet-only executables when offline mode is enabled.
func (e *ScopeEnforcer) OfflineNetworkDecision(executable string) OfflineDecision {
	offline := e.isOffline()
	base := filepath.Base(strings.TrimSpace(executable))
	_, isNetOnly := OfflineNetworkExecutables[base]
	blocked := offline && isNetOnly && !e.isOfflineNetworkAllowed()
	reason := ""
	if blocked {
		reason = fmt.Sprintf(
			"%s requires internet access and %s=1 is set; set %s=1 only if the target network provides the required services",
			executable, OfflineEnv, OfflineNetworkAllowEnv,
		)
	}
	return OfflineDecision{
		Offline:    offline,
		Executable: executable,
		Blocked:    blocked,
		Reason:     reason,
	}
}

// EnforceOffline returns an offline_blocked *Error if executable is refused in offline mode.
func (e *ScopeEnforcer) EnforceOffline(executable string) (OfflineDecision, error) {
	dec := e.OfflineNetworkDecision(executable)
	if dec.Blocked {
		return dec, ocerrors.New(
			ocerrors.CodeOfflineBlocked,
			dec.Reason,
			ocerrors.WithDetail("executable", executable),
		)
	}
	return dec, nil
}

// EnforcementDecision inspects an executable and argv against engagement scope,
// blocklist, and shell wrapper policy without returning a refusal error.
func (e *ScopeEnforcer) EnforcementDecision(engagementID, executable string, arguments []string) (CommandScopeDecision, error) {
	candidates := ExtractCandidates(arguments)
	deniedSet := make(map[string]struct{})
	for _, cand := range candidates {
		chk, err := e.ScopeCheck(engagementID, cand)
		if err != nil {
			return CommandScopeDecision{}, err
		}
		if !chk.Allowed {
			deniedSet[cand] = struct{}{}
		}
	}
	denied := make([]string, 0, len(deniedSet))
	for d := range deniedSet {
		denied = append(denied, d)
	}
	sort.Strings(denied)

	wrapper := IsShellWrapper(executable)
	unscoped := IsUnscopedExecutable(executable)
	allowUnscoped := e.isUnscopedAllowed()
	allowed := len(denied) == 0 && (!unscoped || allowUnscoped)

	reason := ""
	if unscoped && !allowUnscoped {
		if wrapper {
			reason = fmt.Sprintf(
				"%s is a shell/process wrapper that executes arbitrary commands and cannot be scope-checked; set %s=1 to allow it under enforcement",
				executable, UnscopedEnv,
			)
		} else {
			reason = fmt.Sprintf(
				"%s executes arbitrary code and cannot be scope-checked; set %s=1 to allow it under enforcement",
				executable, UnscopedEnv,
			)
		}
	} else if len(denied) > 0 {
		reason = "out-of-scope network target(s): " + strings.Join(denied, ", ")
	}

	return CommandScopeDecision{
		EngagementID:       engagementID,
		Executable:         executable,
		Enforced:           e.isEnforced(),
		Allowed:            allowed,
		Candidates:         candidates,
		Denied:             denied,
		UnscopedExecutable: unscoped,
		ShellWrapper:       wrapper,
		Reason:             reason,
	}, nil
}

// EnforceScope checks offline mode and scope enforcement, returning a typed *Error on refusal.
func (e *ScopeEnforcer) EnforceScope(engagementID, executable string, arguments []string) (CommandScopeDecision, error) {
	if _, err := e.EnforceOffline(executable); err != nil {
		return CommandScopeDecision{
			EngagementID: engagementID,
			Executable:   executable,
			Enforced:     e.isEnforced(),
			Allowed:      false,
			Reason:       err.Error(),
		}, err
	}
	dec, err := e.EnforcementDecision(engagementID, executable, arguments)
	if err != nil {
		return CommandScopeDecision{}, err
	}
	if dec.Enforced && !dec.Allowed {
		return dec, ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("scope enforcement refused %s: %s", executable, dec.Reason),
			ocerrors.WithDetails(map[string]any{
				"executable":    executable,
				"denied":        dec.Denied,
				"shell_wrapper": dec.ShellWrapper,
			}),
		)
	}
	return dec, nil
}

// URLScopeDecision evaluates one native HTTP(S) URL target against blocklist and engagement scope.
func (e *ScopeEnforcer) URLScopeDecision(engagementID, rawURL string) (URLScopeDecisionResult, error) {
	if _, err := CanonicalHTTPURL(rawURL); err != nil {
		return URLScopeDecisionResult{}, err
	}
	host := NormalizeHost(rawURL)

	// Blocklist applies even when OPENCYBER_ENFORCE_SCOPE is off if explicitly configured.
	if rule, blocked := e.Blocklist.Match(host, rawURL); blocked {
		return URLScopeDecisionResult{
			Enforced:      e.isEnforced(),
			Allowed:       false,
			URL:           rawURL,
			Host:          host,
			BlockedByRule: fmt.Sprintf("%s:%s", rule.Kind, rule.Pattern),
			Targets:       []string{},
			Reason:        fmt.Sprintf("target %s matched blocklist rule %s:%s", host, rule.Kind, rule.Pattern),
		}, nil
	}

	if !e.isEnforced() {
		return URLScopeDecisionResult{
			Enforced: false,
			Allowed:  true,
			URL:      rawURL,
			Host:     host,
			Targets:  []string{},
		}, nil
	}
	if strings.TrimSpace(engagementID) == "" {
		return URLScopeDecisionResult{
			Enforced: true,
			Allowed:  false,
			URL:      rawURL,
			Host:     host,
			Targets:  []string{},
			Reason:   "engagement_required",
		}, nil
	}
	chk, err := e.ScopeCheck(engagementID, rawURL)
	if err != nil {
		return URLScopeDecisionResult{}, err
	}
	reason := ""
	if !chk.Allowed {
		if chk.BlockedByRule != "" {
			reason = fmt.Sprintf("target %s matched blocklist rule %s", chk.Host, chk.BlockedByRule)
		} else {
			h := chk.Host
			if h == "" {
				h = rawURL
			}
			reason = fmt.Sprintf("out-of-scope network target: %s", h)
		}
	}
	return URLScopeDecisionResult{
		Enforced:      true,
		Allowed:       chk.Allowed,
		URL:           rawURL,
		Host:          chk.Host,
		MatchedTarget: chk.MatchedTarget,
		BlockedByRule: chk.BlockedByRule,
		Targets:       chk.Targets,
		Reason:        reason,
	}, nil
}

// EnforceURLScope validates a native HTTP(S) target and returns a typed *Error if refused.
func (e *ScopeEnforcer) EnforceURLScope(engagementID, rawURL, tool string) (URLScopeDecisionResult, error) {
	dec, err := e.URLScopeDecision(engagementID, rawURL)
	if err != nil {
		return URLScopeDecisionResult{}, err
	}
	if !dec.Allowed && (dec.Enforced || dec.BlockedByRule != "") {
		if dec.Reason == "engagement_required" {
			return dec, ocerrors.New(
				ocerrors.CodeEngagementRequired,
				fmt.Sprintf("%s requires engagement_id while %s is on", tool, ScopeEnv),
				ocerrors.WithDetails(map[string]any{"tool": tool, "url": rawURL}),
			)
		}
		return dec, ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("scope enforcement refused %s: %s", tool, dec.Reason),
			ocerrors.WithDetails(map[string]any{
				"tool":    tool,
				"url":     rawURL,
				"host":    dec.Host,
				"targets": dec.Targets,
			}),
		)
	}
	return dec, nil
}

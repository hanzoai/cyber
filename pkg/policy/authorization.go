package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const (
	// AuthorizationSchemaVersion is the wire schema version of poc/authorization.json.
	AuthorizationSchemaVersion = 1

	// AuthorizationFilename is stored under <engagement>/poc/authorization.json.
	AuthorizationFilename = "authorization.json"

	// AuthorizationHistoryDir archives superseded signed authorizations by SHA-256.
	AuthorizationHistoryDir = "authorization-history"

	// MaxAuthorizationLifetime caps authorization validity to 365 days.
	MaxAuthorizationLifetime = 365 * 24 * time.Hour

	// MinApprovalKeyBytes is the minimum key size for HMAC-SHA256 signing.
	MinApprovalKeyBytes = 32

	// ApprovalKeyEnv supplies the operator HMAC signing key directly.
	ApprovalKeyEnv = "OPENCYBER_APPROVAL_KEY"

	// ApprovalKeyFileEnv supplies a path to a file containing the HMAC signing key.
	ApprovalKeyFileEnv = "OPENCYBER_APPROVAL_KEY_FILE"

	// CustomTechnique is the opt-in tier for agent-authored code.
	CustomTechnique = "custom"
)

// AllowedTechniques lists non-custom PoC technique classes.
var AllowedTechniques = []string{
	"version_assert",
	"http_sequence",
	"http_auth_diff",
	"oob_callback",
	"file_read_canary",
	"tcp_probe",
}

// AllTechniques lists every recognized PoC technique class including custom.
var AllTechniques = map[string]struct{}{
	"version_assert":   {},
	"http_sequence":    {},
	"http_auth_diff":   {},
	"oob_callback":     {},
	"file_read_canary": {},
	"tcp_probe":        {},
	"custom":           {},
}

var (
	hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

	rfc1918Prefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	localIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
	localHostnameSuffixes = []string{".local", ".test", ".localhost"}
)

// AuthorizationRecord is an operator-signed permission record for PoC runs.
type AuthorizationRecord struct {
	SchemaVersion     int      `json:"schema_version"`
	EngagementID      string   `json:"engagement_id"`
	AuthorizedBy      string   `json:"authorized_by"`
	Reference         string   `json:"reference"`
	ReferenceSHA256   string   `json:"reference_sha256,omitempty"`
	ScopeTargets      []string `json:"scope_targets"`
	ValidFrom         string   `json:"valid_from"`
	ValidUntil        string   `json:"valid_until"`
	AllowedTechniques []string `json:"allowed_techniques"`
	CustomCodeAllowed bool     `json:"custom_code_allowed"`
	ProhibitedEffects []string `json:"prohibited_effects"`
	Acknowledgement   string   `json:"acknowledgement"`
	CreatedAt         string   `json:"created_at"`
	KeyID             string   `json:"key_id"`
	HMACSHA256        string   `json:"hmac_sha256"`
}

// AuthorizationStatus is the non-error inspection view returned by DescribeAuthorization.
type AuthorizationStatus struct {
	EngagementID      string               `json:"engagement_id"`
	Status            string               `json:"status"`
	Authorization     *AuthorizationRecord `json:"authorization"`
	Valid             bool                 `json:"valid"`
	ValidUntil        string               `json:"valid_until,omitempty"`
	RemainingSeconds  int64                `json:"remaining_seconds"`
	AllowedTechniques []string             `json:"allowed_techniques"`
	CustomCodeAllowed bool                 `json:"custom_code_allowed"`
	ScopeTargets      []string             `json:"scope_targets"`
	KeyAvailable      bool                 `json:"key_available"`
	Reason            string               `json:"reason,omitempty"`
	Message           string               `json:"message,omitempty"`
}

// DeriveKeyID computes the 16-hex-character key fingerprint for an HMAC key.
func DeriveKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

// ResolveApprovalKey loads the operator HMAC key from OPENCYBER_APPROVAL_KEY or
// OPENCYBER_APPROVAL_KEY_FILE and validates the minimum 32-byte length.
func ResolveApprovalKey() ([]byte, string, error) {
	raw := strings.TrimSpace(os.Getenv(ApprovalKeyEnv))
	if raw == "" {
		if keyFile := strings.TrimSpace(os.Getenv(ApprovalKeyFileEnv)); keyFile != "" {
			data, err := os.ReadFile(keyFile)
			if err != nil {
				return nil, "", ocerrors.New(
					ocerrors.CodeAuthorizationInvalid,
					fmt.Sprintf("cannot read %s: %v", ApprovalKeyFileEnv, err),
					ocerrors.WithDetail("reason", "approval_key_unavailable"),
					ocerrors.WithCause(err),
				)
			}
			raw = strings.TrimSpace(string(data))
		}
	}
	if raw == "" {
		return nil, "", ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			fmt.Sprintf("set %s (at least %d bytes) or %s to enable signed authorization and approvals", ApprovalKeyEnv, MinApprovalKeyBytes, ApprovalKeyFileEnv),
			ocerrors.WithDetail("reason", "approval_key_unavailable"),
		)
	}
	key := []byte(raw)
	if len(key) < MinApprovalKeyBytes {
		return nil, "", ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			fmt.Sprintf("%s must be at least %d bytes", ApprovalKeyEnv, MinApprovalKeyBytes),
			ocerrors.WithDetail("reason", "approval_key_unavailable"),
		)
	}
	return key, DeriveKeyID(key), nil
}

// ApprovalKeyAvailable reports whether a valid approval key is configured in the environment.
func ApprovalKeyAvailable() bool {
	_, _, err := ResolveApprovalKey()
	return err == nil
}

// SignPayload computes the HMAC-SHA256 hex digest over CanonicalJSON(payload).
func SignPayload(key []byte, payload map[string]any) (string, error) {
	encoded, err := ocerrors.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyPayload verifies an HMAC-SHA256 hex signature in constant time.
func VerifyPayload(key []byte, payload map[string]any, expected string) bool {
	if expected == "" {
		return false
	}
	computed, err := SignPayload(key, payload)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(computed), []byte(expected))
}

// SignedPayload returns the exact field set covered by an AuthorizationRecord's HMAC.
func (r AuthorizationRecord) SignedPayload() map[string]any {
	scope := append([]string{}, r.ScopeTargets...)
	if scope == nil {
		scope = []string{}
	}
	techs := append([]string{}, r.AllowedTechniques...)
	if techs == nil {
		techs = []string{}
	}
	prohib := append([]string{}, r.ProhibitedEffects...)
	if prohib == nil {
		prohib = []string{}
	}
	m := map[string]any{
		"schema_version":      r.SchemaVersion,
		"engagement_id":       r.EngagementID,
		"authorized_by":       r.AuthorizedBy,
		"reference":           r.Reference,
		"scope_targets":       scope,
		"valid_from":          r.ValidFrom,
		"valid_until":         r.ValidUntil,
		"allowed_techniques":  techs,
		"custom_code_allowed": r.CustomCodeAllowed,
		"prohibited_effects":  prohib,
		"acknowledgement":     r.Acknowledgement,
		"created_at":          r.CreatedAt,
		"key_id":              r.KeyID,
	}
	if r.ReferenceSHA256 != "" {
		m["reference_sha256"] = r.ReferenceSHA256
	}
	return m
}

// IsPublicTarget reports whether target looks internet-facing (not RFC1918,
// loopback, IPv6 link-local/ULA, localhost, or .local/.test/.localhost).
func IsPublicTarget(target string) bool {
	host := NormalizeHost(target)
	if host == "" {
		return true
	}
	if host == "*" {
		return false
	}
	if strings.Contains(host, "/") {
		pfx, err := netip.ParsePrefix(host)
		if err != nil {
			return true
		}
		return !isLocalPrefix(pfx)
	}
	if addr, ok := parseAddr(host); ok {
		return !isLocalAddr(addr)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return false
	}
	for _, suffix := range localHostnameSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

func isLocalAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() {
		if addr.IsLoopback() {
			return true
		}
		for _, pfx := range rfc1918Prefixes {
			if pfx.Contains(addr) {
				return true
			}
		}
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, pfx := range localIPv6Prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func isLocalPrefix(pfx netip.Prefix) bool {
	for _, local := range rfc1918Prefixes {
		if prefixWithin(pfx, local) {
			return true
		}
	}
	for _, local := range localIPv6Prefixes {
		if prefixWithin(pfx, local) {
			return true
		}
	}
	return false
}

// AuthorizedTargetWithinEngagement reports whether authorized stays within at
// least one declared engagement target (preventing scope expansion).
func AuthorizedTargetWithinEngagement(authorized string, engagementTargets []string) bool {
	host := NormalizeHost(authorized)
	if host == "" {
		return false
	}
	if host == "*" {
		for _, t := range engagementTargets {
			if NormalizeHost(t) == "*" {
				return true
			}
		}
		return false
	}
	if strings.Contains(host, "/") {
		netPfx, err := netip.ParsePrefix(host)
		if err != nil {
			return false
		}
		for _, t := range engagementTargets {
			th := NormalizeHost(t)
			if th == "" {
				continue
			}
			if th == "*" {
				return true
			}
			if strings.Contains(th, "/") {
				targetPfx, terr := netip.ParsePrefix(th)
				if terr == nil && prefixWithin(netPfx, targetPfx) {
					return true
				}
				continue
			}
			if addr, ok := parseAddr(th); ok {
				if addr.Is4() == netPfx.Addr().Is4() && netPfx.IsSingleIP() && netPfx.Contains(addr) {
					return true
				}
			}
		}
		return false
	}
	for _, t := range engagementTargets {
		if NormalizeHost(t) != "" && TargetMatches(host, t) {
			return true
		}
	}
	return false
}

func parseUTC(raw, field string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("authorization field %q is required", field))
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("authorization field %q must be an ISO-8601 timestamp with timezone", field))
}

func readRegularNoSymlink(path, reasonMsg string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, reasonMsg+": file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, reasonMsg+": not a regular file")
	}
	return os.ReadFile(path)
}

func validateAuthorizationSchema(rec *AuthorizationRecord, engagementID string) error {
	if rec == nil {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization record must be a JSON object")
	}
	if rec.SchemaVersion != AuthorizationSchemaVersion {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("unsupported authorization schema_version: %d", rec.SchemaVersion))
	}
	if rec.EngagementID != engagementID {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization engagement_id does not match the request")
	}
	if strings.TrimSpace(rec.AuthorizedBy) == "" {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'authorized_by' must be a non-empty string")
	}
	if strings.TrimSpace(rec.Reference) == "" {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'reference' must be a non-empty string")
	}
	if strings.TrimSpace(rec.Acknowledgement) == "" {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'acknowledgement' must be a non-empty string")
	}
	if rec.ReferenceSHA256 != "" && !hex64Re.MatchString(rec.ReferenceSHA256) {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'reference_sha256' must be a lowercase SHA-256 hex digest")
	}
	if len(rec.ScopeTargets) == 0 {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'scope_targets' must not be empty")
	}
	if len(rec.AllowedTechniques) == 0 {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'allowed_techniques' must not be empty")
	}
	for _, tech := range rec.AllowedTechniques {
		if _, ok := AllTechniques[tech]; !ok {
			return ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("authorization contains unknown technique: %s", tech))
		}
	}
	vf, err := parseUTC(rec.ValidFrom, "valid_from")
	if err != nil {
		return err
	}
	vu, err := parseUTC(rec.ValidUntil, "valid_until")
	if err != nil {
		return err
	}
	if !vu.After(vf) {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization valid_until must be after valid_from")
	}
	if _, err := parseUTC(rec.CreatedAt, "created_at"); err != nil {
		return err
	}
	if strings.TrimSpace(rec.KeyID) == "" {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'key_id' must be a non-empty string")
	}
	if !hex64Re.MatchString(rec.HMACSHA256) {
		return ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization field 'hmac_sha256' must be a lowercase SHA-256 hex digest")
	}
	return nil
}

// ReadAuthorization reads the raw authorization record, returning (nil, nil) if none exists.
func (s *EngagementStore) ReadAuthorization(engagementID string) (*AuthorizationRecord, error) {
	authPath, err := s.ResolvePath(engagementID, filepath.Join("poc", AuthorizationFilename), false)
	if err != nil {
		return nil, err
	}
	raw, err := readRegularNoSymlink(authPath, "cannot read authorization record")
	if err != nil {
		if stderrors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var rec AuthorizationRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("authorization record is not valid JSON: %v", err), ocerrors.WithCause(err))
	}
	return &rec, nil
}

// LoadAuthorization reads and cryptographically verifies the signed authorization record.
func (s *EngagementStore) LoadAuthorization(engagementID string) (*AuthorizationRecord, error) {
	return s.LoadAuthorizationAt(engagementID, time.Now().UTC())
}

// LoadAuthorizationAt verifies the signed authorization record at a specific UTC instant.
func (s *EngagementStore) LoadAuthorizationAt(engagementID string, now time.Time) (*AuthorizationRecord, error) {
	rec, err := s.ReadAuthorization(engagementID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, ocerrors.New(
			ocerrors.CodeAuthorizationRequired,
			fmt.Sprintf("no signed authorization exists for this engagement; run 'opencyber-poc authorize --engagement %s ...' first", engagementID),
			ocerrors.WithDetails(map[string]any{"engagement_id": engagementID, "reason": "authorization_required"}),
		)
	}
	if err := validateAuthorizationSchema(rec, engagementID); err != nil {
		return nil, err
	}
	key, keyID, err := ResolveApprovalKey()
	if err != nil {
		return nil, err
	}
	if rec.KeyID != keyID {
		return nil, ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			"authorization was signed with a different approval key; re-sign it with the current OPENCYBER_APPROVAL_KEY",
		)
	}
	if !VerifyPayload(key, rec.SignedPayload(), rec.HMACSHA256) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization signature does not match its contents")
	}
	vf, _ := parseUTC(rec.ValidFrom, "valid_from")
	vu, _ := parseUTC(rec.ValidUntil, "valid_until")
	if !now.Before(vu) {
		return nil, ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			fmt.Sprintf("authorization expired at %s", rec.ValidUntil),
			ocerrors.WithDetails(map[string]any{"reason": "authorization_expired", "valid_until": rec.ValidUntil}),
		)
	}
	if now.Before(vf) {
		return nil, ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			fmt.Sprintf("authorization is not valid before %s", rec.ValidFrom),
			ocerrors.WithDetails(map[string]any{"reason": "authorization_not_yet_valid", "valid_from": rec.ValidFrom}),
		)
	}
	return rec, nil
}

// DescribeAuthorization returns a non-error status view for oc_authorization_get.
func (s *EngagementStore) DescribeAuthorization(engagementID string) AuthorizationStatus {
	status := AuthorizationStatus{
		EngagementID:      engagementID,
		Status:            "required",
		AllowedTechniques: []string{},
		ScopeTargets:      []string{},
		KeyAvailable:      ApprovalKeyAvailable(),
	}
	rec, err := s.ReadAuthorization(engagementID)
	if err != nil {
		status.Status = "invalid"
		status.Reason = ocerrors.CodeOf(err)
		status.Message = err.Error()
		return status
	}
	if rec == nil {
		status.Reason = "authorization_required"
		return status
	}
	status.Authorization = rec
	status.AllowedTechniques = append([]string{}, rec.AllowedTechniques...)
	status.ScopeTargets = append([]string{}, rec.ScopeTargets...)
	status.CustomCodeAllowed = rec.CustomCodeAllowed
	status.ValidUntil = rec.ValidUntil
	if vu, perr := parseUTC(rec.ValidUntil, "valid_until"); perr == nil {
		rem := int64(time.Until(vu).Seconds())
		if rem > 0 {
			status.RemainingSeconds = rem
		}
	}

	if _, lerr := s.LoadAuthorization(engagementID); lerr != nil {
		reason := ocerrors.CodeOf(lerr)
		var ocErr *ocerrors.Error
		if stderrors.As(lerr, &ocErr) {
			if r, ok := ocErr.Details["reason"].(string); ok && r != "" {
				reason = r
			}
		}
		switch reason {
		case "authorization_expired":
			status.Status = "expired"
		case "authorization_not_yet_valid":
			status.Status = "not_yet_valid"
		case "approval_key_unavailable":
			status.Status = "unverified"
		default:
			status.Status = "invalid"
		}
		status.Reason = reason
		status.Message = lerr.Error()
		return status
	}
	status.Status = "valid"
	status.Valid = true
	return status
}

// ArchivePrevious copies the existing poc/authorization.json into
// poc/authorization-history/<sha256>.json before superseding it.
func (s *EngagementStore) ArchivePrevious(engagementID string) error {
	authPath, err := s.ResolvePath(engagementID, filepath.Join("poc", AuthorizationFilename), false)
	if err != nil {
		return err
	}
	raw, err := readRegularNoSymlink(authPath, "cannot archive authorization record")
	if err != nil {
		if stderrors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	histDir, err := s.ResolvePath(engagementID, filepath.Join("poc", AuthorizationHistoryDir), false)
	if err != nil {
		return err
	}
	dest := filepath.Join(histDir, digest+".json")
	if existing, rerr := os.ReadFile(dest); rerr == nil && string(existing) == string(raw) {
		return nil
	}
	return atomicWriteFile(dest, raw, 0o600)
}

// WriteAuthorization validates, archives any prior record, signs with key, and
// atomically persists poc/authorization.json.
func (s *EngagementStore) WriteAuthorization(engagementID string, input AuthorizationRecord, key []byte, keyID string) (*AuthorizationRecord, error) {
	if len(key) == 0 {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "approval key must be non-empty bytes")
	}
	if keyID != DeriveKeyID(key) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "key_id does not match the supplied approval key")
	}
	eng, err := s.Get(engagementID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if input.SchemaVersion == 0 {
		input.SchemaVersion = AuthorizationSchemaVersion
	}
	if input.SchemaVersion != AuthorizationSchemaVersion {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("unsupported authorization schema_version: %d", input.SchemaVersion))
	}
	authBy := strings.TrimSpace(input.AuthorizedBy)
	ref := strings.TrimSpace(input.Reference)
	ack := strings.TrimSpace(input.Acknowledgement)
	if authBy == "" || ref == "" || ack == "" {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorized_by, reference, and acknowledgement must be non-empty strings")
	}

	refSHA := strings.ToLower(strings.TrimSpace(input.ReferenceSHA256))
	if refSHA != "" && !hex64Re.MatchString(refSHA) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "reference_sha256 must be a lowercase SHA-256 hex digest")
	}

	scopeTargets := dedupeTrimmed(input.ScopeTargets)
	if len(scopeTargets) == 0 {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "scope_targets must not be empty")
	}
	for _, t := range scopeTargets {
		if !AuthorizedTargetWithinEngagement(t, eng.Targets) {
			return nil, ocerrors.New(
				ocerrors.CodeScopeDenied,
				fmt.Sprintf("authorization scope target is outside the engagement targets: %s", t),
				ocerrors.WithDetails(map[string]any{"target": t, "engagement_targets": eng.Targets}),
			)
		}
	}

	techs := dedupeTrimmed(input.AllowedTechniques)
	sort.Strings(techs)
	if len(techs) == 0 {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "allowed_techniques must not be empty")
	}
	hasCustom := false
	for _, tech := range techs {
		if _, ok := AllTechniques[tech]; !ok {
			return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("authorization contains unknown technique: %s", tech))
		}
		if tech == CustomTechnique {
			hasCustom = true
		}
	}
	if hasCustom && !input.CustomCodeAllowed {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "allowed_techniques includes 'custom' but custom_code_allowed is false")
	}

	var vf time.Time
	if strings.TrimSpace(input.ValidFrom) == "" {
		vf = now
	} else {
		vf, err = parseUTC(input.ValidFrom, "valid_from")
		if err != nil {
			return nil, err
		}
	}
	vu, err := parseUTC(input.ValidUntil, "valid_until")
	if err != nil {
		return nil, err
	}
	if !vu.After(now) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization valid_until must be in the future")
	}
	if vu.After(now.Add(MaxAuthorizationLifetime)) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization valid_until cannot exceed 365 days from now")
	}
	if !vf.Before(vu) {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "authorization valid_from must be before valid_until")
	}
	var createdAt time.Time
	if strings.TrimSpace(input.CreatedAt) == "" {
		createdAt = now
	} else {
		createdAt, err = parseUTC(input.CreatedAt, "created_at")
		if err != nil {
			return nil, err
		}
	}

	normalized := AuthorizationRecord{
		SchemaVersion:     AuthorizationSchemaVersion,
		EngagementID:      engagementID,
		AuthorizedBy:      authBy,
		Reference:         ref,
		ReferenceSHA256:   refSHA,
		ScopeTargets:      scopeTargets,
		ValidFrom:         isoUTC(vf),
		ValidUntil:        isoUTC(vu),
		AllowedTechniques: techs,
		CustomCodeAllowed: input.CustomCodeAllowed,
		ProhibitedEffects: dedupeTrimmed(input.ProhibitedEffects),
		Acknowledgement:   ack,
		CreatedAt:         isoUTC(createdAt),
		KeyID:             keyID,
	}
	if normalized.ProhibitedEffects == nil {
		normalized.ProhibitedEffects = []string{}
	}

	sig, err := SignPayload(key, normalized.SignedPayload())
	if err != nil {
		return nil, err
	}
	normalized.HMACSHA256 = sig

	if err := s.ArchivePrevious(engagementID); err != nil {
		return nil, err
	}
	authPath, err := s.ResolvePath(engagementID, filepath.Join("poc", AuthorizationFilename), false)
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(authPath, append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	return &normalized, nil
}

// ValidateForRun verifies that targets, technique, and customCode are covered
// by the engagement's currently valid signed authorization.
func (s *EngagementStore) ValidateForRun(engagementID string, targets []string, technique string, customCode bool) (*AuthorizationRecord, error) {
	rec, err := s.LoadAuthorization(engagementID)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, ocerrors.New(ocerrors.CodeScopeDenied, "at least one run target is required to validate authorization")
	}
	for _, rawTarget := range targets {
		t := strings.TrimSpace(rawTarget)
		if t == "" {
			return nil, ocerrors.New(ocerrors.CodeScopeDenied, "run targets must be non-empty strings")
		}
		matched := false
		for _, authTarget := range rec.ScopeTargets {
			if TargetMatches(t, authTarget) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ocerrors.New(
				ocerrors.CodeScopeDenied,
				fmt.Sprintf("target is outside the signed authorization scope: %s", t),
				ocerrors.WithDetails(map[string]any{"target": t, "authorized_targets": rec.ScopeTargets}),
			)
		}
	}
	if _, ok := AllTechniques[technique]; !ok {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, fmt.Sprintf("unknown or unauthorized technique: %q", technique))
	}
	techAllowed := false
	for _, allowed := range rec.AllowedTechniques {
		if allowed == technique {
			techAllowed = true
			break
		}
	}
	if !techAllowed {
		return nil, ocerrors.New(
			ocerrors.CodeAuthorizationInvalid,
			fmt.Sprintf("technique %q is not allowed by the authorization", technique),
			ocerrors.WithDetails(map[string]any{"technique": technique, "allowed_techniques": rec.AllowedTechniques}),
		)
	}
	if (customCode || technique == CustomTechnique) && !rec.CustomCodeAllowed {
		return nil, ocerrors.New(ocerrors.CodeAuthorizationInvalid, "custom code execution is not authorized for this engagement")
	}
	return rec, nil
}

func dedupeTrimmed(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

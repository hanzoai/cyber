package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

func TestScopeAllowDenyAndBlocklist(t *testing.T) {
	store := NewEngagementStore(t.TempDir())
	eng, err := store.Create("Scope", []string{"10.0.0.0/24", "example.com", "*.partner.test"}, "RoE test")
	if err != nil {
		t.Fatalf("Create engagement failed: %v", err)
	}

	// TargetMatches: CIDR, domains, subdomains, wildcards, IP mismatch.
	if !TargetMatches("10.0.0.7", "10.0.0.0/24") {
		t.Fatal("expected 10.0.0.7 inside 10.0.0.0/24")
	}
	if TargetMatches("10.0.1.7", "10.0.0.0/24") {
		t.Fatal("expected 10.0.1.7 outside 10.0.0.0/24")
	}
	if !TargetMatches("api.example.com", "example.com") || !TargetMatches("example.com", "example.com") {
		t.Fatal("expected example.com and subdomain to match")
	}
	if TargetMatches("example.org", "example.com") || TargetMatches("10.0.0.7", "example.com") {
		t.Fatal("expected non-matching domain/IP to fail")
	}
	if !TargetMatches("app.partner.test", "*.partner.test") {
		t.Fatal("expected wildcard subdomain match")
	}

	// Blocklist overrides allowlist across all 7 kinds.
	bl := &Blocklist{}
	for _, spec := range []struct {
		kind    BlocklistKind
		pattern string
	}{
		{BlockExactDomain, "admin.example.com"},
		{BlockFuzzyDomain, "internal.partner.test"},
		{BlockExactIP, "10.0.0.99"},
		{BlockFuzzyIP, "10.0.0.20"},
		{BlockExactURL, "https://api.example.com/danger"},
		{BlockFuzzyURL, "/prod-delete"},
		{BlockCIDR, "10.0.0.128/25"},
	} {
		if err := bl.Add(spec.kind, spec.pattern, "blocked"); err != nil {
			t.Fatalf("Blocklist.Add(%s, %s) failed: %v", spec.kind, spec.pattern, err)
		}
	}

	enforcer := NewScopeEnforcer(store, bl)
	t.Setenv(ScopeEnv, "1")
	t.Setenv(UnscopedEnv, "")
	t.Setenv(OfflineEnv, "")

	// Allowed in-scope targets.
	chk, err := enforcer.ScopeCheck(eng.EngagementID, "https://api.example.com/v1")
	if err != nil || !chk.Allowed || chk.MatchedTarget != "example.com" {
		t.Fatalf("expected allowed example.com match, got %+v err=%v", chk, err)
	}
	if _, err := enforcer.EnforceScope(eng.EngagementID, "nmap", []string{"-sV", "10.0.0.5", "api.example.com"}); err != nil {
		t.Fatalf("expected in-scope nmap command allowed, got %v", err)
	}

	// Denied out-of-scope target.
	if _, err := enforcer.EnforceScope(eng.EngagementID, "nmap", []string{"-sV", "8.8.8.8"}); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
		t.Fatalf("expected scope_denied for 8.8.8.8, got %v", err)
	}

	// Blocklist overrides in-scope allowlist.
	for _, blocked := range []string{
		"https://admin.example.com/",
		"https://db.internal.partner.test/",
		"http://10.0.0.99/",
		"http://10.0.0.205/",
		"https://api.example.com/danger",
		"https://api.example.com/v1/prod-delete?id=1",
		"http://10.0.0.150/",
	} {
		if _, err := enforcer.EnforceURLScope(eng.EngagementID, blocked, "oc_http_request"); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
			t.Fatalf("expected blocklist scope_denied for %s, got %v", blocked, err)
		}
	}

	// Missing engagement under enforcement returns engagement_required.
	if _, err := enforcer.EnforceURLScope("", "https://api.example.com/v1", "oc_http_request"); !ocerrors.IsCode(err, ocerrors.CodeEngagementRequired) {
		t.Fatalf("expected engagement_required, got %v", err)
	}

	// Candidate extraction ignores filenames and flags.
	cands := ExtractCandidates([]string{
		"https://api.example.com/path",
		"10.0.0.5",
		"10.0.0.0/24",
		"payload.txt",
		"--script=http-title.nse",
		"example.com:8443",
		"not-a-host",
	})
	candSet := make(map[string]bool, len(cands))
	for _, c := range cands {
		candSet[c] = true
	}
	for _, want := range []string{"https://api.example.com/path", "10.0.0.5", "10.0.0.0/24", "example.com:8443"} {
		if !candSet[want] {
			t.Fatalf("expected candidate %q in %v", want, cands)
		}
	}
	for _, reject := range []string{"payload.txt", "--script=http-title.nse"} {
		if candSet[reject] {
			t.Fatalf("did not expect non-host %q in %v", reject, cands)
		}
	}

	// CanonicalHTTPURL & CredentialBoundaryChanged.
	for _, badURL := range []string{
		"",
		"ftp://example.com/",
		"https://user:pass@example.com/",
		`https://example.com\@evil.test/`,
		"https://example%2ecom/",
		"https://example.com:99999/",
	} {
		if _, err := CanonicalHTTPURL(badURL); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
			t.Fatalf("expected invalid_argument for ambiguous URL %q, got %v", badURL, err)
		}
	}
	if changed, err := CredentialBoundaryChanged("http://example.com/a", "https://example.com/b"); err != nil || changed {
		t.Fatalf("same-host HTTP->HTTPS upgrade should retain creds, got (%v, %v)", changed, err)
	}
	if changed, err := CredentialBoundaryChanged("https://example.com/a", "http://example.com/b"); err != nil || !changed {
		t.Fatalf("HTTPS->HTTP downgrade must strip creds, got (%v, %v)", changed, err)
	}
	if changed, err := CredentialBoundaryChanged("https://a.example.com/a", "https://b.example.com/b"); err != nil || !changed {
		t.Fatalf("cross-host hop must strip creds, got (%v, %v)", changed, err)
	}
}

func TestOfflineModeAndShellWrapperBlock(t *testing.T) {
	store := NewEngagementStore(t.TempDir())
	eng, err := store.Create("Wrappers", []string{"example.test"}, "")
	if err != nil {
		t.Fatalf("Create engagement failed: %v", err)
	}
	enforcer := NewScopeEnforcer(store, nil)

	// Verify published count of 27 dangerous shell wrappers.
	if len(ShellWrappers) != 27 {
		t.Fatalf("expected exactly 27 ShellWrappers, got %d", len(ShellWrappers))
	}

	t.Setenv(ScopeEnv, "1")
	t.Setenv(UnscopedEnv, "")
	t.Setenv(OfflineEnv, "")

	// Every single one of the 27 wrappers must be blocked by both EnforceScope and ParseSimpleArgv.
	for wrapper := range ShellWrappers {
		dec, err := enforcer.EnforceScope(eng.EngagementID, wrapper, []string{"example.test"})
		if !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) || !dec.ShellWrapper {
			t.Fatalf("expected shell wrapper %q refused with scope_denied, got dec=%+v err=%v", wrapper, dec, err)
		}
		if _, ok := ParseSimpleArgv(wrapper + " nmap example.test"); ok {
			t.Fatalf("expected ParseSimpleArgv to refuse wrapper %q", wrapper)
		}
	}
	// Interpreters python / python3 are also refused under enforcement.
	for _, interp := range []string{"python", "python3", "/usr/bin/bash"} {
		if _, err := enforcer.EnforceScope(eng.EngagementID, interp, []string{"-c", "print(1)"}); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
			t.Fatalf("expected %q refused under enforcement, got %v", interp, err)
		}
	}

	// ParseSimpleArgv accepts clean single commands and rejects shell metacharacters & expansions.
	if argv, ok := ParseSimpleArgv("nmap -sV example.test"); !ok || len(argv) != 3 || argv[0] != "nmap" {
		t.Fatalf("expected clean simple command parsed, got (%v, %v)", argv, ok)
	}
	for _, unsafe := range []string{
		"nmap example.test | cat",
		"nmap example.test && id",
		"nmap $(whoami)",
		"FOO=1 nmap example.test",
		"nmap example.test > out.txt",
		"nmap `id`",
		"nmap example.*",
	} {
		if _, ok := ParseSimpleArgv(unsafe); ok {
			t.Fatalf("expected ParseSimpleArgv to reject %q", unsafe)
		}
	}

	// Explicit OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1 permits bash.
	t.Setenv(UnscopedEnv, "1")
	if _, err := enforcer.EnforceScope(eng.EngagementID, "bash", []string{"-c", "true"}); err != nil {
		t.Fatalf("expected bash allowed with %s=1, got %v", UnscopedEnv, err)
	}

	// Offline mode blocks internet-only executables unless explicitly overridden.
	t.Setenv(OfflineEnv, "1")
	t.Setenv(OfflineNetworkAllowEnv, "")
	for bin := range OfflineNetworkExecutables {
		if _, err := enforcer.EnforceScope(eng.EngagementID, bin, []string{"info"}); !ocerrors.IsCode(err, ocerrors.CodeOfflineBlocked) {
			t.Fatalf("expected offline_blocked for %s, got %v", bin, err)
		}
	}
	t.Setenv(OfflineNetworkAllowEnv, "1")
	if _, err := enforcer.EnforceScope(eng.EngagementID, "shodan", []string{"info"}); err != nil {
		t.Fatalf("expected shodan allowed when %s=1, got %v", OfflineNetworkAllowEnv, err)
	}
}

func TestSymlinkEscapeRejectionAndWorkspaceConfinement(t *testing.T) {
	base := t.TempDir()
	wsRoot := filepath.Join(base, "workspace")
	outsideDir := filepath.Join(base, "outside")
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatalf("mkdir outside failed: %v", err)
	}
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("top-secret"), 0o600); err != nil {
		t.Fatalf("write outside secret failed: %v", err)
	}

	store := NewEngagementStore(wsRoot)
	first, err := store.Create("First", []string{"first.example"}, "")
	if err != nil {
		t.Fatalf("Create first failed: %v", err)
	}
	second, err := store.Create("Second", []string{"second.example"}, "")
	if err != nil {
		t.Fatalf("Create second failed: %v", err)
	}
	ws := NewWorkspace(store, NewAuditLog(store))

	// Plant symlinks attempting to escape the engagement root.
	linkFile := filepath.Join(first.Workspace, "escape_file.txt")
	linkDir := filepath.Join(first.Workspace, "escape_dir")
	danglingLink := filepath.Join(first.Workspace, "dangling_escape")
	crossEngLink := filepath.Join(first.Workspace, "other_eng")
	if err := os.Symlink(outsideFile, linkFile); err != nil {
		t.Fatalf("symlink file failed: %v", err)
	}
	if err := os.Symlink(outsideDir, linkDir); err != nil {
		t.Fatalf("symlink dir failed: %v", err)
	}
	if err := os.Symlink(filepath.Join(outsideDir, "nonexistent.txt"), danglingLink); err != nil {
		t.Fatalf("dangling symlink failed: %v", err)
	}
	if err := os.Symlink(second.Workspace, crossEngLink); err != nil {
		t.Fatalf("cross-engagement symlink failed: %v", err)
	}

	// All escape vectors must be rejected with scope_denied.
	escapePaths := []string{
		"escape_file.txt",
		"escape_dir/secret.txt",
		"escape_dir/new_file.txt",
		"dangling_escape",
		"other_eng/engagement.json",
		"../outside/secret.txt",
		"../../outside/secret.txt",
		second.Workspace,
		outsideFile,
	}
	for _, p := range escapePaths {
		if _, err := store.ResolvePath(first.EngagementID, p, false); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
			t.Fatalf("expected scope_denied for escape path %q, got %v", p, err)
		}
		if _, err := ws.ReadFile(first.EngagementID, p, 1024, 0); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
			t.Fatalf("expected ReadFile scope_denied for %q, got %v", p, err)
		}
		if _, err := ws.WriteFile(first.EngagementID, p, "pwned", false); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
			t.Fatalf("expected WriteFile scope_denied for %q, got %v", p, err)
		}
	}

	// NUL byte rejected as invalid_argument.
	if _, err := store.ResolvePath(first.EngagementID, "bad\x00path", false); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
		t.Fatalf("expected invalid_argument for NUL path, got %v", err)
	}

	// Verify outside file was never modified.
	if raw, err := os.ReadFile(outsideFile); err != nil || string(raw) != "top-secret" {
		t.Fatalf("outside file was modified: %q err=%v", raw, err)
	}

	// Normal workspace isolation, paged reading, limit enforcement, and server-managed refusal.
	if _, err := ws.WriteFile(first.EngagementID, "notes/page.txt", "0123456789", false); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	page1, err := ws.ReadFile(first.EngagementID, "notes/page.txt", 4, 0)
	if err != nil || page1.Content != "0123" || !page1.Truncated || page1.NextOffset == nil || *page1.NextOffset != 4 || page1.Continuation == nil {
		t.Fatalf("unexpected page1: %+v err=%v", page1, err)
	}
	whole, err := ws.ReadFile(first.EngagementID, "notes/page.txt", 0, 0)
	if err != nil || whole.Content != "0123456789" || whole.Truncated {
		t.Fatalf("unexpected whole read: %+v err=%v", whole, err)
	}
	if _, err := ws.ReadFile(first.EngagementID, "notes/page.txt", MaxWorkspaceReadBytes+1, 0); !ocerrors.IsCode(err, ocerrors.CodeLimitExceeded) {
		t.Fatalf("expected limit_exceeded above ceiling, got %v", err)
	}

	// Refuse writing or deleting server-managed paths.
	for _, protected := range []string{"engagement.json", "poc/authorization.json", "poc/spec.json"} {
		if _, err := ws.WriteFile(first.EngagementID, protected, "{}", false); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
			t.Fatalf("expected invalid_argument writing server-managed %q, got %v", protected, err)
		}
	}
	if _, err := ws.DeletePath(first.EngagementID, "engagement.json"); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
		t.Fatalf("expected invalid_argument deleting engagement.json, got %v", err)
	}

	// Listing engagements returns both.
	listed, err := store.List()
	if err != nil || len(listed.Engagements) != 2 {
		t.Fatalf("expected 2 listed engagements, got %+v err=%v", listed, err)
	}
}

func TestAuditChainRedactionTamperDetectionAndSpecialFiles(t *testing.T) {
	store := NewEngagementStore(t.TempDir())
	eng, err := store.Create("Audit", []string{"example.test"}, "")
	if err != nil {
		t.Fatalf("Create engagement failed: %v", err)
	}
	audit := NewAuditLog(store)
	ctx := context.Background()

	// Record events including credentials and a >64KiB large payload.
	rec1, err := audit.RecordEvent(ctx, eng.EngagementID, map[string]any{
		"event":    "test.secret",
		"password": "hunter2",
		"headers":  map[string]any{"Authorization": "Bearer secret-jwt-token", "Accept": "text/plain"},
		"note":     "token=deadbeef password=hunter2 Bearer anotherToken",
	})
	if err != nil {
		t.Fatalf("RecordEvent 1 failed: %v", err)
	}
	if rec1["password"] != "***" {
		t.Fatalf("expected password redacted, got %v", rec1["password"])
	}
	if hdrs := rec1["headers"].(map[string]any); hdrs["Authorization"] != "***" || hdrs["Accept"] != "text/plain" {
		t.Fatalf("unexpected redacted headers: %+v", hdrs)
	}
	note := rec1["note"].(string)
	for _, leak := range []string{"hunter2", "deadbeef", "anotherToken"} {
		if strings.Contains(note, leak) {
			t.Fatalf("credential %q leaked in audit note: %q", leak, note)
		}
	}

	// Large payload (>100 KiB) should chain cleanly without restarting seq.
	if _, err := audit.RecordEvent(ctx, eng.EngagementID, map[string]any{
		"event":    "test.large",
		"argument": strings.Repeat("x", 100_000),
	}); err != nil {
		t.Fatalf("RecordEvent large failed: %v", err)
	}
	rec3, err := audit.RecordEvent(ctx, eng.EngagementID, map[string]any{"event": "test.three", "value": 3})
	if err != nil {
		t.Fatalf("RecordEvent 3 failed: %v", err)
	}
	if rec3["seq"] != int64(3) {
		t.Fatalf("expected seq 3 after large record, got %v", rec3["seq"])
	}

	// VerifyAudit & offline VerifyChain both pass.
	verified := audit.VerifyAudit(eng.EngagementID)
	if !verified.Valid || verified.Events != 3 || verified.LastHash != rec3["hash"] {
		t.Fatalf("expected valid 3-event audit chain, got %+v", verified)
	}

	// Snapshot verifies and copies stream.
	var snapBuf bytes.Buffer
	snapReport, err := audit.Snapshot(ctx, eng.EngagementID, &snapBuf)
	if err != nil || !snapReport.Valid || snapReport.Events != 3 {
		t.Fatalf("Snapshot failed: %+v err=%v", snapReport, err)
	}
	offline := VerifyChain(bytes.NewReader(snapBuf.Bytes()), eng.EngagementID)
	if !offline.Valid || offline.Events != 3 {
		t.Fatalf("offline VerifyChain failed: %+v", offline)
	}

	// ReadAudit and Summary work.
	readRes, err := audit.ReadAudit(eng.EngagementID, 10, 0, "")
	if err != nil || len(readRes.Events) != 3 || !readRes.TotalExact {
		t.Fatalf("ReadAudit failed: %+v err=%v", readRes, err)
	}
	summary, err := audit.Summary(eng.EngagementID)
	if err != nil || summary.Total != 3 {
		t.Fatalf("Summary failed: %+v err=%v", summary, err)
	}

	// Tamper detection 1: edit a field on line 2.
	auditPath := filepath.Join(eng.Workspace, ".opencyber", "audit", "events.jsonl")
	origBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(origBytes)), "\n")
	var tampered map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &tampered); err != nil {
		t.Fatalf("unmarshal line 2 failed: %v", err)
	}
	tampered["argument"] = "tampered"
	badLine, _ := json.Marshal(tampered)
	editedStream := strings.Join([]string{lines[0], string(badLine), lines[2]}, "\n") + "\n"
	broken := VerifyChain(strings.NewReader(editedStream), eng.EngagementID)
	if broken.Valid || broken.FirstInvalidSeq == nil || *broken.FirstInvalidSeq != 2 || !strings.Contains(broken.Error, "hash") {
		t.Fatalf("expected tamper detection at seq 2 with hash error, got %+v", broken)
	}

	// Tamper detection 2: deleted middle event breaks chain at seq 2.
	deletedStream := strings.Join([]string{lines[0], lines[2]}, "\n") + "\n"
	brokenDel := VerifyChain(strings.NewReader(deletedStream), eng.EngagementID)
	if brokenDel.Valid || brokenDel.FirstInvalidSeq == nil || *brokenDel.FirstInvalidSeq != 2 {
		t.Fatalf("expected deletion detection at seq 2, got %+v", brokenDel)
	}

	// Tamper detection 3: wrong engagement ID fails verification.
	wrongEng := VerifyChain(bytes.NewReader(origBytes), "eng_20260101_00000000000000000000000000000000")
	if wrongEng.Valid || !strings.Contains(wrongEng.Error, "engagement_id") {
		t.Fatalf("expected engagement_id mismatch, got %+v", wrongEng)
	}

	// Corrupted trailing record refuses to restart chain on subsequent append.
	corruptBytes := append(append([]byte{}, origBytes...), []byte("not-json\n")...)
	if err := os.WriteFile(auditPath, corruptBytes, 0o600); err != nil {
		t.Fatalf("write corrupt audit failed: %v", err)
	}
	if _, err := audit.RecordEvent(ctx, eng.EngagementID, map[string]any{"event": "must.not.restart"}); err == nil {
		t.Fatal("expected RecordEvent to refuse appending onto corrupted final record")
	}

	// Unix special file checks: symlink, hardlink, and FIFO must all be rejected!
	if runtime.GOOS != "windows" {
		other, err := store.Create("Other", []string{"other.test"}, "")
		if err != nil {
			t.Fatalf("Create other failed: %v", err)
		}
		if _, err := audit.RecordEvent(ctx, other.EngagementID, map[string]any{"event": "other.original"}); err != nil {
			t.Fatalf("RecordEvent other failed: %v", err)
		}
		otherAudit := filepath.Join(other.Workspace, ".opencyber", "audit", "events.jsonl")
		otherOrig, _ := os.ReadFile(otherAudit)

		victim, err := store.Create("Victim", []string{"victim.test"}, "")
		if err != nil {
			t.Fatalf("Create victim failed: %v", err)
		}
		victimDir := filepath.Join(victim.Workspace, ".opencyber", "audit")
		if err := os.MkdirAll(victimDir, 0o700); err != nil {
			t.Fatalf("mkdir victim audit failed: %v", err)
		}
		victimPath := filepath.Join(victimDir, "events.jsonl")

		// Symlink rejected on write, read, and verify.
		if err := os.Symlink(otherAudit, victimPath); err != nil {
			t.Fatalf("symlink failed: %v", err)
		}
		if _, err := audit.RecordEvent(ctx, victim.EngagementID, map[string]any{"event": "must.not.append"}); err == nil {
			t.Fatal("expected symlink rejected on audit write")
		}
		if _, err := audit.ReadAudit(victim.EngagementID, 10, 0, ""); err == nil {
			t.Fatal("expected symlink rejected on audit read")
		}
		if rep := audit.VerifyAudit(victim.EngagementID); rep.Valid {
			t.Fatalf("expected symlink rejected on audit verify, got %+v", rep)
		}
		_ = os.Remove(victimPath)

		// Hardlink rejected on write.
		if err := os.Link(otherAudit, victimPath); err != nil {
			t.Fatalf("hardlink failed: %v", err)
		}
		if _, err := audit.RecordEvent(ctx, victim.EngagementID, map[string]any{"event": "must.not.append"}); err == nil {
			t.Fatal("expected hardlink rejected on audit write")
		}
		_ = os.Remove(victimPath)

		// FIFO rejected on write.
		if err := syscall.Mkfifo(victimPath, 0o600); err != nil {
			t.Fatalf("mkfifo failed: %v", err)
		}
		if _, err := audit.RecordEvent(ctx, victim.EngagementID, map[string]any{"event": "must.not.append"}); err == nil {
			t.Fatal("expected fifo rejected on audit write")
		}
		_ = os.Remove(victimPath)

		// Confirm other engagement's audit file was untouched.
		if after, _ := os.ReadFile(otherAudit); !bytes.Equal(after, otherOrig) {
			t.Fatal("other engagement audit file was modified through special file attack")
		}
	}
}

func TestAuthorizationSigningVerificationAndHistory(t *testing.T) {
	store := NewEngagementStore(t.TempDir())
	eng, err := store.Create("PoC", []string{"10.0.0.0/24", "app.example.test"}, "")
	if err != nil {
		t.Fatalf("Create engagement failed: %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef_secret_key")
	keyID := DeriveKeyID(key)
	t.Setenv(ApprovalKeyEnv, string(key))

	// Missing authorization reports status=required.
	st := store.DescribeAuthorization(eng.EngagementID)
	if st.Status != "required" || st.Valid || !st.KeyAvailable {
		t.Fatalf("expected required status, got %+v", st)
	}
	if _, err := store.LoadAuthorization(eng.EngagementID); !ocerrors.IsCode(err, ocerrors.CodeAuthorizationRequired) {
		t.Fatalf("expected authorization_required, got %v", err)
	}

	// Scope exceeding engagement targets must fail with scope_denied.
	now := time.Now().UTC()
	_, err = store.WriteAuthorization(eng.EngagementID, AuthorizationRecord{
		AuthorizedBy:      "operator@example.test",
		Reference:         "ROE-2026-001",
		ScopeTargets:      []string{"evil.other.com"},
		ValidFrom:         isoUTC(now.Add(-time.Minute)),
		ValidUntil:        isoUTC(now.Add(24 * time.Hour)),
		AllowedTechniques: []string{"http_sequence"},
		Acknowledgement:   "Written authorization on file.",
	}, key, keyID)
	if !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
		t.Fatalf("expected scope_denied for out-of-engagement auth target, got %v", err)
	}

	// Write valid authorization.
	rec1, err := store.WriteAuthorization(eng.EngagementID, AuthorizationRecord{
		AuthorizedBy:      "operator@example.test",
		Reference:         "ROE-2026-001",
		ScopeTargets:      []string{"10.0.0.10", "app.example.test"},
		ValidFrom:         isoUTC(now.Add(-time.Minute)),
		ValidUntil:        isoUTC(now.Add(24 * time.Hour)),
		AllowedTechniques: []string{"version_assert", "http_sequence"},
		CustomCodeAllowed: false,
		Acknowledgement:   "Written authorization on file.",
	}, key, keyID)
	if err != nil {
		t.Fatalf("WriteAuthorization failed: %v", err)
	}

	// DescribeAuthorization & ValidateForRun succeed for covered targets/techniques.
	st = store.DescribeAuthorization(eng.EngagementID)
	if st.Status != "valid" || !st.Valid || st.RemainingSeconds <= 0 {
		t.Fatalf("expected valid authorization status, got %+v", st)
	}
	if _, err := store.ValidateForRun(eng.EngagementID, []string{"10.0.0.10"}, "http_sequence", false); err != nil {
		t.Fatalf("ValidateForRun failed: %v", err)
	}
	if _, err := store.ValidateForRun(eng.EngagementID, []string{"10.0.0.10"}, "tcp_probe", false); !ocerrors.IsCode(err, ocerrors.CodeAuthorizationInvalid) {
		t.Fatalf("expected unauthorized technique refused, got %v", err)
	}
	if _, err := store.ValidateForRun(eng.EngagementID, []string{"10.0.0.10"}, "http_sequence", true); !ocerrors.IsCode(err, ocerrors.CodeAuthorizationInvalid) {
		t.Fatalf("expected custom code refused when custom_code_allowed=false, got %v", err)
	}
	if _, err := store.ValidateForRun(eng.EngagementID, []string{"10.0.0.11"}, "http_sequence", false); !ocerrors.IsCode(err, ocerrors.CodeScopeDenied) {
		t.Fatalf("expected target outside signed scope refused, got %v", err)
	}

	// Superseding archives the previous record under poc/authorization-history/.
	if _, err := store.WriteAuthorization(eng.EngagementID, AuthorizationRecord{
		AuthorizedBy:      "operator@example.test",
		Reference:         "ROE-2026-002",
		ScopeTargets:      []string{"10.0.0.0/24"},
		ValidFrom:         isoUTC(now.Add(-time.Minute)),
		ValidUntil:        isoUTC(now.Add(48 * time.Hour)),
		AllowedTechniques: []string{"http_sequence", "custom"},
		CustomCodeAllowed: true,
		Acknowledgement:   "Expanded written authorization.",
	}, key, keyID); err != nil {
		t.Fatalf("second WriteAuthorization failed: %v", err)
	}
	histEntries, err := os.ReadDir(filepath.Join(eng.Workspace, "poc", AuthorizationHistoryDir))
	if err != nil || len(histEntries) != 1 {
		t.Fatalf("expected 1 archived authorization record, got %d err=%v", len(histEntries), err)
	}
	_ = rec1

	// Expired check via LoadAuthorizationAt.
	if _, err := store.LoadAuthorizationAt(eng.EngagementID, now.Add(72*time.Hour)); !ocerrors.IsCode(err, ocerrors.CodeAuthorizationInvalid) {
		t.Fatalf("expected expired authorization_invalid, got %v", err)
	}

	// Tampered HMAC is rejected.
	authPath := filepath.Join(eng.Workspace, "poc", AuthorizationFilename)
	raw, _ := os.ReadFile(authPath)
	tamperedRaw := strings.Replace(string(raw), "ROE-2026-002", "ROE-TAMPERED", 1)
	if err := os.WriteFile(authPath, []byte(tamperedRaw), 0o600); err != nil {
		t.Fatalf("write tampered auth failed: %v", err)
	}
	if _, err := store.LoadAuthorization(eng.EngagementID); !ocerrors.IsCode(err, ocerrors.CodeAuthorizationInvalid) {
		t.Fatalf("expected tampered signature rejected, got %v", err)
	}

	// IsPublicTarget checks.
	for _, local := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1", "fe80::1", "fd00::1", "localhost", "app.local", "box.test", "10.0.0.0/24"} {
		if IsPublicTarget(local) {
			t.Fatalf("expected %q treated as local, got public", local)
		}
	}
	for _, pub := range []string{"8.8.8.8", "1.1.1.1", "example.com", "2001:4860:4860::8888", "8.8.8.0/24"} {
		if !IsPublicTarget(pub) {
			t.Fatalf("expected %q treated as public, got local", pub)
		}
	}
}

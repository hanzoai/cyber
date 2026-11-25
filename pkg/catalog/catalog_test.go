package catalog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const expectedRecordedCatalogSHA256 = "ae1da77d082433e47e129b24b4f920e9f2b7a33cf947b3779967d8c4e7d2a726"

func TestEmbeddedCatalogLoadsAll271ToolsAndDigestIsStable(t *testing.T) {
	cat := Default()
	if cat.Len() != 271 {
		t.Fatalf("expected 271 tools, got %d", cat.Len())
	}

	m := cat.Manifest()
	if m.SchemaVersion != CatalogSchemaVersion || m.ContractSchemaVersion != ContractSchemaVersion {
		t.Fatalf("unexpected manifest schema versions: %+v", m)
	}
	if m.Counts.Total != 271 || m.Counts.ByKind["executable"] != 171 || m.Counts.ByKind["native"] != 100 {
		t.Fatalf("unexpected manifest counts: %+v", m.Counts)
	}

	// Verify sorted order and every single per-tool SHA-256 digest.
	all := cat.All()
	for i, entry := range all {
		if i > 0 && all[i-1].Name >= entry.Name {
			t.Fatalf("tools not sorted at index %d: %q >= %q", i, all[i-1].Name, entry.Name)
		}
		if len(entry.Digest) != 64 {
			t.Fatalf("tool %s has invalid digest length %d", entry.Name, len(entry.Digest))
		}
		computed, err := ToolDigest(entry)
		if err != nil {
			t.Fatalf("ToolDigest(%s) failed: %v", entry.Name, err)
		}
		if computed != entry.Digest {
			t.Fatalf("tool %s digest mismatch:\n  recorded: %s\n  computed: %s", entry.Name, entry.Digest, computed)
		}
	}

	// Verify full manifest integrity and exact byte-for-byte canonical SHA-256 digest.
	if err := VerifyManifest(m); err != nil {
		t.Fatalf("VerifyManifest failed: %v", err)
	}
	d1, err := cat.Digest()
	if err != nil {
		t.Fatalf("Digest() failed: %v", err)
	}
	d2, err := cat.Digest()
	if err != nil {
		t.Fatalf("second Digest() failed: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("catalog digest not deterministic: %s != %s", d1, d2)
	}
	if d1 != expectedRecordedCatalogSHA256 {
		t.Fatalf("catalog SHA-256 mismatch:\n  expected: %s\n  got:      %s", expectedRecordedCatalogSHA256, d1)
	}
	if d1 != m.CatalogSHA256 {
		t.Fatalf("computed digest %s != manifest catalog_sha256 %s", d1, m.CatalogSHA256)
	}

	// CountSummary matches manifest counts.
	cs := CountSummaryOf(all)
	if cs.Total != m.Counts.Total || cs.ByKind["executable"] != 171 || cs.ByKind["native"] != 100 {
		t.Fatalf("CountSummaryOf mismatch: %+v", cs)
	}
}

func TestCatalogLookupsAndExecutableSpecs(t *testing.T) {
	cat := Default()

	// Exact name lookup.
	nmap, ok := cat.ByName("oc_nmap")
	if !ok || nmap.Kind != "executable" || nmap.Group != "network" || nmap.Spec == nil || nmap.Spec.Executable != "nmap" {
		t.Fatalf("unexpected oc_nmap entry: %+v", nmap)
	}
	if _, err := cat.Tool("oc_does_not_exist"); !ocerrors.IsCode(err, ocerrors.CodeUnknownTool) {
		t.Fatalf("expected unknown_tool error, got %v", err)
	}

	// Lookup by execution mode (kind).
	execs := cat.ByExecutionMode("executable")
	natives := cat.ByExecutionMode("native")
	if len(execs) != 171 || len(natives) != 100 {
		t.Fatalf("expected 171 executable and 100 native, got %d / %d", len(execs), len(natives))
	}

	// Verify 1-to-1 match between ToolSpecs and executable entries in manifest.
	specs := cat.ExecutableSpecs()
	if len(specs) != 171 {
		t.Fatalf("expected 171 ToolSpecs, got %d", len(specs))
	}
	for _, entry := range execs {
		if entry.Spec == nil {
			t.Fatalf("executable tool %s missing ToolSpec binding", entry.Name)
		}
		if entry.Spec.Category != entry.Group {
			t.Fatalf("tool %s category %q != group %q", entry.Name, entry.Spec.Category, entry.Group)
		}
	}

	// Lookup by binary name and optional/dependency metadata.
	if spec, ok := cat.ByExecutable("tshark"); !ok || spec.Name != "oc_packet_analysis" {
		t.Fatalf("unexpected tshark lookup: %+v %v", spec, ok)
	}
	if spec, ok := cat.ExecutableSpec("oc_terrascan"); !ok || spec.Required || spec.OptionalReason == "" {
		t.Fatalf("expected oc_terrascan to be optional: %+v", spec)
	}
	rustscan, ok := cat.ExecutableSpec("oc_rustscan")
	if !ok || len(rustscan.Dependencies) != 1 || rustscan.Dependencies[0] != "nmap" {
		t.Fatalf("expected oc_rustscan dependency on nmap: %+v", rustscan)
	}
	avail := rustscan.AvailabilityWith(func(bin string) (string, error) {
		if bin == "rustscan" {
			return "/usr/bin/rustscan", nil
		}
		return "", errors.New("not found")
	})
	if avail.Available || len(avail.MissingDependencies) != 1 || avail.MissingDependencies[0] != "nmap" {
		t.Fatalf("expected unavailable due to missing nmap dep: %+v", avail)
	}

	// Lookup by category, shape, scope, and search.
	webTools := cat.ByCategory("web")
	if len(webTools) != 31 {
		t.Fatalf("expected 31 web tools, got %d", len(webTools))
	}
	if len(cat.ByShape(ShapeInspect)) != 46 {
		t.Fatalf("expected 46 inspect tools, got %d", len(cat.ByShape(ShapeInspect)))
	}
	if len(cat.ByScope(ScopeURL)) == 0 {
		t.Fatal("expected URL-scoped tools")
	}
	searched := cat.Search(SearchFilter{Query: "graphql", ExecutionMode: "native"})
	if len(searched) < 2 {
		t.Fatalf("expected >=2 native graphql tools, got %d", len(searched))
	}
	paged := cat.Search(SearchFilter{Category: "web", Limit: 5, Offset: 2})
	if len(paged) != 5 {
		t.Fatalf("expected 5 paged web tools, got %d", len(paged))
	}

	counts := cat.CategoryCounts()
	if counts["web"] != 31 || counts["network"] != 11 || counts["control_plane"] != 18 {
		t.Fatalf("unexpected category counts: %+v", counts)
	}

	// Functional reference inventory coverage should be 100%.
	cov := cat.ReferenceCoverage()
	if len(cov.Uncovered) != 0 {
		t.Fatalf("expected all reference functions covered, uncovered: %v", cov.Uncovered)
	}
}

func TestAlignmentAndRenderManifest(t *testing.T) {
	cat := Default()
	all := cat.All()
	manifest := cat.Manifest()

	// Full match.
	full, err := CheckAlignment(all, manifest, manifest.CatalogSHA256)
	if err != nil {
		t.Fatalf("CheckAlignment(full) failed: %v", err)
	}
	if !full.Recorded || full.Profile != "full" || !full.Matches || !full.SubsetMatches {
		t.Fatalf("expected full match, got %+v", full)
	}
	if full.MatchesExpected == nil || !*full.MatchesExpected {
		t.Fatalf("expected MatchesExpected=true, got %+v", full)
	}

	// Pinned expected digest mismatch.
	pinnedBad, err := CheckAlignment(all, manifest, strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("CheckAlignment(pinnedBad) failed: %v", err)
	}
	if pinnedBad.MatchesExpected == nil || *pinnedBad.MatchesExpected {
		t.Fatalf("expected MatchesExpected=false, got %+v", pinnedBad)
	}

	// Compact subset (drop all 13 browser tools).
	subset := make([]*ToolEntry, 0, len(all)-13)
	for _, entry := range all {
		if !strings.HasPrefix(entry.Name, "oc_browser_") {
			subset = append(subset, entry)
		}
	}
	compact, err := CheckAlignment(subset, manifest, "")
	if err != nil {
		t.Fatalf("CheckAlignment(compact) failed: %v", err)
	}
	if compact.Profile != "compact" || compact.Matches || !compact.SubsetMatches || compact.MissingToolCount != 13 {
		t.Fatalf("unexpected compact alignment: %+v", compact)
	}

	// Tampered tool description is flagged in changed_tools.
	modified := make([]*ToolEntry, len(all))
	copy(modified, all)
	cp := *modified[0]
	cp.Description += " tampered"
	modified[0] = &cp
	changed, err := CheckAlignment(modified, manifest, "")
	if err != nil {
		t.Fatalf("CheckAlignment(changed) failed: %v", err)
	}
	if changed.Matches || changed.SubsetMatches || len(changed.ChangedTools) != 1 || changed.ChangedTools[0] != cp.Name {
		t.Fatalf("expected changed tool %s, got %+v", cp.Name, changed)
	}

	// Unexpected tool is named.
	extra := append([]*ToolEntry{}, all...)
	fake, err := ProjectTool(ToolContract{
		Name:       "oc_not_recorded",
		Kind:       "native",
		Group:      "diagnostics",
		Shape:      ShapeInspect,
		Scope:      ScopeNone,
		Idempotent: true,
		ErrorCodes: []string{"internal_error"},
	}, ToolRegistration{Description: "fake"})
	if err != nil {
		t.Fatalf("ProjectTool failed: %v", err)
	}
	extra = append(extra, fake)
	unexp, err := CheckAlignment(extra, manifest, "")
	if err != nil {
		t.Fatalf("CheckAlignment(unexpected) failed: %v", err)
	}
	if unexp.SubsetMatches || len(unexp.UnexpectedTools) != 1 || unexp.UnexpectedTools[0] != "oc_not_recorded" {
		t.Fatalf("expected unexpected tool oc_not_recorded, got %+v", unexp)
	}

	// Tampered manifest header cannot pass as a full or subset match.
	tamperedManifest := *manifest
	tamperedManifest.CatalogSHA256 = strings.Repeat("0", 64)
	tamperedReport, err := CheckAlignment(subset, &tamperedManifest, "")
	if err != nil {
		t.Fatalf("CheckAlignment(tampered) failed: %v", err)
	}
	if tamperedReport.Matches || tamperedReport.SubsetMatches {
		t.Fatalf("tampered manifest must not pass: %+v", tamperedReport)
	}

	// Unrecorded manifest.
	unrec, err := CheckAlignment(all, nil, "")
	if err != nil {
		t.Fatalf("CheckAlignment(nil) failed: %v", err)
	}
	if unrec.Recorded || unrec.Profile != "unrecorded" || unrec.Matches || unrec.SubsetMatches {
		t.Fatalf("unexpected unrecorded alignment: %+v", unrec)
	}

	// RenderManifest is deterministic, one tool per line, and server_version does not alter digest.
	r1, err := RenderManifest(all, "0.3.0")
	if err != nil {
		t.Fatalf("RenderManifest failed: %v", err)
	}
	r2, err := RenderManifest(all, "9.9.9")
	if err != nil {
		t.Fatalf("RenderManifest failed: %v", err)
	}
	var m1, m2 Manifest
	if err := json.Unmarshal([]byte(r1), &m1); err != nil {
		t.Fatalf("unmarshal r1 failed: %v", err)
	}
	if err := json.Unmarshal([]byte(r2), &m2); err != nil {
		t.Fatalf("unmarshal r2 failed: %v", err)
	}
	if m1.CatalogSHA256 != m2.CatalogSHA256 || m1.CatalogSHA256 != expectedRecordedCatalogSHA256 {
		t.Fatalf("server_version altered catalog_sha256: %s vs %s", m1.CatalogSHA256, m2.CatalogSHA256)
	}
	toolLines := 0
	for _, line := range strings.Split(r1, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " "), `{"annotations"`) {
			toolLines++
		}
	}
	if toolLines != 271 {
		t.Fatalf("expected 271 tool lines, got %d", toolLines)
	}

	size, err := PayloadBytes(all)
	if err != nil || size <= 100_000 {
		t.Fatalf("expected PayloadBytes > 100000, got (%d, %v)", size, err)
	}
}

func TestContractMetadataAndArgumentValidation(t *testing.T) {
	cat := Default()

	// Contract helpers & annotations.
	catalogContract, err := ContractFor("oc_catalog")
	if err != nil {
		t.Fatalf("ContractFor(oc_catalog) failed: %v", err)
	}
	if !catalogContract.ReadOnly() || catalogContract.ProvenanceSource() != "server" {
		t.Fatalf("unexpected oc_catalog contract: %+v", catalogContract)
	}
	if ann := catalogContract.Annotations(); ann.Title != "Catalog" || !ann.ReadOnlyHint || ann.DestructiveHint {
		t.Fatalf("unexpected annotations: %+v", ann)
	}

	if err := ValidateAdvertised([]string{"oc_catalog", "oc_nmap"}); err != nil {
		t.Fatalf("ValidateAdvertised failed: %v", err)
	}
	if err := ValidateAdvertised([]string{"oc_catalog", "oc_bogus"}); !ocerrors.IsCode(err, ocerrors.CodeUnknownTool) {
		t.Fatalf("expected unknown_tool from ValidateAdvertised, got %v", err)
	}

	// Valid arguments pass.
	if err := ValidateArguments("oc_nmap", map[string]any{
		"engagement_id":     "eng_20261125_0123456789abcdef0123456789abcdef",
		"arguments":         []string{"-sV", "10.0.0.1"},
		"stdin":             nil,
		"working_directory": ".",
	}); err != nil {
		t.Fatalf("expected valid oc_nmap arguments to pass, got %v", err)
	}

	// Missing required parameter fails with missing_parameter.
	if err := ValidateArguments("oc_nmap", map[string]any{
		"engagement_id": "eng_20261125_0123456789abcdef0123456789abcdef",
	}); !ocerrors.IsCode(err, ocerrors.CodeMissingParameter) {
		t.Fatalf("expected missing_parameter, got %v", err)
	}

	// Unknown parameter fails with invalid_argument.
	if err := ValidateArguments("oc_nmap", map[string]any{
		"engagement_id": "eng_20261125_0123456789abcdef0123456789abcdef",
		"arguments":     []string{"-sV"},
		"bogus_flag":    true,
	}); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
		t.Fatalf("expected invalid_argument for unknown param, got %v", err)
	}

	// Wrong type for array items fails with invalid_argument.
	if err := ValidateArguments("oc_nmap", map[string]any{
		"engagement_id": "eng_20261125_0123456789abcdef0123456789abcdef",
		"arguments":     []any{"-sV", 123},
	}); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
		t.Fatalf("expected invalid_argument for non-string argv element, got %v", err)
	}

	// Nullable object and number validation on oc_api_fuzz.
	if err := cat.ValidateArguments("oc_api_fuzz", map[string]any{
		"engagement_id": "eng_20261125_0123456789abcdef0123456789abcdef",
		"base_url":      "https://example.test",
		"path":          "/v1/items",
		"method":        "GET",
		"location":      "query",
		"parameter":     "id",
		"payloads":      []string{"1", "2"},
		"max_requests":  10,
		"headers":       map[string]string{"Accept": "application/json"},
		"timeout":       15.5,
	}); err != nil {
		t.Fatalf("expected valid oc_api_fuzz arguments to pass, got %v", err)
	}

	// Float passed to integer field must fail.
	if err := cat.ValidateArguments("oc_api_fuzz", map[string]any{
		"engagement_id": "eng_20261125_0123456789abcdef0123456789abcdef",
		"base_url":      "https://example.test",
		"path":          "/v1/items",
		"method":        "GET",
		"location":      "query",
		"parameter":     "id",
		"payloads":      []string{"1"},
		"max_requests":  10.5,
	}); !ocerrors.IsCode(err, ocerrors.CodeInvalidArgument) {
		t.Fatalf("expected invalid_argument for float in integer field, got %v", err)
	}
}

package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

// CatalogSchemaVersion is the wire schema version of catalog.json.
const CatalogSchemaVersion = 1

// CountSummary aggregates tool counts by kind, group, and shape.
type CountSummary struct {
	Total   int            `json:"total"`
	ByKind  map[string]int `json:"by_kind"`
	ByGroup map[string]int `json:"by_group"`
	ByShape map[string]int `json:"by_shape"`
}

// Manifest is the recorded release catalog manifest (data/catalog.json).
type Manifest struct {
	SchemaVersion         int          `json:"schema_version"`
	ContractSchemaVersion int          `json:"contract_schema_version"`
	GeneratedBy           string       `json:"generated_by"`
	ServerVersion         string       `json:"server_version"`
	CatalogSHA256         string       `json:"catalog_sha256"`
	Counts                CountSummary `json:"counts"`
	Tools                 []*ToolEntry `json:"tools"`
}

// ToolRegistration is the runtime descriptor passed into ProjectTools for live alignment checks.
type ToolRegistration struct {
	Description  string
	InputSchema  map[string]any
	OutputSchema map[string]any
	Annotations  map[string]any
	Meta         map[string]any
}

// AlignmentReport compares a live advertised tool set against a recorded Manifest.
type AlignmentReport struct {
	Recorded              bool     `json:"recorded"`
	Profile               string   `json:"profile"`
	Matches               bool     `json:"matches"`
	SubsetMatches         bool     `json:"subset_matches"`
	RecordedSHA256        *string  `json:"recorded_sha256"`
	AdvertisedSHA256      string   `json:"advertised_sha256"`
	RecordedToolCount     *int     `json:"recorded_tool_count"`
	AdvertisedToolCount   int      `json:"advertised_tool_count"`
	MissingToolCount      int      `json:"missing_tool_count"`
	UnexpectedTools       []string `json:"unexpected_tools"`
	ChangedTools          []string `json:"changed_tools"`
	ContractSchemaVersion int      `json:"contract_schema_version"`
	ExpectedDigest        string   `json:"expected_digest,omitempty"`
	MatchesExpected       *bool    `json:"matches_expected"`
}

// ToolDigest computes the deterministic SHA-256 digest of a single ToolEntry
// (excluding the "digest" field itself), matching catalog_identity.py:project_tool.
func ToolDigest(entry *ToolEntry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("nil tool entry")
	}
	encoded, err := ocerrors.CanonicalJSON(entry.canonicalMap(false))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ProjectTool builds a digested ToolEntry from a contract and runtime tool registration.
func ProjectTool(contract ToolContract, reg ToolRegistration) (*ToolEntry, error) {
	entry := &ToolEntry{
		Name:                 contract.Name,
		Kind:                 contract.Kind,
		Group:                contract.Group,
		Shape:                contract.Shape,
		Effects:              append([]Effect(nil), contract.Effects...),
		Scope:                contract.Scope,
		RequiresEngagement:   contract.RequiresEngagement,
		Destructive:          contract.Destructive,
		OpenWorld:            contract.OpenWorld,
		Idempotent:           contract.Idempotent,
		ReturnsTargetContent: contract.ReturnsTargetContent,
		ErrorCodes:           append([]string(nil), contract.ErrorCodes...),
		Description:          reg.Description,
		InputSchema:          reg.InputSchema,
		OutputSchema:         reg.OutputSchema,
		Annotations:          reg.Annotations,
		Meta:                 reg.Meta,
	}
	if entry.InputSchema == nil {
		entry.InputSchema = map[string]any{}
	}
	if entry.Annotations == nil {
		entry.Annotations = map[string]any{}
	}
	if entry.Meta == nil {
		entry.Meta = map[string]any{}
	}
	digest, err := ToolDigest(entry)
	if err != nil {
		return nil, err
	}
	entry.Digest = digest
	return entry, nil
}

// ProjectTools projects and digests a map of registered tools, sorted by tool name.
func ProjectTools(contracts map[string]ToolContract, regs map[string]ToolRegistration) ([]*ToolEntry, error) {
	names := make([]string, 0, len(regs))
	for name := range regs {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]*ToolEntry, 0, len(names))
	for _, name := range names {
		contract, ok := contracts[name]
		if !ok {
			return nil, ocerrors.New(
				ocerrors.CodeUnknownTool,
				fmt.Sprintf("no contract registered for tool %s", name),
				ocerrors.WithDetail("tool", name),
			)
		}
		entry, err := ProjectTool(contract, regs[name])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// CatalogSHA256 computes the canonical SHA-256 over contract_schema_version and
// all tool entries (including each tool's per-entry digest), matching
// catalog_identity.py:catalog_sha256 byte-for-byte.
func CatalogSHA256(entries []*ToolEntry) (string, error) {
	sorted := make([]*ToolEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	tools := make([]map[string]any, len(sorted))
	for i, entry := range sorted {
		tools[i] = entry.canonicalMap(true)
	}
	material := map[string]any{
		"contract_schema_version": ContractSchemaVersion,
		"tools":                   tools,
	}
	encoded, err := ocerrors.CanonicalJSON(material)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// CountSummaryOf computes kind, group, and shape totals across entries.
func CountSummaryOf(entries []*ToolEntry) CountSummary {
	byKind := make(map[string]int)
	byGroup := make(map[string]int)
	byShape := make(map[string]int)
	for _, entry := range entries {
		byKind[entry.Kind]++
		byGroup[entry.Group]++
		byShape[string(entry.Shape)]++
	}
	return CountSummary{
		Total:   len(entries),
		ByKind:  byKind,
		ByGroup: byGroup,
		ByShape: byShape,
	}
}

// VerifyManifest validates schema versions, name uniqueness, every per-tool SHA-256
// digest, and the top-level catalog_sha256 digest.
func VerifyManifest(m *Manifest) error {
	if m == nil {
		return ocerrors.New(ocerrors.CodeIntegrityMismatch, "manifest is nil")
	}
	if m.SchemaVersion != CatalogSchemaVersion {
		return ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("unsupported catalog schema_version: %d", m.SchemaVersion))
	}
	if m.ContractSchemaVersion != ContractSchemaVersion {
		return ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("unsupported contract_schema_version: %d", m.ContractSchemaVersion))
	}
	seen := make(map[string]struct{}, len(m.Tools))
	for _, entry := range m.Tools {
		if entry == nil || entry.Name == "" {
			return ocerrors.New(ocerrors.CodeIntegrityMismatch, "manifest contains unnamed tool entry")
		}
		if _, dup := seen[entry.Name]; dup {
			return ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("duplicate tool in manifest: %s", entry.Name))
		}
		seen[entry.Name] = struct{}{}
		expected, err := ToolDigest(entry)
		if err != nil {
			return ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("cannot hash tool %s: %v", entry.Name, err), ocerrors.WithCause(err))
		}
		if entry.Digest != expected {
			return ocerrors.New(
				ocerrors.CodeIntegrityMismatch,
				fmt.Sprintf("tool %s digest mismatch: recorded %s != computed %s", entry.Name, entry.Digest, expected),
				ocerrors.WithDetails(map[string]any{"tool": entry.Name, "recorded": entry.Digest, "computed": expected}),
			)
		}
	}
	computed, err := CatalogSHA256(m.Tools)
	if err != nil {
		return ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("cannot hash catalog: %v", err), ocerrors.WithCause(err))
	}
	if m.CatalogSHA256 != computed {
		return ocerrors.New(
			ocerrors.CodeIntegrityMismatch,
			fmt.Sprintf("catalog_sha256 mismatch: recorded %s != computed %s", m.CatalogSHA256, computed),
			ocerrors.WithDetails(map[string]any{"recorded": m.CatalogSHA256, "computed": computed}),
		)
	}
	return nil
}

// CheckAlignment compares an advertised tool list against a recorded manifest
// and optional pinned expectedDigest (matching catalog_identity.py:alignment).
func CheckAlignment(advertised []*ToolEntry, recorded *Manifest, expectedDigest string) (AlignmentReport, error) {
	sortedAdv := make([]*ToolEntry, len(advertised))
	copy(sortedAdv, advertised)
	sort.Slice(sortedAdv, func(i, j int) bool { return sortedAdv[i].Name < sortedAdv[j].Name })

	advSHA, err := CatalogSHA256(sortedAdv)
	if err != nil {
		return AlignmentReport{}, err
	}
	report := AlignmentReport{
		AdvertisedSHA256:      advSHA,
		AdvertisedToolCount:   len(sortedAdv),
		UnexpectedTools:       []string{},
		ChangedTools:          []string{},
		ContractSchemaVersion: ContractSchemaVersion,
		ExpectedDigest:        expectedDigest,
	}
	if expectedDigest != "" {
		matched := advSHA == expectedDigest
		report.MatchesExpected = &matched
	}

	if recorded == nil {
		report.Recorded = false
		report.Profile = "unrecorded"
		return report, nil
	}

	manifestValid := VerifyManifest(recorded) == nil
	recByName := make(map[string]*ToolEntry, len(recorded.Tools))
	for _, entry := range recorded.Tools {
		if entry != nil && entry.Name != "" {
			recByName[entry.Name] = entry
		}
	}
	advByName := make(map[string]*ToolEntry, len(sortedAdv))
	for _, entry := range sortedAdv {
		if entry != nil && entry.Name != "" {
			advByName[entry.Name] = entry
		}
	}

	var unexpected, missing, changed []string
	for name := range advByName {
		if _, ok := recByName[name]; !ok {
			unexpected = append(unexpected, name)
		}
	}
	for name := range recByName {
		if _, ok := advByName[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name, advEntry := range advByName {
		if recEntry, ok := recByName[name]; ok {
			advDigest, derr := ToolDigest(advEntry)
			if derr != nil || advDigest != recEntry.Digest {
				changed = append(changed, name)
			}
		}
	}
	sort.Strings(unexpected)
	sort.Strings(missing)
	sort.Strings(changed)
	if unexpected == nil {
		unexpected = []string{}
	}
	if changed == nil {
		changed = []string{}
	}

	var profile string
	switch {
	case len(sortedAdv) == len(recorded.Tools):
		profile = "full"
	case len(missing) > 0 && len(unexpected) == 0 && len(changed) == 0:
		if len(sortedAdv) < len(recorded.Tools) {
			profile = "compact"
		} else {
			profile = "subset"
		}
	default:
		profile = "subset"
	}

	recSHA := recorded.CatalogSHA256
	recCount := len(recorded.Tools)
	matches := manifestValid &&
		profile == "full" &&
		len(unexpected) == 0 &&
		len(changed) == 0 &&
		recSHA == advSHA &&
		recorded.ContractSchemaVersion == ContractSchemaVersion
	subsetMatches := manifestValid &&
		len(unexpected) == 0 &&
		len(changed) == 0 &&
		recorded.ContractSchemaVersion == ContractSchemaVersion

	report.Recorded = true
	report.Profile = profile
	report.Matches = matches
	report.SubsetMatches = subsetMatches
	report.RecordedSHA256 = &recSHA
	report.RecordedToolCount = &recCount
	report.MissingToolCount = len(missing)
	report.UnexpectedTools = unexpected
	report.ChangedTools = changed
	return report, nil
}

// RenderManifest renders a deterministic manifest with one tool per line,
// matching catalog_identity.py:render_manifest.
func RenderManifest(entries []*ToolEntry, serverVersion string) (string, error) {
	sorted := make([]*ToolEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	sha, err := CatalogSHA256(sorted)
	if err != nil {
		return "", err
	}
	counts := CountSummaryOf(sorted)

	type headerPair struct {
		key string
		val any
	}
	headers := []headerPair{
		{"schema_version", CatalogSchemaVersion},
		{"contract_schema_version", ContractSchemaVersion},
		{"generated_by", "scripts/record-catalog.py"},
		{"server_version", serverVersion},
		{"catalog_sha256", sha},
		{"counts", counts},
	}

	var b strings.Builder
	b.WriteString("{\n")
	for _, h := range headers {
		rawVal, err := jsonMarshalNoEscape(h.val)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "  %q: %s,\n", h.key, rawVal)
	}
	b.WriteString("  \"tools\": [\n")
	for i, entry := range sorted {
		line, err := ocerrors.CanonicalJSON(entry.canonicalMap(true))
		if err != nil {
			return "", err
		}
		b.WriteString("    ")
		b.Write(line)
		if i < len(sorted)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  ]\n}\n")
	return b.String(), nil
}

// PayloadBytes returns the wire byte size of the advertised tool list
// (excluding server-side digest and contract duplication), matching catalog_identity.py:payload_bytes.
func PayloadBytes(entries []*ToolEntry) (int, error) {
	sorted := make([]*ToolEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	wire := make([]map[string]any, len(sorted))
	for i, entry := range sorted {
		var outSchema any
		if entry.OutputSchema != nil {
			outSchema = entry.OutputSchema
		}
		wire[i] = map[string]any{
			"name":         entry.Name,
			"description":  entry.Description,
			"inputSchema":  entry.InputSchema,
			"outputSchema": outSchema,
			"annotations":  entry.Annotations,
			"meta":         entry.Meta,
		}
	}
	encoded, err := ocerrors.CanonicalJSON(wire)
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

func jsonMarshalNoEscape(v any) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

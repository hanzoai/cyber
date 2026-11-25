package exec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// OfflineEnv enables strict air-gapped operation when set to a truthy value.
	OfflineEnv = "OPENCYBER_OFFLINE"
	// OfflineNetworkAllowEnv permits internet-facing tools inside an offline enclave when explicitly enabled.
	OfflineNetworkAllowEnv = "OPENCYBER_OFFLINE_ALLOW_NETWORK"
	// CVEDBEnv overrides the local offline CVE database path.
	CVEDBEnv = "OPENCYBER_CVE_DB"
	// AssetManifestEnv overrides the build-time offline asset manifest path.
	AssetManifestEnv = "OPENCYBER_ASSET_MANIFEST"

	DefaultCVEDB        = "/usr/share/opencyber/cve/cve.sqlite"
	DefaultManifestPath = "/usr/share/opencyber/asset-manifest.json"
)

// OfflineNetworkExecutables is the single source of truth for executables refused
// while OPENCYBER_OFFLINE=1 (unless OPENCYBER_OFFLINE_ALLOW_NETWORK=1).
var OfflineNetworkExecutables = map[string]struct{}{
	"shodan":       {},
	"censys":       {},
	"subfinder":    {},
	"theHarvester": {},
	"sherlock":     {},
}

// AssetSpec describes one offline asset expected in a self-contained deployment.
type AssetSpec struct {
	Name              string
	Path              string
	ResolvePath       func() string
	Kind              string // "file" or "tree"
	MinCount          int
	MinBytes          int64
	Required          bool
	Description       string
	InternetDependent bool
}

// ResolvedPath returns the effective filesystem path for this asset.
func (s AssetSpec) ResolvedPath() string {
	if s.ResolvePath != nil {
		return s.ResolvePath()
	}
	return s.Path
}

// DefaultAssetSpecs returns the standard offline asset inventory specs.
func DefaultAssetSpecs() []AssetSpec {
	return []AssetSpec{
		{
			Name:        "nuclei-templates",
			ResolvePath: func() string { home, _ := os.UserHomeDir(); return filepath.Join(home, ".local", "nuclei-templates") },
			Kind:        "tree",
			MinCount:    5000,
			Required:    true,
			Description: "Nuclei template store; scanning is meaningless without it.",
		},
		{
			Name:        "seclists",
			Path:        "/usr/share/seclists",
			Kind:        "tree",
			MinCount:    1000,
			Required:    true,
			Description: "Discovery, fuzzing, payload, and password lists.",
		},
		{
			Name:        "baseline-password-dictionary",
			Path:        "/usr/share/wordlists/opencyber-keyboard-patterns.txt",
			Kind:        "file",
			MinBytes:    1_000_000,
			Required:    true,
			Description: "SecLists generated keyboard-pattern dictionary; not a breach-password corpus.",
		},
		{
			Name:        "rockyou",
			Path:        "/usr/share/wordlists/rockyou.txt",
			Kind:        "file",
			MinBytes:    100_000_000,
			Required:    false,
			Description: "Optional operator-provided RockYou corpus; not included without a redistribution basis.",
		},
		{
			Name:        "exploitdb",
			Path:        "/usr/share/exploitdb",
			Kind:        "tree",
			MinCount:    40_000,
			Required:    true,
			Description: "Local exploit database used by searchsploit.",
		},
		{
			Name:        "nmap-scripts",
			Path:        "/usr/share/nmap/scripts",
			Kind:        "tree",
			MinCount:    500,
			Required:    true,
			Description: "Bundled Nmap NSE scripts for authorized local-network assessments.",
		},
		{
			Name:        "wpscan-database",
			Path:        "/usr/share/opencyber/wpscan-cache/wpscan/db",
			Kind:        "tree",
			MinCount:    8,
			Required:    true,
			Description: "WPScan local detection metadata and its license.",
		},
		{
			Name:        "wordlists",
			Path:        "/usr/share/wordlists",
			Kind:        "tree",
			MinCount:    2,
			Required:    true,
			Description: "Shared wordlist directory.",
		},
		{
			Name:        "wireshark-data",
			Path:        "/usr/share/wireshark",
			Kind:        "tree",
			MinCount:    50,
			Required:    false,
			Description: "Wireshark profiles, filters, and OUI data for passive attribution.",
		},
		{
			Name:        "cve-database",
			ResolvePath: LocalCVEDB,
			Kind:        "file",
			MinBytes:    100_000,
			Required:    false,
			Description: "Optional local CVE index for offline oc_cve_lookup.",
		},
	}
}

// OfflineEnabled returns true when OPENCYBER_OFFLINE is set to a truthy value.
func OfflineEnabled() bool {
	return isTruthy(os.Getenv(OfflineEnv))
}

// LocalCVEDB returns the configured local offline CVE database path.
func LocalCVEDB() string {
	if p := strings.TrimSpace(os.Getenv(CVEDBEnv)); p != "" {
		return p
	}
	return DefaultCVEDB
}

// AssetManifestPath returns the configured asset manifest path.
func AssetManifestPath() string {
	if p := strings.TrimSpace(os.Getenv(AssetManifestEnv)); p != "" {
		return p
	}
	return DefaultManifestPath
}

// RequireOnline returns an offline_blocked *Error if OPENCYBER_OFFLINE is enabled.
func RequireOnline(feature string) error {
	if !OfflineEnabled() {
		return nil
	}
	return NewError(
		"offline_blocked",
		fmt.Sprintf("%s requires internet access, but %s=1 is set. Use local assets or a locally built CVE index (%s) instead.",
			feature, OfflineEnv, CVEDBEnv),
		WithDetails(map[string]any{"feature": feature}),
	)
}

// AssetEntry holds the measured status of one offline asset.
type AssetEntry struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Required          bool   `json:"required"`
	InternetDependent bool   `json:"internet_dependent"`
	MinCount          int    `json:"min_count"`
	MinBytes          int64  `json:"min_bytes"`
	Path              string `json:"path"`
	Exists            bool   `json:"exists"`
	Kind              string `json:"kind"`
	Count             int    `json:"count"`
	Bytes             int64  `json:"bytes"`
	SHA256            string `json:"sha256,omitempty"`
	OK                bool   `json:"ok"`
}

// AssetsSummary summarizes measured asset counts.
type AssetsSummary struct {
	Total           int `json:"total"`
	OK              int `json:"ok"`
	MissingRequired int `json:"missing_required"`
	MissingOptional int `json:"missing_optional"`
}

// AssetsStatusResult is the full status report for offline assets.
type AssetsStatusResult struct {
	Assets          []AssetEntry  `json:"assets"`
	MissingRequired []string      `json:"missing_required"`
	MissingOptional []string      `json:"missing_optional"`
	Ready           bool          `json:"ready"`
	Summary         AssetsSummary `json:"summary"`
}

// AssetsStatus inspects the given asset specs (or DefaultAssetSpecs if empty).
func AssetsStatus(deep bool, specs []AssetSpec) AssetsStatusResult {
	if len(specs) == 0 {
		specs = DefaultAssetSpecs()
	}
	entries := make([]AssetEntry, 0, len(specs))
	missingReq := []string{}
	missingOpt := []string{}
	okCount := 0

	for _, spec := range specs {
		p := spec.ResolvedPath()
		exists, count, size := measureAsset(p, spec.Kind)
		ok := exists && count >= spec.MinCount && size >= spec.MinBytes
		entry := AssetEntry{
			Name:              spec.Name,
			Description:       spec.Description,
			Required:          spec.Required,
			InternetDependent: spec.InternetDependent,
			MinCount:          spec.MinCount,
			MinBytes:          spec.MinBytes,
			Path:              p,
			Exists:            exists,
			Kind:              spec.Kind,
			Count:             count,
			Bytes:             size,
			OK:                ok,
		}
		if deep && exists {
			if spec.Kind == "file" {
				entry.SHA256 = fileSHA256(p)
			} else {
				entry.SHA256 = treeSHA256(p)
			}
		}
		entries = append(entries, entry)
		if ok {
			okCount++
		} else if spec.Required {
			missingReq = append(missingReq, spec.Name)
		} else {
			missingOpt = append(missingOpt, spec.Name)
		}
	}

	return AssetsStatusResult{
		Assets:          entries,
		MissingRequired: missingReq,
		MissingOptional: missingOpt,
		Ready:           len(missingReq) == 0,
		Summary: AssetsSummary{
			Total:           len(entries),
			OK:              okCount,
			MissingRequired: len(missingReq),
			MissingOptional: len(missingOpt),
		},
	}
}

func measureAsset(p, kind string) (exists bool, count int, totalBytes int64) {
	fi, err := os.Lstat(p)
	if err != nil {
		return false, 0, 0
	}
	if kind == "file" {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return false, 0, 0
		}
		return true, 1, fi.Size()
	}
	if !fi.IsDir() {
		return false, 0, 0
	}
	exists = true
	_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || !info.Mode().IsRegular() {
			return nil
		}
		count++
		totalBytes += info.Size()
		return nil
	})
	return exists, count, totalBytes
}

func fileSHA256(p string) string {
	f, err := openRegularNoFollow(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func treeSHA256(root string) string {
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return ""
	}
	var rels []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr == nil {
			rels = append(rels, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(rels) == 0 {
		return ""
	}
	sort.Strings(rels)
	h := sha256.New()
	count := 0
	for _, rel := range rels {
		full := filepath.Join(root, filepath.FromSlash(rel))
		f, err := openRegularNoFollow(full)
		if err != nil {
			continue
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		_, copyErr := io.Copy(h, f)
		_ = f.Close()
		if copyErr == nil {
			count++
		}
	}
	if count == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AssetManifestRecord is one entry in the build-time asset manifest JSON.
type AssetManifestRecord struct {
	Count    int    `json:"count"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256,omitempty"`
	Required bool   `json:"required"`
}

// AssetManifest is the on-disk JSON manifest comparing build-time and runtime assets.
type AssetManifest struct {
	SchemaVersion   int                            `json:"schema_version"`
	GeneratedAt     string                         `json:"generated_at"`
	Assets          map[string]AssetManifestRecord `json:"assets"`
	MissingRequired []string                       `json:"missing_required"`
	MissingOptional []string                       `json:"missing_optional"`
	Path            string                         `json:"path,omitempty"`
}

// ManifestMismatch describes one difference between recorded and live assets.
type ManifestMismatch struct {
	Name     string `json:"name"`
	Field    string `json:"field,omitempty"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ManifestVerification reports build-time asset manifest verification results.
type ManifestVerification struct {
	Available  bool               `json:"available"`
	Valid      *bool              `json:"valid"`
	Path       string             `json:"path"`
	Note       string             `json:"note,omitempty"`
	Error      string             `json:"error,omitempty"`
	Mismatches []ManifestMismatch `json:"mismatches,omitempty"`
}

// VerifyManifest compares live asset measurements against a build-time manifest.
func VerifyManifest(manifestPath string, current *AssetsStatusResult, deep bool, specs []AssetSpec) ManifestVerification {
	if manifestPath == "" {
		manifestPath = AssetManifestPath()
	}
	fi, err := os.Lstat(manifestPath)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return ManifestVerification{
			Available: false,
			Valid:     nil,
			Path:      manifestPath,
			Note:      "no build-time asset manifest installed",
		}
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return ManifestVerification{
			Available: true,
			Valid:     boolPtr(false),
			Path:      manifestPath,
			Error:     fmt.Sprintf("invalid manifest: %v", err),
		}
	}
	var manifest AssetManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ManifestVerification{
			Available: true,
			Valid:     boolPtr(false),
			Path:      manifestPath,
			Error:     fmt.Sprintf("invalid manifest: %v", err),
		}
	}
	status := AssetsStatusResult{}
	if current != nil {
		status = *current
	} else {
		status = AssetsStatus(deep, specs)
	}
	liveByName := make(map[string]AssetEntry, len(status.Assets))
	for _, a := range status.Assets {
		liveByName[a.Name] = a
	}

	var mismatches []ManifestMismatch
	for _, name := range sortedMapKeys(manifest.Assets) {
		expected := manifest.Assets[name]
		if !expected.Required {
			continue
		}
		actual, ok := liveByName[name]
		if !ok {
			mismatches = append(mismatches, ManifestMismatch{
				Name:  name,
				Error: "asset is no longer in the catalog",
			})
			continue
		}
		if expected.Count != actual.Count {
			mismatches = append(mismatches, ManifestMismatch{
				Name: name, Field: "count", Expected: expected.Count, Actual: actual.Count,
			})
		}
		if expected.Bytes != actual.Bytes {
			mismatches = append(mismatches, ManifestMismatch{
				Name: name, Field: "bytes", Expected: expected.Bytes, Actual: actual.Bytes,
			})
		}
		if deep && ((expected.SHA256 != "" && expected.SHA256 != actual.SHA256) || (actual.Bytes > 0 && expected.SHA256 == "")) {
			mismatches = append(mismatches, ManifestMismatch{
				Name: name, Field: "sha256", Expected: expected.SHA256, Actual: actual.SHA256,
			})
		}
	}
	valid := len(mismatches) == 0
	return ManifestVerification{
		Available:  true,
		Valid:      &valid,
		Path:       manifestPath,
		Mismatches: mismatches,
	}
}

// WriteManifest writes a build-time asset manifest JSON file atomically.
func WriteManifest(manifestPath string, deep bool, specs []AssetSpec) (*AssetManifest, error) {
	if manifestPath == "" {
		manifestPath = AssetManifestPath()
	}
	status := AssetsStatus(deep, specs)
	records := make(map[string]AssetManifestRecord, len(status.Assets))
	for _, a := range status.Assets {
		records[a.Name] = AssetManifestRecord{
			Count:    a.Count,
			Bytes:    a.Bytes,
			SHA256:   a.SHA256,
			Required: a.Required,
		}
	}
	manifest := &AssetManifest{
		SchemaVersion:   1,
		GeneratedAt:     nowUTC(),
		Assets:          records,
		MissingRequired: status.MissingRequired,
		MissingOptional: status.MissingOptional,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := atomicWriteFile(manifestPath, data, 0o644); err != nil {
		return nil, err
	}
	manifest.Path = manifestPath
	return manifest, nil
}

// OfflinePosture summarizes air-gap readiness and blocked internet-only tools.
type OfflinePosture struct {
	Mode                        string   `json:"mode"`
	OfflineEnv                  string   `json:"offline_env"`
	AssetsReady                 bool     `json:"assets_ready"`
	MissingRequiredAssets       []string `json:"missing_required_assets"`
	LocalCVEDatabasePath        string   `json:"local_cve_database_path"`
	LocalCVEDatabasePresent     bool     `json:"local_cve_database_present"`
	BlockedExecutables          []string `json:"blocked_executables"`
	InternetDependentFeatures   []string `json:"internet_dependent_features"`
	Guidance                    string   `json:"guidance"`
}

// OfflineStatus evaluates the runtime air-gap posture.
func OfflineStatus(status *AssetsStatusResult, specs []AssetSpec) OfflinePosture {
	var st AssetsStatusResult
	if status != nil {
		st = *status
	} else {
		st = AssetsStatus(false, specs)
	}
	cvePath := LocalCVEDB()
	cvePresent := false
	if fi, err := os.Lstat(cvePath); err == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().IsRegular() {
		cvePresent = true
	}
	mode := "connected"
	if OfflineEnabled() {
		mode = "airgapped"
	}
	blocked := sortedMapKeys(OfflineNetworkExecutables)
	return OfflinePosture{
		Mode:                    mode,
		OfflineEnv:              OfflineEnv,
		AssetsReady:             st.Ready,
		MissingRequiredAssets:   st.MissingRequired,
		LocalCVEDatabasePath:    cvePath,
		LocalCVEDatabasePresent: cvePresent,
		BlockedExecutables:      blocked,
		InternetDependentFeatures: []string{
			"oc_cve_lookup without a local CVE database",
			"oc_hibp_password_check",
			"oc_shodan",
			"oc_censys",
			"oc_subfinder passive sources",
			"oc_theharvester online sources",
			"oc_sherlock",
		},
		Guidance: "Set OPENCYBER_OFFLINE=1 on airgapped deployments so internet-only features fail with an actionable message instead of hanging.",
	}
}

package errors

import (
	"fmt"
	"sort"
)

// CoverageStatus declares how completely a collection, stream, or run was examined.
type CoverageStatus string

const (
	CoverageComplete CoverageStatus = "complete"
	CoveragePartial  CoverageStatus = "partial"
	CoverageUnknown  CoverageStatus = "unknown"
	CoverageEmpty    CoverageStatus = "empty"
)

// Coverage declares what a tool examined and whether more data remains.
type Coverage struct {
	Status     CoverageStatus `json:"status"`
	Examined   *int           `json:"examined"`
	Total      *int           `json:"total"`
	Exhausted  *bool          `json:"exhausted"`
	NextOffset *int           `json:"next_offset"`
}

// CoverageOption customizes optional fields on a Coverage declaration.
type CoverageOption func(*Coverage)

// WithExamined records how many items or bytes were examined.
func WithExamined(n int) CoverageOption {
	return func(c *Coverage) {
		v := n
		c.Examined = &v
	}
}

// WithTotal records the total number of items or bytes when known.
func WithTotal(n int) CoverageOption {
	return func(c *Coverage) {
		v := n
		c.Total = &v
	}
}

// WithExhausted records whether the underlying source was exhausted.
func WithExhausted(v bool) CoverageOption {
	return func(c *Coverage) {
		b := v
		c.Exhausted = &b
	}
}

// WithNextOffset records the next pagination offset when more items remain.
func WithNextOffset(n int) CoverageOption {
	return func(c *Coverage) {
		v := n
		c.NextOffset = &v
	}
}

// ValidCoverageStatus reports whether status is in the closed coverage status vocabulary.
func ValidCoverageStatus(status CoverageStatus) bool {
	switch status {
	case CoverageComplete, CoveragePartial, CoverageUnknown, CoverageEmpty:
		return true
	default:
		return false
	}
}

// NewCoverage builds a validated Coverage declaration with every field present.
func NewCoverage(status CoverageStatus, opts ...CoverageOption) (Coverage, error) {
	if !ValidCoverageStatus(status) {
		return Coverage{}, fmt.Errorf("unknown coverage status: %s", status)
	}
	cov := Coverage{Status: status}
	for _, opt := range opts {
		if opt != nil {
			opt(&cov)
		}
	}
	return cov, nil
}

// MustCoverage builds a Coverage declaration, falling back to CoverageUnknown if invalid.
func MustCoverage(status CoverageStatus, opts ...CoverageOption) Coverage {
	cov, err := NewCoverage(status, opts...)
	if err != nil {
		cov = Coverage{Status: CoverageUnknown}
		for _, opt := range opts {
			if opt != nil {
				opt(&cov)
			}
		}
	}
	return cov
}

// NormalizeCoverage fills defaults on a raw Coverage pointer based on truncation state.
func NormalizeCoverage(raw *Coverage, truncated bool) Coverage {
	defaultStatus := CoverageComplete
	if truncated {
		defaultStatus = CoveragePartial
	}
	if raw == nil {
		return Coverage{Status: defaultStatus}
	}
	status := raw.Status
	if status == "" {
		status = defaultStatus
	}
	if !ValidCoverageStatus(status) {
		status = defaultStatus
	}
	out := Coverage{Status: status}
	if raw.Examined != nil {
		v := *raw.Examined
		out.Examined = &v
	}
	if raw.Total != nil {
		v := *raw.Total
		out.Total = &v
	}
	if raw.Exhausted != nil {
		v := *raw.Exhausted
		out.Exhausted = &v
	}
	if raw.NextOffset != nil {
		v := *raw.NextOffset
		out.NextOffset = &v
	}
	return out
}

// ToMap serializes Coverage into a JSON map with all five fields explicitly present.
func (c Coverage) ToMap() map[string]any {
	var examined, total, exhausted, nextOffset any
	if c.Examined != nil {
		examined = *c.Examined
	}
	if c.Total != nil {
		total = *c.Total
	}
	if c.Exhausted != nil {
		exhausted = *c.Exhausted
	}
	if c.NextOffset != nil {
		nextOffset = *c.NextOffset
	}
	return map[string]any{
		"status":      string(c.Status),
		"examined":    examined,
		"total":       total,
		"exhausted":   exhausted,
		"next_offset": nextOffset,
	}
}

// ReferenceFunctions is the canonical security-assessment functional inventory
// tracked by coverage accounting (migrated from coverage.py).
var ReferenceFunctions = []string{
	"aircrack-ng", "aireplay-ng", "airmon-ng", "airodump-ng", "amass", "anew", "angr",
	"api-schema-analyzer", "arjun", "arp-scan", "autorecon", "autopsy", "binwalk",
	"bulk-extractor", "burpsuite", "censys-cli", "checkov", "checksec", "clair", "curl",
	"dalfox", "dirb", "dirsearch", "dnsenum", "docker-bench-security", "dotdotpwn",
	"enum4linux", "enum4linux-ng", "evil-winrm", "exiftool", "falco", "feroxbuster",
	"ffuf", "fierce", "file", "foremost", "gau", "gdb", "ghidra", "gobuster",
	"graphql-scanner", "hakrawler", "hash-identifier", "hashcat", "hashcat-utils",
	"hashpump", "have-i-been-pwned", "httpie", "httpx", "hydra", "insomnia", "jaeles",
	"john", "jwt-analyzer", "katana", "kismet", "kube-bench", "kube-hunter",
	"libc-database", "maltego", "masscan", "medusa", "nbtscan", "nikto", "nmap", "nuclei",
	"nxc", "objdump", "one-gadget", "ophcrack", "outguess", "paramspider", "patator",
	"photorec", "postman", "prowler", "pwninit", "pwntools", "qsreplace", "radare2",
	"recon-ng", "responder", "ropgadget", "ropper", "rpcclient", "rustscan", "scalpel",
	"scout-suite", "sherlock", "shodan-cli", "sleuthkit", "smbmap", "social-analyzer",
	"spiderfoot", "sqlmap", "steghide", "stegsolve", "strings", "subfinder", "tcpdump",
	"terrascan", "testdisk", "theharvester", "trivy", "tshark", "uro", "vol", "volatility",
	"volatility3", "wafw00f", "waybackurls", "wfuzz", "wireshark", "wpscan", "x8", "xsser",
	"xxd", "zaproxy", "zsteg",
}

// ReferenceAliases maps reference tool names whose MCP tool name does not match
// their executable verbatim (migrated from coverage.py).
var ReferenceAliases = map[string]string{
	"angr":                "oc_angr_analyze",
	"api-schema-analyzer": "oc_openapi_inspect",
	"autopsy":             "oc_sleuthkit_fls",
	"bulk-extractor":      "oc_bulk_extractor",
	"burpsuite":           "oc_zap",
	"censys-cli":          "oc_censys",
	"clair":               "oc_trivy",
	"exploit-db":          "oc_exploit_search",
	"falco":               "oc_process_snapshot",
	"graphql-scanner":     "oc_graphql_request",
	"hashcat-utils":       "oc_hashcat",
	"have-i-been-pwned":   "oc_hibp_password_check",
	"httpie":              "oc_httpie",
	"insomnia":            "oc_http_request",
	"jwt-analyzer":        "oc_jwt_decode",
	"libc-database":       "oc_pwninit",
	"maltego":             "oc_spiderfoot",
	"one-gadget":          "oc_one_gadget",
	"outguess":            "oc_steghide",
	"photorec":            "oc_testdisk",
	"postman":             "oc_http_request",
	"pwntools":            "oc_pwntools",
	"ropgadget":           "oc_ropgadget",
	"scout-suite":         "oc_scout_suite",
	"searchsploit":        "oc_exploit_search",
	"shodan-cli":          "oc_shodan",
	"sleuthkit":           "oc_sleuthkit_fls",
	"social-analyzer":     "oc_sherlock",
	"stegsolve":           "oc_zsteg",
	"theharvester":        "oc_theharvester",
	"volatility":          "oc_volatility",
	"volatility3":         "oc_volatility",
	"waybackurls":         "oc_urlfinder",
	"wireshark":           "oc_packet_analysis",
	"wpscan":              "oc_whatweb",
}

// ReferenceCoverage maps each covered reference function name to its OpenCyber MCP tool name.
// byExecutable maps executable binary names (e.g. "nmap") to MCP tool names (e.g. "oc_nmap").
func ReferenceCoverage(byExecutable map[string]string) map[string]string {
	covered := make(map[string]string, len(ReferenceFunctions))
	for _, ref := range ReferenceFunctions {
		if alias, ok := ReferenceAliases[ref]; ok {
			covered[ref] = alias
		} else if toolName, ok := byExecutable[ref]; ok {
			covered[ref] = toolName
		}
	}
	return covered
}

// UncoveredReferenceFunctions returns sorted reference function names not covered
// by either ReferenceAliases or byExecutable.
func UncoveredReferenceFunctions(byExecutable map[string]string) []string {
	covered := ReferenceCoverage(byExecutable)
	uncovered := make([]string, 0)
	for _, ref := range ReferenceFunctions {
		if _, ok := covered[ref]; !ok {
			uncovered = append(uncovered, ref)
		}
	}
	sort.Strings(uncovered)
	return uncovered
}

// ReferenceCoverageReport summarizes functional inventory coverage.
type ReferenceCoverageReport struct {
	Covered      map[string]string `json:"covered"`
	Uncovered    []string          `json:"uncovered"`
	Total        int               `json:"total"`
	CoveredCount int               `json:"covered_count"`
	Percent      float64           `json:"percent"`
}

// ComputeReferenceCoverage calculates complete inventory coverage metrics.
func ComputeReferenceCoverage(byExecutable map[string]string) ReferenceCoverageReport {
	covered := ReferenceCoverage(byExecutable)
	uncovered := UncoveredReferenceFunctions(byExecutable)
	total := len(ReferenceFunctions)
	pct := 0.0
	if total > 0 {
		pct = float64(len(covered)) * 100.0 / float64(total)
	}
	return ReferenceCoverageReport{
		Covered:      covered,
		Uncovered:    uncovered,
		Total:        total,
		CoveredCount: len(covered),
		Percent:      pct,
	}
}

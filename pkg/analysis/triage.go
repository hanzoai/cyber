package analysis

import (
	"sort"
	"strings"
)

// TriageFinding represents one normalized finding input for deduplication and prioritization.
type TriageFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Category string `json:"category,omitempty"`
	Verified bool   `json:"verified"`
}

// TriageSummary summarizes deduplicated findings sorted by operational priority.
type TriageSummary struct {
	Total       int             `json:"total"`
	Unique      int             `json:"unique"`
	Verified    int             `json:"verified"`
	BySeverity  map[string]int  `json:"by_severity"`
	Prioritized []TriageFinding `json:"prioritized"`
}

var severityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

// TriageFindings deduplicates findings by (target, severity, normalized title) and orders
// verified higher-severity items first.
func TriageFindings(items []TriageFinding) TriageSummary {
	bySev := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	seen := make(map[string]int, len(items))
	unique := make([]TriageFinding, 0, len(items))

	for _, item := range items {
		sev := strings.ToLower(strings.TrimSpace(item.Severity))
		if _, ok := severityRank[sev]; !ok {
			sev = "info"
		}
		item.Severity = sev
		key := strings.ToLower(strings.TrimSpace(item.Target)) + "|" + sev + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		if idx, exists := seen[key]; exists {
			if item.Verified && !unique[idx].Verified {
				unique[idx].Verified = true
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, item)
	}

	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Verified != unique[j].Verified {
			return unique[i].Verified
		}
		ri, rj := severityRank[unique[i].Severity], severityRank[unique[j].Severity]
		if ri != rj {
			return ri > rj
		}
		return unique[i].Title < unique[j].Title
	})

	verified := 0
	for _, u := range unique {
		bySev[u.Severity]++
		if u.Verified {
			verified++
		}
	}

	return TriageSummary{
		Total:       len(items),
		Unique:      len(unique),
		Verified:    verified,
		BySeverity:  bySev,
		Prioritized: unique,
	}
}

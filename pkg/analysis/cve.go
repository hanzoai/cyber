package analysis

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// CVERecord represents one normalized offline vulnerability record.
type CVERecord struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	Products    []string `json:"products,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// CVEIndex provides offline deterministic CVE lookup and query filtering.
type CVEIndex struct {
	byID    map[string]CVERecord
	records []CVERecord
}

// NewCVEIndex builds an in-memory offline CVEIndex from records.
func NewCVEIndex(records []CVERecord) *CVEIndex {
	idx := &CVEIndex{
		byID:    make(map[string]CVERecord, len(records)),
		records: make([]CVERecord, 0, len(records)),
	}
	for _, rec := range records {
		id := strings.ToUpper(strings.TrimSpace(rec.ID))
		if id == "" {
			continue
		}
		rec.ID = id
		rec.Severity = strings.ToLower(strings.TrimSpace(rec.Severity))
		if _, dup := idx.byID[id]; !dup {
			idx.records = append(idx.records, rec)
		}
		idx.byID[id] = rec
	}
	sort.Slice(idx.records, func(i, j int) bool {
		if idx.records[i].CVSS != idx.records[j].CVSS {
			return idx.records[i].CVSS > idx.records[j].CVSS
		}
		return idx.records[i].ID < idx.records[j].ID
	})
	return idx
}

// LoadCVEIndexJSONL loads newline-delimited CVE records from a local offline file.
func LoadCVEIndexJSONL(path string) (*CVEIndex, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []CVERecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec CVERecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.ID != "" {
			recs = append(recs, rec)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return NewCVEIndex(recs), nil
}

// Get returns a single CVE record by case-insensitive ID.
func (idx *CVEIndex) Get(id string) (CVERecord, bool) {
	if idx == nil {
		return CVERecord{}, false
	}
	rec, ok := idx.byID[strings.ToUpper(strings.TrimSpace(id))]
	return rec, ok
}

// Search filters offline CVE records by query substring, product token, and minimum CVSS score.
func (idx *CVEIndex) Search(query, product string, minCVSS float64, limit int) []CVERecord {
	if idx == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	prod := strings.ToLower(strings.TrimSpace(product))
	if limit <= 0 {
		limit = 50
	}
	var out []CVERecord
	for _, rec := range idx.records {
		if rec.CVSS < minCVSS {
			continue
		}
		if prod != "" {
			matched := false
			for _, p := range rec.Products {
				if strings.Contains(strings.ToLower(p), prod) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if q != "" {
			hay := strings.ToLower(rec.ID + " " + rec.Summary + " " + rec.CWE + " " + strings.Join(rec.Products, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, rec)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Count returns total indexed offline CVE records.
func (idx *CVEIndex) Count() int {
	if idx == nil {
		return 0
	}
	return len(idx.records)
}

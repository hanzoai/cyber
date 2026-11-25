package policy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const (
	// AuditSchemaVersion is the wire schema version of audit JSONL records.
	AuditSchemaVersion = 1

	// MaxReadEvents caps matching events examined by ReadAudit.
	MaxReadEvents = 5000

	// MaxAuditRecordBytes caps the byte length of one JSONL audit record (1 MiB).
	MaxAuditRecordBytes = 1024 * 1024
)

// GenesisHash is the 64-zero prev_hash of the first record in every audit chain.
var GenesisHash = strings.Repeat("0", 64)

// AuditReadResult is the paged output of AuditLog.ReadAudit.
type AuditReadResult struct {
	EngagementID string               `json:"engagement_id"`
	Total        int                  `json:"total"`
	TotalExact   bool                 `json:"total_exact"`
	Offset       int                  `json:"offset"`
	Limit        int                  `json:"limit"`
	Events       []map[string]any     `json:"events"`
	Coverage     ocerrors.Coverage    `json:"coverage"`
	LimitFacts   *ocerrors.LimitFacts `json:"limit_facts,omitempty"`
	Limitations  []string             `json:"limitations,omitempty"`
}

// AuditVerifyResult reports hash-chain verification results for an audit stream.
type AuditVerifyResult struct {
	EngagementID    string `json:"engagement_id"`
	Valid           bool   `json:"valid"`
	Events          int    `json:"events"`
	FirstInvalidSeq *int   `json:"first_invalid_seq"`
	Error           string `json:"error,omitempty"`
	LastHash        string `json:"last_hash,omitempty"`
	Note            string `json:"note,omitempty"`
}

// AuditSummary summarizes event counts by event type for an engagement.
type AuditSummary struct {
	EngagementID string         `json:"engagement_id"`
	Events       map[string]int `json:"events"`
	Total        int            `json:"total"`
	Path         string         `json:"path"`
}

// AuditLog manages hash-chained, credential-redacted JSONL audit logs per engagement.
type AuditLog struct {
	Store *EngagementStore
	mu    sync.Mutex
}

// NewAuditLog creates an AuditLog backed by store.
func NewAuditLog(store *EngagementStore) *AuditLog {
	if store == nil {
		store = NewEngagementStore("")
	}
	return &AuditLog{Store: store}
}

// Redact recursively masks values that look like credentials, passwords, cookies,
// API keys, or bearer tokens.
func Redact(value any) any {
	return ocerrors.RedactValue(value)
}

// RecordEvent appends one credential-redacted, SHA-256 hash-chained record to
// <engagement>/.opencyber/audit/events.jsonl and returns the stored record.
func (a *AuditLog) RecordEvent(ctx context.Context, engagementID string, event map[string]any) (map[string]any, error) {
	if event == nil {
		return nil, ocerrors.New(ocerrors.CodeInvalidArgument, "audit event must be a map")
	}
	eventName, ok := event["event"].(string)
	if !ok || strings.TrimSpace(eventName) == "" {
		return nil, ocerrors.New(ocerrors.CodeInvalidArgument, "audit event requires a string 'event' field")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := openAuditEventsFile(a.Store, engagementID, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := flockAcquire(ctx, f.Fd(), true); err != nil {
		return nil, err
	}
	defer flockRelease(f.Fd())

	previous, err := readLastAuditRecord(f)
	if err != nil {
		return nil, ocerrors.New(ocerrors.CodeIntegrityMismatch, err.Error(), ocerrors.WithCause(err))
	}

	seq := int64(1)
	prevHash := GenesisHash
	if previous != nil {
		prevSeq, ok := extractStrictInt64(previous["seq"])
		if !ok || prevSeq < 1 {
			return nil, ocerrors.New(ocerrors.CodeIntegrityMismatch, "existing audit final record has invalid seq")
		}
		h, ok := previous["hash"].(string)
		if !ok || h == "" {
			return nil, ocerrors.New(ocerrors.CodeIntegrityMismatch, "existing audit final record has missing hash")
		}
		seq = prevSeq + 1
		prevHash = h
	}

	redacted := ocerrors.RedactMap(event)
	payload := make(map[string]any, len(redacted)+6)
	for k, v := range redacted {
		payload[k] = v
	}
	payload["schema_version"] = AuditSchemaVersion
	payload["seq"] = seq
	payload["ts"] = isoUTC(time.Now().UTC())
	payload["engagement_id"] = engagementID
	payload["prev_hash"] = prevHash
	delete(payload, "hash")

	digest, err := ocerrors.CanonicalSHA256(payload)
	if err != nil {
		return nil, fmt.Errorf("hash audit record: %w", err)
	}
	payload["hash"] = digest

	encoded, err := ocerrors.CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("encode audit record: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxAuditRecordBytes {
		return nil, ocerrors.New(
			ocerrors.CodeLimitExceeded,
			"audit record exceeds the 1 MiB verification limit",
			ocerrors.WithDetail("bytes", len(encoded)),
		)
	}

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	if _, err := f.Write(encoded); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return payload, nil
}

// SafeRecord performs a best-effort audit write, returning nil on failure.
func (a *AuditLog) SafeRecord(engagementID string, event map[string]any) map[string]any {
	rec, err := a.RecordEvent(context.Background(), engagementID, event)
	if err != nil {
		return nil
	}
	return rec
}

// ReadAudit reads a bounded, optionally filtered page of events from the engagement audit trail.
func (a *AuditLog) ReadAudit(engagementID string, limit, offset int, eventFilter string) (AuditReadResult, error) {
	if limit < 1 || limit > 1000 {
		return AuditReadResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "limit must be between 1 and 1000", ocerrors.WithDetail("parameter", "limit"))
	}
	if offset < 0 {
		return AuditReadResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "offset must not be negative", ocerrors.WithDetail("parameter", "offset"))
	}

	selected := make([]map[string]any, 0)
	matched := 0
	totalExact := true

	f, err := openAuditEventsFile(a.Store, engagementID, false)
	if err != nil {
		if !stderrors.Is(err, os.ErrNotExist) {
			return AuditReadResult{}, err
		}
	} else {
		defer f.Close()
		reader := bufio.NewReaderSize(f, 64*1024)
		for {
			line, rerr := readBoundedLine(reader, MaxAuditRecordBytes)
			if rerr != nil {
				if stderrors.Is(rerr, io.EOF) && len(line) == 0 {
					break
				}
				if !stderrors.Is(rerr, io.EOF) {
					return AuditReadResult{}, ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("invalid audit stream: %v", rerr), ocerrors.WithCause(rerr))
				}
			}
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				rec, perr := decodeJSONObject(trimmed)
				if perr != nil {
					return AuditReadResult{}, ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("corrupt audit record: %v", perr), ocerrors.WithCause(perr))
				}
				if eventFilter == "" || fmt.Sprint(rec["event"]) == eventFilter {
					matched++
					if matched > MaxReadEvents {
						matched = MaxReadEvents
						totalExact = false
						break
					}
					if matched-1 >= offset && matched-1 < offset+limit {
						selected = append(selected, rec)
					}
				}
			}
			if stderrors.Is(rerr, io.EOF) {
				break
			}
		}
	}

	exhausted := offset+len(selected) >= matched
	status := ocerrors.CoveragePartial
	if totalExact && exhausted {
		status = ocerrors.CoverageComplete
	}
	opts := []ocerrors.CoverageOption{
		ocerrors.WithExamined(matched),
		ocerrors.WithExhausted(exhausted),
	}
	if totalExact {
		opts = append(opts, ocerrors.WithTotal(matched))
	}
	if !exhausted {
		opts = append(opts, ocerrors.WithNextOffset(offset+len(selected)))
	}

	res := AuditReadResult{
		EngagementID: engagementID,
		Total:        matched,
		TotalExact:   totalExact,
		Offset:       offset,
		Limit:        limit,
		Events:       selected,
		Coverage:     ocerrors.MustCoverage(status, opts...),
	}
	if !totalExact {
		eff := float64(MaxReadEvents)
		if facts, ferr := ocerrors.FactsFor("audit.max_events", &eff, nil, ""); ferr == nil {
			res.LimitFacts = facts
		}
		res.Limitations = []string{
			fmt.Sprintf("Examined the first %d matching events; more records remain on disk. Export the audit trail for an unfiltered read.", MaxReadEvents),
		}
	} else if !exhausted {
		res.Limitations = []string{
			fmt.Sprintf("Returned events %d to %d of %d; continue with the next_offset value.", offset, offset+len(selected), matched),
		}
	}
	return res, nil
}

// VerifyAudit recomputes the engagement's hash chain from disk and reports the first inconsistency.
func (a *AuditLog) VerifyAudit(engagementID string) AuditVerifyResult {
	f, err := openAuditEventsFile(a.Store, engagementID, false)
	if err != nil {
		if stderrors.Is(err, os.ErrNotExist) {
			return AuditVerifyResult{
				EngagementID: engagementID,
				Valid:        true,
				Events:       0,
				LastHash:     GenesisHash,
				Note:         "audit trail is empty",
			}
		}
		seq := 1
		return AuditVerifyResult{
			EngagementID:    engagementID,
			Valid:           false,
			Events:          0,
			FirstInvalidSeq: &seq,
			Error:           fmt.Sprintf("unsafe or unreadable audit file: %v", err),
		}
	}
	defer f.Close()
	return VerifyChain(f, engagementID)
}

// Summary aggregates event counts per event type for an engagement.
func (a *AuditLog) Summary(engagementID string) (AuditSummary, error) {
	eng, err := a.Store.Get(engagementID)
	if err != nil {
		return AuditSummary{}, err
	}
	counts := make(map[string]int)
	total := 0
	f, err := openAuditEventsFile(a.Store, engagementID, false)
	if err != nil {
		if !stderrors.Is(err, os.ErrNotExist) {
			return AuditSummary{}, err
		}
	} else {
		defer f.Close()
		reader := bufio.NewReaderSize(f, 64*1024)
		for {
			line, rerr := readBoundedLine(reader, MaxAuditRecordBytes)
			if rerr != nil && !stderrors.Is(rerr, io.EOF) {
				return AuditSummary{}, rerr
			}
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				rec, perr := decodeJSONObject(trimmed)
				if perr != nil {
					return AuditSummary{}, perr
				}
				name := "unknown"
				if s, ok := rec["event"].(string); ok && s != "" {
					name = s
				}
				counts[name]++
				total++
			}
			if stderrors.Is(rerr, io.EOF) {
				break
			}
		}
	}
	return AuditSummary{
		EngagementID: engagementID,
		Events:       counts,
		Total:        total,
		Path:         filepath.Join(eng.Workspace, ".opencyber", "audit", "events.jsonl"),
	}, nil
}

// Snapshot copies and verifies an engagement's audit trail into dst while holding a shared lock.
func (a *AuditLog) Snapshot(ctx context.Context, engagementID string, dst io.Writer) (AuditVerifyResult, error) {
	f, err := openAuditEventsFile(a.Store, engagementID, false)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	defer f.Close()

	if err := flockAcquire(ctx, f.Fd(), false); err != nil {
		return AuditVerifyResult{}, err
	}
	defer flockRelease(f.Fd())

	before, err := f.Stat()
	if err != nil {
		return AuditVerifyResult{}, err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, f); err != nil {
		return AuditVerifyResult{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return AuditVerifyResult{}, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return AuditVerifyResult{}, ocerrors.New(ocerrors.CodeConflict, "audit changed while its snapshot was copied")
	}

	report, err := VerifyChainContext(ctx, bytes.NewReader(buf.Bytes()), engagementID)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	if !report.Valid {
		return report, ocerrors.New(ocerrors.CodeIntegrityMismatch, fmt.Sprintf("invalid audit snapshot: %s", report.Error))
	}
	if dst != nil {
		if _, err := dst.Write(buf.Bytes()); err != nil {
			return report, err
		}
	}
	return report, nil
}

// VerifyChain performs offline, bounded-memory SHA-256 hash-chain verification
// over any JSONL audit stream. If engagementID is non-empty, every record's
// engagement_id is also verified against it.
func VerifyChain(r io.Reader, engagementID string) AuditVerifyResult {
	res, _ := VerifyChainContext(context.Background(), r, engagementID)
	return res
}

// VerifyChainContext verifies an audit stream while honoring ctx cancellation.
func VerifyChainContext(ctx context.Context, r io.Reader, engagementID string) (AuditVerifyResult, error) {
	prevHash := GenesisHash
	count := 0
	lineNum := 0
	reader := bufio.NewReaderSize(r, 64*1024)

	for {
		if ctx != nil && ctx.Err() != nil {
			return AuditVerifyResult{}, ctx.Err()
		}
		line, rerr := readBoundedLine(reader, MaxAuditRecordBytes)
		if rerr != nil {
			if stderrors.Is(rerr, io.EOF) && len(line) == 0 {
				break
			}
			if stderrors.Is(rerr, errAuditLineTooLong) {
				lineNum++
				badSeq := count + 1
				return AuditVerifyResult{
					EngagementID:    engagementID,
					Valid:           false,
					Events:          count,
					FirstInvalidSeq: &badSeq,
					Error:           fmt.Sprintf("line %d: audit record exceeds the 1 MiB verification limit", lineNum),
				}, nil
			}
			if !stderrors.Is(rerr, io.EOF) {
				lineNum++
				badSeq := count + 1
				return AuditVerifyResult{
					EngagementID:    engagementID,
					Valid:           false,
					Events:          count,
					FirstInvalidSeq: &badSeq,
					Error:           fmt.Sprintf("line %d: read error: %v", lineNum, rerr),
				}, nil
			}
		}

		lineNum++
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if stderrors.Is(rerr, io.EOF) {
				break
			}
			continue
		}

		errMsg := ""
		rec, perr := decodeJSONObject(trimmed)
		if perr != nil {
			errMsg = fmt.Sprintf("invalid JSON: %v", perr)
		} else {
			seq, seqOK := extractStrictInt64(rec["seq"])
			sv, svOK := extractStrictInt64(rec["schema_version"])
			recEng, _ := rec["engagement_id"].(string)
			recPrev, _ := rec["prev_hash"].(string)
			recHash, _ := rec["hash"].(string)

			switch {
			case !seqOK || seq != int64(count+1):
				errMsg = fmt.Sprintf("expected seq %d", count+1)
			case !svOK || sv != AuditSchemaVersion:
				errMsg = "unsupported audit schema_version"
			case engagementID != "" && recEng != engagementID:
				errMsg = "audit engagement_id does not match"
			case recPrev != prevHash:
				errMsg = "prev_hash does not match the previous record"
			default:
				material := make(map[string]any, len(rec))
				for k, v := range rec {
					if k != "hash" {
						material[k] = v
					}
				}
				computed, herr := ocerrors.CanonicalSHA256(material)
				if herr != nil || computed != recHash {
					errMsg = "record hash does not match its contents"
				} else {
					prevHash = recHash
				}
			}
		}

		if errMsg != "" {
			badSeq := count + 1
			return AuditVerifyResult{
				EngagementID:    engagementID,
				Valid:           false,
				Events:          count,
				FirstInvalidSeq: &badSeq,
				Error:           fmt.Sprintf("line %d: %s", lineNum, errMsg),
			}, nil
		}

		count++
		if stderrors.Is(rerr, io.EOF) {
			break
		}
	}

	return AuditVerifyResult{
		EngagementID: engagementID,
		Valid:        true,
		Events:       count,
		LastHash:     prevHash,
	}, nil
}

var errAuditLineTooLong = stderrors.New("audit record exceeds the 1 MiB verification limit")

func readBoundedLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > maxBytes {
			return out, errAuditLineTooLong
		}
		if err == nil || !stderrors.Is(err, bufio.ErrBufferFull) {
			return out, err
		}
	}
}

func readLastAuditRecord(f *os.File) (map[string]any, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	window := int64(MaxAuditRecordBytes + 1)
	if size < window {
		window = size
	}
	if _, err := f.Seek(size-window, io.SeekStart); err != nil {
		return nil, err
	}
	tail, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	rawLines := bytes.Split(tail, []byte("\n"))
	var lastLine []byte
	for i := len(rawLines) - 1; i >= 0; i-- {
		if trimmed := bytes.TrimSpace(rawLines[i]); len(trimmed) > 0 {
			lastLine = trimmed
			break
		}
	}
	if len(lastLine) == 0 {
		return nil, fmt.Errorf("existing audit has no readable final record")
	}
	if len(lastLine)+1 > MaxAuditRecordBytes {
		return nil, fmt.Errorf("existing audit record exceeds the 1 MiB limit")
	}
	rec, err := decodeJSONObject(lastLine)
	if err != nil {
		return nil, fmt.Errorf("existing audit has an invalid final record: %w", err)
	}
	return rec, nil
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, err
	}
	obj, ok := val.(map[string]any)
	if !ok || obj == nil {
		return nil, fmt.Errorf("record is not an object")
	}
	return obj, nil
}

func extractStrictInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}

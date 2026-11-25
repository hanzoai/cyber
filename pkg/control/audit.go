// Copyright © 2026 Hanzo AI. MIT License.

package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
	"github.com/hanzoai/cyber/pkg/policy"
)

// AuditEvent is one credential-redacted, SHA-256 hash-chained control-plane audit record.
type AuditEvent struct {
	// ID uniquely identifies the audit record.
	ID string `json:"id"`
	// Org is the tenant organization that owns the event.
	Org string `json:"org"`
	// EngagementID scopes the hash chain to one engagement (empty for org-level events).
	EngagementID string `json:"engagementId"`
	// Seq is the strictly monotonic 1-based sequence number in the hash chain.
	Seq int64 `json:"seq"`
	// Event names the audited control-plane operation.
	Event string `json:"event"`
	// Actor identifies the IAM user or operator who triggered the event.
	Actor string `json:"actor"`
	// Payload holds redacted structured metadata for the event.
	Payload map[string]any `json:"payload"`
	// PrevHash is the SHA-256 digest of the previous event (or 64 zeros at genesis).
	PrevHash string `json:"prevHash"`
	// Hash is the canonical SHA-256 digest covering this record and PrevHash.
	Hash string `json:"hash"`
	// CreatedAt is the creation timestamp in Unix milliseconds.
	CreatedAt int64 `json:"createdAt"`
}

// AuditVerifyReport reports cryptographic verification of an org/engagement audit chain.
type AuditVerifyReport struct {
	// Org is the verified tenant organization.
	Org string `json:"org"`
	// EngagementID is the verified engagement scope (empty for org-level chain).
	EngagementID string `json:"engagementId,omitempty"`
	// Valid is true when every record's sequence, prevHash, and SHA-256 digest match.
	Valid bool `json:"valid"`
	// Events is the number of verified events examined.
	Events int `json:"events"`
	// FirstInvalidSeq is the 1-based sequence number of the first invalid record when Valid is false.
	FirstInvalidSeq int64 `json:"firstInvalidSeq,omitempty"`
	// LastHash is the final verified SHA-256 digest (or 64-zero genesis hash if empty).
	LastHash string `json:"lastHash"`
	// Error describes the detected tamper or corruption when Valid is false.
	Error string `json:"error,omitempty"`
}

func auditCanonicalHash(org, engagementID string, seq int64, event, actor, payloadJSON, prevHash string, createdAt int64) (string, error) {
	material := map[string]any{
		"schema_version": policy.AuditSchemaVersion,
		"org":            org,
		"engagement_id":  engagementID,
		"seq":            seq,
		"event":          event,
		"actor":          actor,
		"payload_json":   payloadJSON,
		"prev_hash":      prevHash,
		"created_at":     createdAt,
	}
	return ocerrors.CanonicalSHA256(material)
}

// AppendAuditEvent atomically appends a redacted, SHA-256 hash-chained audit record.
func (s *Store) AppendAuditEvent(ctx context.Context, org, engagementID, event, actor string, payload map[string]any) (AuditEvent, error) {
	if err := checkText(org, engagementID, event, actor); err != nil {
		return AuditEvent{}, err
	}
	redacted := ocerrors.RedactMap(payload)
	if redacted == nil {
		redacted = map[string]any{}
	}
	rawPayload, err := ocerrors.CanonicalJSON(redacted)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("encode audit payload: %w", err)
	}
	payloadJSON := string(rawPayload)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var prevSeq int64
	var prevHash string
	row := tx.QueryRowContext(ctx,
		`SELECT seq, hash FROM cyber_audit_events WHERE org=$1 AND engagement_id=$2 ORDER BY seq DESC LIMIT 1`,
		org, engagementID)
	if err := row.Scan(&prevSeq, &prevHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			prevSeq = 0
			prevHash = policy.GenesisHash
		} else {
			return AuditEvent{}, err
		}
	}

	seq := prevSeq + 1
	createdAt := nowMS()
	digest, err := auditCanonicalHash(org, engagementID, seq, event, actor, payloadJSON, prevHash, createdAt)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("hash audit event: %w", err)
	}

	rec := AuditEvent{
		ID:           genID("aud"),
		Org:          org,
		EngagementID: engagementID,
		Seq:          seq,
		Event:        event,
		Actor:        actor,
		Payload:      redacted,
		PrevHash:     prevHash,
		Hash:         digest,
		CreatedAt:    createdAt,
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO cyber_audit_events (id,org,engagement_id,seq,event,actor,payload_json,prev_hash,hash,created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		rec.ID, rec.Org, rec.EngagementID, rec.Seq, rec.Event, rec.Actor, payloadJSON, rec.PrevHash, rec.Hash, rec.CreatedAt,
	); err != nil {
		return AuditEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditEvent{}, err
	}
	return rec, nil
}

// ListAuditEvents returns org-scoped audit events ordered chronologically by seq.
func (s *Store) ListAuditEvents(ctx context.Context, org, engagementID string, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var (
		rows *sql.Rows
		err  error
	)
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,seq,event,actor,payload_json,prev_hash,hash,created_at
			 FROM cyber_audit_events WHERE org=$1 AND engagement_id=$2 ORDER BY seq ASC LIMIT $3`,
			org, engagementID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id,org,engagement_id,seq,event,actor,payload_json,prev_hash,hash,created_at
			 FROM cyber_audit_events WHERE org=$1 ORDER BY created_at ASC, seq ASC LIMIT $2`,
			org, limit)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var a AuditEvent
		var rawPayload string
		if err := rows.Scan(&a.ID, &a.Org, &a.EngagementID, &a.Seq, &a.Event, &a.Actor, &rawPayload, &a.PrevHash, &a.Hash, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Payload = map[string]any{}
		_ = json.Unmarshal([]byte(rawPayload), &a.Payload)
		out = append(out, a)
	}
	return out, rows.Err()
}

// VerifyAuditChain recomputes the full SHA-256 hash chain for an org/engagement
// and reports the first sequence number where tampering or corruption occurred.
func (s *Store) VerifyAuditChain(ctx context.Context, org, engagementID string) (AuditVerifyReport, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq,event,actor,payload_json,prev_hash,hash,created_at
		 FROM cyber_audit_events WHERE org=$1 AND engagement_id=$2 ORDER BY seq ASC`,
		org, engagementID)
	if err != nil {
		return AuditVerifyReport{}, err
	}
	defer func() { _ = rows.Close() }()

	prevHash := policy.GenesisHash
	var count int
	for rows.Next() {
		var (
			seq                       int64
			event, actor, payloadJSON string
			recPrev, recHash          string
			createdAt                 int64
		)
		if err := rows.Scan(&seq, &event, &actor, &payloadJSON, &recPrev, &recHash, &createdAt); err != nil {
			return AuditVerifyReport{}, err
		}
		expectedSeq := int64(count + 1)
		if seq != expectedSeq {
			return AuditVerifyReport{
				Org: org, EngagementID: engagementID, Valid: false, Events: count,
				FirstInvalidSeq: expectedSeq, LastHash: prevHash,
				Error: fmt.Sprintf("expected seq %d, found %d", expectedSeq, seq),
			}, nil
		}
		if recPrev != prevHash {
			return AuditVerifyReport{
				Org: org, EngagementID: engagementID, Valid: false, Events: count,
				FirstInvalidSeq: seq, LastHash: prevHash,
				Error: fmt.Sprintf("seq %d prev_hash mismatch", seq),
			}, nil
		}
		computed, err := auditCanonicalHash(org, engagementID, seq, event, actor, payloadJSON, recPrev, createdAt)
		if err != nil || computed != recHash {
			return AuditVerifyReport{
				Org: org, EngagementID: engagementID, Valid: false, Events: count,
				FirstInvalidSeq: seq, LastHash: prevHash,
				Error: fmt.Sprintf("seq %d SHA-256 content digest mismatch (tampering detected)", seq),
			}, nil
		}
		prevHash = recHash
		count++
	}
	if err := rows.Err(); err != nil {
		return AuditVerifyReport{}, err
	}
	return AuditVerifyReport{
		Org:          org,
		EngagementID: engagementID,
		Valid:        true,
		Events:       count,
		LastHash:     prevHash,
	}, nil
}

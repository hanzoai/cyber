package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const (
	// DefaultWorkspaceReadMaxBytes is the default per-call read ceiling (1 MiB).
	DefaultWorkspaceReadMaxBytes = 1048576

	// MaxWorkspaceReadBytes is the hard ceiling from workspace.read_max_bytes (64 MiB).
	MaxWorkspaceReadBytes = 67108864
)

// WorkspaceEntry describes one file or directory inside an engagement workspace.
type WorkspaceEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// WorkspaceListResult is the paged directory listing returned by Workspace.List.
type WorkspaceListResult struct {
	EngagementID string                 `json:"engagement_id"`
	Workspace    string                 `json:"workspace"`
	Entries      []WorkspaceEntry       `json:"entries"`
	TotalEntries int                    `json:"total_entries"`
	Coverage     ocerrors.Coverage      `json:"coverage"`
	Limitations  []string               `json:"limitations,omitempty"`
	Continuation *ocerrors.Continuation `json:"continuation,omitempty"`
}

// WorkspaceReadResult is the bounded file read returned by Workspace.ReadFile.
type WorkspaceReadResult struct {
	EngagementID string                 `json:"engagement_id"`
	Path         string                 `json:"path"`
	Content      string                 `json:"content"`
	Offset       int64                  `json:"offset"`
	TotalBytes   int64                  `json:"total_bytes"`
	Truncated    bool                   `json:"truncated"`
	NextOffset   *int64                 `json:"next_offset"`
	Coverage     *ocerrors.Coverage     `json:"coverage,omitempty"`
	Limitations  []string               `json:"limitations,omitempty"`
	Continuation *ocerrors.Continuation `json:"continuation,omitempty"`
}

// WorkspaceWriteResult is returned by Workspace.WriteFile.
type WorkspaceWriteResult struct {
	EngagementID string `json:"engagement_id"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Appended     bool   `json:"appended"`
}

// WorkspaceDeleteResult is returned by Workspace.DeletePath.
type WorkspaceDeleteResult struct {
	EngagementID string `json:"engagement_id"`
	Deleted      string `json:"deleted"`
}

// FindingReportResult is returned by Workspace.WriteFindingReport.
type FindingReportResult struct {
	WorkspaceWriteResult
	Title       string   `json:"title"`
	Target      string   `json:"target"`
	Severity    string   `json:"severity"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// Workspace provides symlink-confined file operations inside engagement namespaces.
type Workspace struct {
	Store *EngagementStore
	Audit *AuditLog
}

// NewWorkspace creates a Workspace using store and an optional AuditLog.
func NewWorkspace(store *EngagementStore, audit *AuditLog) *Workspace {
	if store == nil {
		store = NewEngagementStore("")
	}
	if audit == nil {
		audit = NewAuditLog(store)
	}
	return &Workspace{Store: store, Audit: audit}
}

// ServerManagedPath reports whether an engagement-relative path is owned by the
// server or PoC subsystem and must never be written or deleted by workspace tools.
func ServerManagedPath(rel string) bool {
	cleaned := path.Clean(filepath.ToSlash(rel))
	cleaned = strings.TrimPrefix(cleaned, "./")
	if cleaned == "" || cleaned == "." {
		return false
	}
	if cleaned == "engagement.json" {
		return true
	}
	return cleaned == "poc" || strings.HasPrefix(cleaned, "poc/")
}

func refuseServerManaged(engRoot, target, action string) error {
	rel, err := filepath.Rel(engRoot, target)
	if err != nil {
		return ocerrors.New(ocerrors.CodeScopeDenied, "path is outside engagement root")
	}
	posixRel := filepath.ToSlash(rel)
	if posixRel == "engagement.json" {
		return ocerrors.New(ocerrors.CodeInvalidArgument, "engagement.json is managed by the OpenCyber server")
	}
	if ServerManagedPath(posixRel) {
		return ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("%s is managed by the PoC subsystem and cannot be %s through the workspace tools; use the oc_poc_* tools or the opencyber-poc CLI", posixRel, action),
		)
	}
	return nil
}

// List enumerates workspace entries under relPath with optional recursion and paging.
func (w *Workspace) List(engagementID, relPath string, recursive bool, limit, offset int) (WorkspaceListResult, error) {
	eng, err := w.Store.Get(engagementID)
	if err != nil {
		return WorkspaceListResult{}, err
	}
	if relPath == "" {
		relPath = "."
	}
	root, err := w.Store.ResolvePath(engagementID, relPath, true)
	if err != nil {
		return WorkspaceListResult{}, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return WorkspaceListResult{}, ocerrors.New(
			ocerrors.CodeNotFound,
			fmt.Sprintf("not a directory: %s", relPath),
			ocerrors.WithDetail("path", relPath),
		)
	}
	if limit < 0 {
		return WorkspaceListResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "limit must be a non-negative integer; 0 returns every entry", ocerrors.WithDetail("parameter", "limit"))
	}
	if offset < 0 {
		return WorkspaceListResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "offset must be a non-negative integer", ocerrors.WithDetail("parameter", "offset"))
	}

	var all []WorkspaceEntry
	if recursive {
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil || p == root {
				return nil
			}
			// Never follow symlinks out of the engagement.
			if d.Type()&os.ModeSymlink != 0 {
				if realPath, rerr := filepath.EvalSymlinks(p); rerr != nil || !isWithinDir(realPath, eng.Workspace) {
					return nil
				}
			}
			st, serr := os.Stat(p)
			if serr != nil {
				return nil
			}
			rel, rerr := filepath.Rel(eng.Workspace, p)
			if rerr != nil {
				return nil
			}
			typ := "file"
			size := st.Size()
			if st.IsDir() {
				typ = "directory"
				size = 0
			}
			all = append(all, WorkspaceEntry{Path: filepath.ToSlash(rel), Type: typ, Size: size})
			return nil
		})
		if walkErr != nil {
			return WorkspaceListResult{}, walkErr
		}
	} else {
		dirEntries, derr := os.ReadDir(root)
		if derr != nil {
			return WorkspaceListResult{}, derr
		}
		for _, d := range dirEntries {
			p := filepath.Join(root, d.Name())
			st, serr := os.Stat(p)
			if serr != nil {
				continue
			}
			rel, rerr := filepath.Rel(eng.Workspace, p)
			if rerr != nil {
				continue
			}
			typ := "file"
			size := st.Size()
			if st.IsDir() {
				typ = "directory"
				size = 0
			}
			all = append(all, WorkspaceEntry{Path: filepath.ToSlash(rel), Type: typ, Size: size})
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	total := len(all)
	var selected []WorkspaceEntry
	if offset < total {
		end := total
		if limit > 0 && offset+limit < end {
			end = offset + limit
		}
		selected = append([]WorkspaceEntry(nil), all[offset:end]...)
	} else {
		selected = []WorkspaceEntry{}
	}

	examined := offset + len(selected)
	if examined > total {
		examined = total
	}
	exhausted := examined >= total
	covStatus := ocerrors.CoveragePartial
	if total == 0 {
		covStatus = ocerrors.CoverageEmpty
	} else if exhausted {
		covStatus = ocerrors.CoverageComplete
	}
	opts := []ocerrors.CoverageOption{
		ocerrors.WithExamined(examined),
		ocerrors.WithTotal(total),
		ocerrors.WithExhausted(exhausted),
	}
	if !exhausted {
		opts = append(opts, ocerrors.WithNextOffset(examined))
	}

	res := WorkspaceListResult{
		EngagementID: engagementID,
		Workspace:    eng.Workspace,
		Entries:      selected,
		TotalEntries: total,
		Coverage:     ocerrors.MustCoverage(covStatus, opts...),
	}
	if !exhausted {
		res.Limitations = []string{
			"The page reflects the directory at call time; entries written between pages can shift later offsets, so a paged list is a snapshot series, not one atomic inventory.",
		}
		res.Continuation = &ocerrors.Continuation{
			Tool: "oc_workspace_list",
			Arguments: map[string]any{
				"engagement_id": engagementID,
				"path":          relPath,
				"recursive":     recursive,
				"limit":         limit,
				"offset":        examined,
			},
		}
	}
	return res, nil
}

// ReadFile reads up to maxBytes starting at byte offset inside an engagement workspace.
// Pass maxBytes == 0 to read the entire remaining file.
func (w *Workspace) ReadFile(engagementID, relPath string, maxBytes int, offset int64) (WorkspaceReadResult, error) {
	eng, err := w.Store.Get(engagementID)
	if err != nil {
		return WorkspaceReadResult{}, err
	}
	target, err := w.Store.ResolvePath(engagementID, relPath, true)
	if err != nil {
		return WorkspaceReadResult{}, err
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return WorkspaceReadResult{}, ocerrors.New(
			ocerrors.CodeNotFound,
			fmt.Sprintf("not a file: %s", relPath),
			ocerrors.WithDetail("path", relPath),
		)
	}
	if maxBytes < 0 {
		return WorkspaceReadResult{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			"max_bytes must be a non-negative integer of bytes; 0 returns the whole file",
			ocerrors.WithDetail("parameter", "max_bytes"),
		)
	}
	if maxBytes > MaxWorkspaceReadBytes {
		eff := float64(MaxWorkspaceReadBytes)
		req := float64(maxBytes)
		return WorkspaceReadResult{}, ocerrors.RaiseExceeded(
			"workspace.read_max_bytes",
			fmt.Sprintf("max_bytes exceeds the supported ceiling of %d bytes", MaxWorkspaceReadBytes),
			&eff,
			&req,
			"max_bytes",
			nil,
		)
	}
	if offset < 0 {
		return WorkspaceReadResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "offset must be a non-negative integer", ocerrors.WithDetail("parameter", "offset"))
	}
	totalBytes := info.Size()
	if offset > totalBytes {
		return WorkspaceReadResult{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("offset %d is past the end of a %d-byte file", offset, totalBytes),
			ocerrors.WithDetails(map[string]any{"offset": offset, "total_bytes": totalBytes}),
		)
	}

	f, err := os.Open(target)
	if err != nil {
		return WorkspaceReadResult{}, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return WorkspaceReadResult{}, err
		}
	}
	var data []byte
	if maxBytes == 0 {
		data, err = io.ReadAll(f)
	} else {
		data, err = io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	}
	if err != nil {
		return WorkspaceReadResult{}, err
	}

	rel, err := filepath.Rel(eng.Workspace, target)
	if err != nil {
		return WorkspaceReadResult{}, err
	}
	posixRel := filepath.ToSlash(rel)
	readEnd := offset + int64(len(data))
	truncated := readEnd < totalBytes

	res := WorkspaceReadResult{
		EngagementID: engagementID,
		Path:         posixRel,
		Content:      strings.ToValidUTF8(string(data), "\uFFFD"),
		Offset:       offset,
		TotalBytes:   totalBytes,
		Truncated:    truncated,
	}
	if truncated {
		next := readEnd
		res.NextOffset = &next
		cov := ocerrors.MustCoverage(
			ocerrors.CoveragePartial,
			ocerrors.WithExamined(int(readEnd)),
			ocerrors.WithTotal(int(totalBytes)),
			ocerrors.WithExhausted(false),
		)
		res.Coverage = &cov
		res.Limitations = []string{
			fmt.Sprintf("Returned bytes %d to %d of %d; the remainder is unread, which is not evidence that it is empty.", offset, readEnd, totalBytes),
		}
		res.Continuation = &ocerrors.Continuation{
			Tool: "oc_workspace_read",
			Arguments: map[string]any{
				"engagement_id": engagementID,
				"path":          posixRel,
				"max_bytes":     maxBytes,
				"offset":        readEnd,
			},
		}
	}
	return res, nil
}

// WriteFile writes or appends UTF-8 content to a confined engagement file,
// refusing server-managed paths and symlink escapes.
func (w *Workspace) WriteFile(engagementID, relPath, content string, appendMode bool) (WorkspaceWriteResult, error) {
	eng, err := w.Store.Get(engagementID)
	if err != nil {
		return WorkspaceWriteResult{}, err
	}
	target, err := w.Store.ResolvePath(engagementID, relPath, false)
	if err != nil {
		return WorkspaceWriteResult{}, err
	}
	if err := refuseServerManaged(eng.Workspace, target, "written"); err != nil {
		return WorkspaceWriteResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return WorkspaceWriteResult{}, err
	}
	// Re-verify after MkdirAll so no symlink appeared.
	if _, err := w.Store.ResolvePath(engagementID, relPath, false); err != nil {
		return WorkspaceWriteResult{}, err
	}

	flags := os.O_WRONLY | os.O_CREATE
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(target, flags, 0o600)
	if err != nil {
		return WorkspaceWriteResult{}, err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return WorkspaceWriteResult{}, err
	}
	if err := f.Close(); err != nil {
		return WorkspaceWriteResult{}, err
	}

	st, err := os.Stat(target)
	if err != nil {
		return WorkspaceWriteResult{}, err
	}
	rel, err := filepath.Rel(eng.Workspace, target)
	if err != nil {
		return WorkspaceWriteResult{}, err
	}
	posixRel := filepath.ToSlash(rel)

	res := WorkspaceWriteResult{
		EngagementID: engagementID,
		Path:         posixRel,
		Size:         st.Size(),
		Appended:     appendMode,
	}
	if w.Audit != nil {
		sum := sha256.Sum256([]byte(content))
		w.Audit.SafeRecord(engagementID, map[string]any{
			"event":    "workspace.write",
			"path":     posixRel,
			"size":     st.Size(),
			"appended": appendMode,
			"sha256":   hex.EncodeToString(sum[:]),
		})
	}
	return res, nil
}

// DeletePath removes a file or empty directory inside an engagement workspace,
// refusing the engagement root, server-managed paths, and symlink escapes.
func (w *Workspace) DeletePath(engagementID, relPath string) (WorkspaceDeleteResult, error) {
	eng, err := w.Store.Get(engagementID)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	target, err := w.Store.ResolvePath(engagementID, relPath, true)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	if filepath.Clean(target) == filepath.Clean(eng.Workspace) {
		return WorkspaceDeleteResult{}, ocerrors.New(ocerrors.CodeInvalidArgument, "cannot delete the engagement root")
	}
	if err := refuseServerManaged(eng.Workspace, target, "deleted"); err != nil {
		return WorkspaceDeleteResult{}, err
	}
	if err := os.Remove(target); err != nil {
		return WorkspaceDeleteResult{}, err
	}
	rel, err := filepath.Rel(eng.Workspace, target)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	posixRel := filepath.ToSlash(rel)
	if w.Audit != nil {
		w.Audit.SafeRecord(engagementID, map[string]any{
			"event": "workspace.delete",
			"path":  posixRel,
		})
	}
	return WorkspaceDeleteResult{
		EngagementID: engagementID,
		Deleted:      posixRel,
	}, nil
}

// WriteFindingReport formats and writes a structured Markdown security finding.
func (w *Workspace) WriteFindingReport(engagementID, relPath, title, target, severity, summary string, evidence []string, remediation string, evidenceIDs []string) (FindingReportResult, error) {
	lines := make([]string, 0, len(evidence))
	for _, item := range evidence {
		lines = append(lines, "- "+item)
	}
	evidenceBlock := strings.Join(lines, "\n")
	if evidenceBlock == "" {
		evidenceBlock = "- No evidence supplied"
	}
	rem := remediation
	if strings.TrimSpace(rem) == "" {
		rem = "Not supplied"
	}
	content := fmt.Sprintf(
		"# %s\n\n- Target: `%s`\n- Severity: **%s**\n\n## Summary\n\n%s\n\n## Evidence\n\n%s\n\n## Remediation\n\n%s\n",
		title, target, strings.ToUpper(severity), summary, evidenceBlock, rem,
	)
	writeRes, err := w.WriteFile(engagementID, relPath, content, false)
	if err != nil {
		return FindingReportResult{}, err
	}
	ids := append([]string{}, evidenceIDs...)
	if ids == nil {
		ids = []string{}
	}
	return FindingReportResult{
		WorkspaceWriteResult: writeRes,
		Title:                title,
		Target:               target,
		Severity:             severity,
		EvidenceIDs:          ids,
	}, nil
}

// Package policy implements Rules of Engagement scope enforcement, blocklists,
// shell wrapper refusal, symlink-safe engagement workspace confinement,
// HMAC-SHA256 signed PoC authorization records, and tamper-evident hash-chained
// JSONL audit trails.
package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	ocerrors "github.com/hanzoai/cyber/pkg/errors"
)

const (
	// WorkspaceEnv selects the root workspace directory for engagements.
	WorkspaceEnv = "OPENCYBER_WORKSPACE"

	// DefaultWorkspace is the container workspace path when WorkspaceEnv is unset.
	DefaultWorkspace = "/workspace"

	// EngagementSchemaVersion is the current engagement.json schema revision.
	EngagementSchemaVersion = 1
)

// EngagementIDPattern matches server-generated engagement identifiers.
var EngagementIDPattern = regexp.MustCompile(`^eng_\d{8}_[0-9a-f]{32}$`)

// EngagementDirectoryNames are the default subdirectories initialized per engagement.
var EngagementDirectoryNames = []string{"artifacts", "evidence", "findings"}

// Engagement is the persisted manifest for one isolated assessment namespace.
type Engagement struct {
	SchemaVersion int      `json:"schema_version"`
	EngagementID  string   `json:"engagement_id"`
	Name          string   `json:"name"`
	Targets       []string `json:"targets"`
	Objective     string   `json:"objective"`
	CreatedAt     string   `json:"created_at"`
	Workspace     string   `json:"workspace,omitempty"`
}

// InvalidEngagement records a corrupt engagement directory encountered during listing.
type InvalidEngagement struct {
	EngagementID string `json:"engagement_id"`
	Error        string `json:"error"`
}

// EngagementList is the response returned by EngagementStore.List.
type EngagementList struct {
	Workspace          string              `json:"workspace"`
	Engagements        []Engagement        `json:"engagements"`
	InvalidEngagements []InvalidEngagement `json:"invalid_engagements"`
}

// EngagementStore manages persistent, isolated engagement directories under a workspace root.
type EngagementStore struct {
	WorkspaceRoot string
}

// NewEngagementStore constructs a store rooted at workspaceRoot.
// If workspaceRoot is empty, OPENCYBER_WORKSPACE or DefaultWorkspace is used.
func NewEngagementStore(workspaceRoot string) *EngagementStore {
	if strings.TrimSpace(workspaceRoot) == "" {
		workspaceRoot = strings.TrimSpace(os.Getenv(WorkspaceEnv))
		if workspaceRoot == "" {
			workspaceRoot = DefaultWorkspace
		}
	}
	return &EngagementStore{WorkspaceRoot: canonicalizeRoot(workspaceRoot)}
}

// canonicalizeRoot resolves parent symlinks (such as macOS /var -> /private/var)
// even when the leaf directory has not been created yet.
func canonicalizeRoot(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	// Resolve deepest existing ancestor and re-append non-existent tail.
	cur := abs
	var tail []string
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			parts := append([]string{resolved}, tail...)
			return filepath.Join(parts...)
		}
	}
}

// ValidateEngagementID verifies that id matches the server-generated engagement format.
func ValidateEngagementID(id string) error {
	if !EngagementIDPattern.MatchString(id) {
		return ocerrors.New(
			ocerrors.CodeInvalidArgument,
			"engagement_id must be a server-generated identifier such as eng_20261009_9f8d4c1a6b2743f4a2c11bb8d02a91a7",
			ocerrors.WithDetail("engagement_id", id),
		)
	}
	return nil
}

func (s *EngagementStore) root() string {
	return canonicalizeRoot(s.WorkspaceRoot)
}

func (s *EngagementStore) engagementsDir() string {
	return filepath.Join(s.root(), "engagements")
}

func (s *EngagementStore) engagementDir(engagementID string) (string, error) {
	if err := ValidateEngagementID(engagementID); err != nil {
		return "", err
	}
	return filepath.Join(s.engagementsDir(), engagementID), nil
}

// Create initializes a new engagement directory with atomic manifest creation.
func (s *EngagementStore) Create(name string, targets []string, objective string) (Engagement, error) {
	normalizedName := strings.TrimSpace(name)
	if normalizedName == "" {
		return Engagement{}, ocerrors.New(ocerrors.CodeInvalidArgument, "name must not be empty")
	}
	if len(normalizedName) > 200 {
		return Engagement{}, ocerrors.New(ocerrors.CodeInvalidArgument, "name must be 200 characters or fewer")
	}
	if len(targets) == 0 {
		return Engagement{}, ocerrors.New(ocerrors.CodeInvalidArgument, "targets must contain at least one authorized target")
	}
	normalizedTargets := make([]string, 0, len(targets))
	for _, t := range targets {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			return Engagement{}, ocerrors.New(ocerrors.CodeInvalidArgument, "every target must be a non-empty string")
		}
		normalizedTargets = append(normalizedTargets, trimmed)
	}

	engRoot := s.engagementsDir()
	if err := os.MkdirAll(engRoot, 0o700); err != nil {
		return Engagement{}, fmt.Errorf("create engagements directory: %w", err)
	}

	now := time.Now().UTC()
	dateStr := now.Format("20060102")

	var engagementID, finalDir, tempDir string
	for {
		engagementID = fmt.Sprintf("eng_%s_%s", dateStr, randomHex(16))
		finalDir = filepath.Join(engRoot, engagementID)
		tempDir = filepath.Join(engRoot, "."+engagementID+".tmp")
		if _, err := os.Lstat(finalDir); err == nil {
			continue
		}
		if err := os.Mkdir(tempDir, 0o700); err != nil {
			if stderrors.Is(err, os.ErrExist) {
				continue
			}
			return Engagement{}, fmt.Errorf("create temporary engagement directory: %w", err)
		}
		break
	}

	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.RemoveAll(tempDir)
		}
	}()

	for _, sub := range EngagementDirectoryNames {
		if err := os.Mkdir(filepath.Join(tempDir, sub), 0o700); err != nil {
			return Engagement{}, fmt.Errorf("create engagement subdir %s: %w", sub, err)
		}
	}

	manifest := Engagement{
		SchemaVersion: EngagementSchemaVersion,
		EngagementID:  engagementID,
		Name:          normalizedName,
		Targets:       normalizedTargets,
		Objective:     strings.TrimSpace(objective),
		CreatedAt:     isoUTC(now),
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Engagement{}, err
	}
	raw = append(raw, '\n')
	if err := atomicWriteFile(filepath.Join(tempDir, "engagement.json"), raw, 0o600); err != nil {
		return Engagement{}, err
	}
	if err := os.Rename(tempDir, finalDir); err != nil {
		return Engagement{}, fmt.Errorf("finalize engagement directory: %w", err)
	}
	cleanupTemp = false

	resolvedDir, err := filepath.EvalSymlinks(finalDir)
	if err != nil {
		resolvedDir = finalDir
	}
	manifest.Workspace = resolvedDir
	return manifest, nil
}

// Get loads and verifies an engagement manifest, rejecting symlinks and tampered manifests.
func (s *EngagementStore) Get(engagementID string) (Engagement, error) {
	dir, err := s.engagementDir(engagementID)
	if err != nil {
		return Engagement{}, err
	}
	engRoot := s.engagementsDir()
	if info, lerr := os.Lstat(engRoot); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("invalid engagement namespace: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
		)
	}
	resolvedEngRoot := canonicalizeRoot(engRoot)

	dirInfo, lerr := os.Lstat(dir)
	if lerr != nil {
		if stderrors.Is(lerr, os.ErrNotExist) {
			return Engagement{}, ocerrors.New(
				ocerrors.CodeEngagementNotFound,
				fmt.Sprintf("unknown engagement_id: %s", engagementID),
				ocerrors.WithDetail("engagement_id", engagementID),
			)
		}
		return Engagement{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("invalid engagement namespace: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
			ocerrors.WithCause(lerr),
		)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("invalid engagement namespace: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
		)
	}
	resolvedDir, rerr := filepath.EvalSymlinks(dir)
	if rerr != nil || resolvedDir != filepath.Join(resolvedEngRoot, engagementID) {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("invalid engagement namespace: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
		)
	}

	manifestPath := filepath.Join(resolvedDir, "engagement.json")
	mInfo, merr := os.Lstat(manifestPath)
	if merr != nil || mInfo.Mode()&os.ModeSymlink != 0 || !mInfo.Mode().IsRegular() {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeEngagementNotFound,
			fmt.Sprintf("unknown engagement_id: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
		)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeIntegrityMismatch,
			fmt.Sprintf("invalid engagement manifest: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
			ocerrors.WithCause(err),
		)
	}
	var eng Engagement
	if err := json.Unmarshal(raw, &eng); err != nil {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeIntegrityMismatch,
			fmt.Sprintf("invalid engagement manifest: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
			ocerrors.WithCause(err),
		)
	}
	if eng.EngagementID != engagementID {
		return Engagement{}, ocerrors.New(
			ocerrors.CodeIntegrityMismatch,
			fmt.Sprintf("invalid engagement manifest: %s", engagementID),
			ocerrors.WithDetail("engagement_id", engagementID),
		)
	}
	eng.Workspace = resolvedDir
	return eng, nil
}

// List enumerates all engagements under WorkspaceRoot sorted newest-first.
func (s *EngagementStore) List() (EngagementList, error) {
	engRoot := s.engagementsDir()
	res := EngagementList{
		Workspace:          s.root(),
		Engagements:        []Engagement{},
		InvalidEngagements: []InvalidEngagement{},
	}
	entries, err := os.ReadDir(engRoot)
	if err != nil {
		if stderrors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if !EngagementIDPattern.MatchString(name) {
			continue
		}
		if !entry.IsDir() {
			continue
		}
		eng, gerr := s.Get(name)
		if gerr != nil {
			res.InvalidEngagements = append(res.InvalidEngagements, InvalidEngagement{
				EngagementID: name,
				Error:        gerr.Error(),
			})
			continue
		}
		res.Engagements = append(res.Engagements, eng)
	}
	sort.Slice(res.Engagements, func(i, j int) bool {
		return res.Engagements[i].CreatedAt > res.Engagements[j].CreatedAt
	})
	return res, nil
}

// ResolvePath safely confines relOrAbsPath inside the engagement workspace.
//
// It rejects NUL bytes, lexical traversal outside the engagement root, and any
// symlink (including symlinks on intermediate directories and dangling symlinks)
// that escapes the engagement root via filepath.EvalSymlinks verification.
func (s *EngagementStore) ResolvePath(engagementID, value string, mustExist bool) (string, error) {
	eng, err := s.Get(engagementID)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(value, '\x00') {
		return "", ocerrors.New(
			ocerrors.CodeInvalidArgument,
			"path must not contain NUL bytes",
			ocerrors.WithDetails(map[string]any{"engagement_id": engagementID}),
		)
	}
	engRoot, err := filepath.EvalSymlinks(eng.Workspace)
	if err != nil {
		return "", ocerrors.New(
			ocerrors.CodeInvalidArgument,
			fmt.Sprintf("cannot resolve engagement root: %v", err),
			ocerrors.WithCause(err),
		)
	}

	if value == "" || value == "." {
		return engRoot, nil
	}

	var candidate string
	if filepath.IsAbs(value) {
		candidate = filepath.Clean(value)
	} else {
		candidate = filepath.Clean(filepath.Join(engRoot, value))
	}

	if !isWithinDir(candidate, engRoot) {
		return "", ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("path must remain inside engagement %s", engagementID),
			ocerrors.WithDetails(map[string]any{"path": value, "engagement_id": engagementID}),
		)
	}

	resolved, err := resolveAndConfineSymlinks(engRoot, candidate, engagementID, value)
	if err != nil {
		return "", err
	}

	if mustExist {
		if _, err := os.Stat(resolved); err != nil {
			if stderrors.Is(err, os.ErrNotExist) {
				return "", ocerrors.New(
					ocerrors.CodeNotFound,
					fmt.Sprintf("engagement path does not exist: %s", value),
					ocerrors.WithDetails(map[string]any{"path": value, "engagement_id": engagementID}),
				)
			}
			return "", ocerrors.New(
				ocerrors.CodeInvalidArgument,
				fmt.Sprintf("cannot inspect engagement path %s: %v", value, err),
				ocerrors.WithCause(err),
			)
		}
	}
	return resolved, nil
}

// resolveAndConfineSymlinks walks candidate component-by-component below engRoot,
// verifying via EvalSymlinks that neither existing targets, intermediate symlinks,
// nor dangling symlinks can escape engRoot.
func resolveAndConfineSymlinks(engRoot, candidate, engagementID, origValue string) (string, error) {
	if candidate == engRoot {
		return engRoot, nil
	}
	rel, err := filepath.Rel(engRoot, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("path must remain inside engagement %s", engagementID),
			ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
		)
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := engRoot
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next := filepath.Join(cur, part)
		info, lerr := os.Lstat(next)
		if lerr != nil {
			if stderrors.Is(lerr, os.ErrNotExist) {
				// Remaining tail does not exist yet; cur is already verified inside engRoot.
				for j := i; j < len(parts); j++ {
					if parts[j] != "" && parts[j] != "." {
						cur = filepath.Join(cur, parts[j])
					}
				}
				if !isWithinDir(cur, engRoot) {
					return "", ocerrors.New(
						ocerrors.CodeScopeDenied,
						fmt.Sprintf("path must remain inside engagement %s", engagementID),
						ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
					)
				}
				return cur, nil
			}
			return "", ocerrors.New(
				ocerrors.CodeInvalidArgument,
				fmt.Sprintf("cannot inspect path %s: %v", origValue, lerr),
				ocerrors.WithCause(lerr),
			)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			realNext, evalErr := filepath.EvalSymlinks(next)
			if evalErr != nil {
				// Dangling or cyclic symlink: fail closed to prevent symlink-planting escapes.
				return "", ocerrors.New(
					ocerrors.CodeScopeDenied,
					fmt.Sprintf("path contains an unresolvable or escaping symlink inside engagement %s", engagementID),
					ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
				)
			}
			if !isWithinDir(realNext, engRoot) {
				return "", ocerrors.New(
					ocerrors.CodeScopeDenied,
					fmt.Sprintf("symlink escapes engagement %s", engagementID),
					ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
				)
			}
			cur = realNext
			continue
		}
		cur = next
	}

	// Final whole-path EvalSymlinks check as defense in depth.
	finalReal, err := filepath.EvalSymlinks(cur)
	if err != nil {
		return "", ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("path must remain inside engagement %s", engagementID),
			ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
			ocerrors.WithCause(err),
		)
	}
	if !isWithinDir(finalReal, engRoot) {
		return "", ocerrors.New(
			ocerrors.CodeScopeDenied,
			fmt.Sprintf("symlink escapes engagement %s", engagementID),
			ocerrors.WithDetails(map[string]any{"path": origValue, "engagement_id": engagementID}),
		)
	}
	return finalReal, nil
}

func isWithinDir(path, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	if cleanPath == cleanRoot {
		return true
	}
	prefix := cleanRoot
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(cleanPath, prefix)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.%s.tmp", filepath.Base(path), randomHex(8)))
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func isoUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

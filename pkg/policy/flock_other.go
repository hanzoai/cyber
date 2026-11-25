//go:build !unix

package policy

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
)

func flockAcquire(ctx context.Context, _ uintptr, _ bool) error {
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

func flockRelease(_ uintptr) {}

func openAuditEventsFile(store *EngagementStore, engagementID string, create bool) (*os.File, error) {
	if _, err := store.Get(engagementID); err != nil {
		return nil, err
	}
	cur := store.root()
	components := []string{"engagements", engagementID, ".opencyber", "audit"}
	for _, comp := range components {
		next := filepath.Join(cur, comp)
		if create && (comp == ".opencyber" || comp == "audit") {
			if err := os.Mkdir(next, 0o700); err != nil && !stderrors.Is(err, os.ErrExist) {
				return nil, err
			}
		}
		info, err := os.Lstat(next)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("audit directory component %q must be a real directory without symlinks", comp)
		}
		cur = next
	}
	target := filepath.Join(cur, "events.jsonl")
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("audit requires a regular file")
		}
	} else if !stderrors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	flags := os.O_RDONLY
	if create {
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(target, flags, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("audit requires a regular file")
	}
	return f, nil
}

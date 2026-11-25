//go:build unix

package policy

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func flockAcquire(ctx context.Context, fd uintptr, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		err := syscall.Flock(int(fd), how|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !stderrors.Is(err, syscall.EWOULDBLOCK) && !stderrors.Is(err, syscall.EAGAIN) {
			return err
		}
		if ctx == nil {
			return syscall.Flock(int(fd), how)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func flockRelease(fd uintptr) {
	_ = syscall.Flock(int(fd), syscall.LOCK_UN)
}

// openAuditEventsFile safely opens <workspace>/engagements/<id>/.opencyber/audit/events.jsonl
// while refusing symlinks on every component below workspace root, non-regular files (FIFOs,
// devices, directories), and hardlinked files (nlink != 1).
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
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("audit file must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("audit requires a regular file with a single link")
		}
	} else if !stderrors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	flags := syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_RDWR | os.O_CREATE | os.O_APPEND
	} else {
		flags |= os.O_RDONLY
	}
	f, err := os.OpenFile(target, flags, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("audit requires a regular file with a single link")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("audit requires a regular file with a single link")
	}
	return f, nil
}

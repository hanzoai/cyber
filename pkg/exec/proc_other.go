//go:build !unix

package exec

import (
	"os"
	"os/exec"
	"time"
)

func configureProcessGroup(_ *exec.Cmd) {}

func terminateProcessGroup(cmd *exec.Cmd, waitDone <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
	}
}

func flockFile(_ *os.File, _ bool) error { return nil }

func funlockFile(_ *os.File) error { return nil }

func openRegularNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, NewError("invalid_argument", "target must be a regular file")
	}
	return os.Open(path)
}

type fileIdentity struct {
	dev   uint64
	ino   uint64
	size  int64
	mtime int64
}

func statIdentity(fi os.FileInfo) fileIdentity {
	return fileIdentity{
		size:  fi.Size(),
		mtime: fi.ModTime().UnixNano(),
	}
}

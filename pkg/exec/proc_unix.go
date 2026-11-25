//go:build unix

package exec

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateProcessGroup(cmd *exec.Cmd, waitDone <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
	}
	// Always send SIGKILL to the process group so descendants that ignored SIGTERM
	// or outlived the leader are terminated too.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
	}
}

func flockFile(f *os.File, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	return syscall.Flock(int(f.Fd()), how)
}

func funlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func openRegularNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("failed to wrap descriptor")
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, NewError("invalid_argument", "target must be a regular file")
	}
	return f, nil
}

type fileIdentity struct {
	dev   uint64
	ino   uint64
	size  int64
	mtime int64
}

func statIdentity(fi os.FileInfo) fileIdentity {
	id := fileIdentity{
		size:  fi.Size(),
		mtime: fi.ModTime().UnixNano(),
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		id.dev = uint64(st.Dev)
		id.ino = uint64(st.Ino)
	}
	return id
}

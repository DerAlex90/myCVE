//go:build windows

package runner

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		file.Close()
		return nil, errors.New("another agent process is using this state directory")
	}
	return func() { windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped); file.Close() }, nil
}

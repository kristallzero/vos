// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 VoS contributors.

package core

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func Lock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	o := new(windows.Overlapped)
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, o); e != nil {
		f.Close()
		return nil, fmt.Errorf("another VoS process owns %s: %w", path, e)
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); f.Close() }, nil
}

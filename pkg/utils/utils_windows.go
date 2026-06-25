// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package utils

import (
	"strings"
	"syscall"
)

// ValidateSocketPath checks if a Windows named pipe exists at the given path.
func ValidateSocketPath(socketPath string) error {
	path := strings.TrimPrefix(socketPath, "npipe:")
	path = strings.ReplaceAll(path, "\\", "/")
	if !strings.HasPrefix(path, "//./pipe/") {
		path = "//./pipe" + path
	}

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return ErrSocketNotFound
		}
		return err
	}
	_ = syscall.CloseHandle(handle)

	return nil
}

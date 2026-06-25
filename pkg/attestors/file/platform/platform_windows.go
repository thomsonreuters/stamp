//go:build windows

// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
	"golang.org/x/sys/windows"
)

// Windows access rights constants.
const (
	fileReadAttributes = 0x0080     // Read file attributes without data access
	readControl        = 0x00020000 // Read security descriptor (required for ownership info)
)

// WindowsOps implements Ops for Windows systems using path-based tracking.
type WindowsOps struct{}

// CheckCircularSymlink detects circular symlinks using resolved path tracking.
// Returns true if the directory has already been visited.
func (p *WindowsOps) CheckCircularSymlink(dirPath string, dirInfo os.FileInfo, seenDirInodes map[string]bool) bool {
	if dirInfo == nil {
		return false
	}

	// Resolve to absolute canonical path (handles junctions and symlinks)
	absPath, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		absPath, err = filepath.Abs(dirPath)
		if err != nil {
			return false
		}
	}

	if seenDirInodes[absPath] {
		return true
	}

	seenDirInodes[absPath] = true
	return false
}

// CheckFileDuplicate checks if a file has been processed before.
// Uses volume serial number + file index to detect hardlinks.
func (p *WindowsOps) CheckFileDuplicate(filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) bool {
	if fileInfo == nil || seenInodes == nil {
		return false
	}

	fileID, ok := getWindowsFileID(filePath)
	if !ok {
		return false
	}

	if seenInodes[fileID] {
		return true
	}

	seenInodes[fileID] = true
	return false
}

// ExtractOwnership extracts file owner and group SIDs as strings (e.g., "S-1-5-21-...").
func (p *WindowsOps) ExtractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo {
	ownerSID, groupSID, err := getWindowsOwnership(filePath)
	if err != nil {
		return nil
	}

	return &filepredicate.OwnershipInfo{
		UID:   0, // Not applicable on Windows
		GID:   0, // Not applicable on Windows
		User:  ownerSID,
		Group: groupSID,
	}
}

// ExtractTimestamps extracts creation, modified, and accessed times.
func (p *WindowsOps) ExtractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo {
	stat, ok := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return nil
	}

	return &filepredicate.TimestampInfo{
		Created:  time.Unix(0, stat.CreationTime.Nanoseconds()),
		Modified: time.Unix(0, stat.LastWriteTime.Nanoseconds()),
		Accessed: time.Unix(0, stat.LastAccessTime.Nanoseconds()),
	}
}

// getWindowsOwnership extracts owner and group SIDs as strings.
func getWindowsOwnership(filePath string) (string, string, error) {
	pathUTF16, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert path to UTF-16: %w", err)
	}

	// Use readControl to read security descriptor (owner/group information)
	handle, err := syscall.CreateFile(
		pathUTF16,
		readControl,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS, // Required for directories
		0,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	sd, err := windows.GetSecurityInfo(
		windows.Handle(handle),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", "", fmt.Errorf("GetSecurityInfo failed: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return "", "", fmt.Errorf("failed to get owner SID: %w", err)
	}

	group, _, err := sd.Group()
	if err != nil {
		return "", "", fmt.Errorf("failed to get group SID: %w", err)
	}

	var ownerStr, groupStr string
	if owner != nil {
		ownerStr = owner.String()
	}

	if group != nil {
		groupStr = group.String()
	}

	return ownerStr, groupStr, nil
}

// getWindowsFileID returns a unique identifier combining volume serial and file index.
// Format: "volumeSerial-fileIndex" (e.g., "a8b3c4d5-000000000001a2b3").
func getWindowsFileID(filePath string) (string, bool) {
	pathUTF16, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return "", false
	}

	handle, err := syscall.CreateFile(
		pathUTF16,
		fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS, // Required for directories
		0,
	)
	if err != nil {
		return "", false
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var fileInfo syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(handle, &fileInfo)
	if err != nil {
		return "", false
	}

	fileIndex := (uint64(fileInfo.FileIndexHigh) << 32) | uint64(fileInfo.FileIndexLow)
	uniqueID := fmt.Sprintf("%08x-%016x", fileInfo.VolumeSerialNumber, fileIndex)

	return uniqueID, true
}

var _ Ops = (*WindowsOps)(nil) // Ensure interface compliance

// NewWindowsOps creates a new Windows platform operations handler.
func NewWindowsOps() *WindowsOps {
	return &WindowsOps{}
}

// newOps returns the Windows implementation (build-tag-selected factory).
func newOps() Ops {
	return NewWindowsOps()
}

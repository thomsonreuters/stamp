//go:build linux

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
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// LinuxOps implements Ops for Linux systems using inode-based tracking.
type LinuxOps struct{}

// getFileInode extracts the inode number from file info.
func getFileInode(fileInfo os.FileInfo) (uint64, bool) {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return stat.Ino, true
	}
	return 0, false
}

// CheckCircularSymlink detects circular symlinks using inode tracking.
func (p *LinuxOps) CheckCircularSymlink(dirPath string, dirInfo os.FileInfo, seenDirInodes map[string]bool) bool {
	if dirInfo == nil || seenDirInodes == nil {
		return false
	}

	inode, ok := getFileInode(dirInfo)
	if !ok {
		return false
	}

	inodeStr := strconv.FormatUint(inode, 10)
	if seenDirInodes[inodeStr] {
		return true
	}

	seenDirInodes[inodeStr] = true
	return false
}

// CheckFileDuplicate detects hardlinks using inode tracking.
func (p *LinuxOps) CheckFileDuplicate(filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) bool {
	if fileInfo == nil || seenInodes == nil {
		return false
	}

	inode, ok := getFileInode(fileInfo)
	if !ok {
		return false
	}

	inodeStr := strconv.FormatUint(inode, 10)
	if seenInodes[inodeStr] {
		return true
	}

	seenInodes[inodeStr] = true
	return false
}

// ExtractOwnership extracts file ownership information (UID/GID).
func (p *LinuxOps) ExtractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	ownership := &filepredicate.OwnershipInfo{
		UID: int(stat.Uid),
		GID: int(stat.Gid),
	}

	// Try to resolve UID to username
	if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
		ownership.User = u.Username
	}

	// Try to resolve GID to group name
	if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
		ownership.Group = g.Name
	}

	return ownership
}

// ExtractTimestamps extracts file timestamps with nanosecond precision.
// Linux uses: Atim, Mtim, Ctim.
func (p *LinuxOps) ExtractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	return &filepredicate.TimestampInfo{
		Accessed: time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec)), //nolint:unconvert // required for 32-bit systems
		Modified: time.Unix(int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec)), //nolint:unconvert // required for 32-bit systems
		Created:  time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)), //nolint:unconvert // required for 32-bit systems
	}
}

var _ Ops = (*LinuxOps)(nil) // Ensure interface compliance

// NewLinuxOps creates a new Linux platform operations handler.
func NewLinuxOps() *LinuxOps {
	return &LinuxOps{}
}

// newOps returns the Linux implementation (build-tag-selected factory).
func newOps() Ops {
	return NewLinuxOps()
}

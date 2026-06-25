//go:build darwin

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

const (
	inodeBase = 10
)

// DarwinOps implements Ops for Darwin/macOS systems using inode-based tracking.
type DarwinOps struct{}

// getFileInode extracts the inode number from file info.
func getFileInode(fileInfo os.FileInfo) (uint64, bool) {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return stat.Ino, true
	}
	return 0, false
}

// CheckCircularSymlink detects circular symlinks using inode tracking.
func (p *DarwinOps) CheckCircularSymlink(dirPath string, dirInfo os.FileInfo, seenDirInodes map[string]bool) bool {
	if dirInfo == nil || seenDirInodes == nil {
		return false
	}

	inode, ok := getFileInode(dirInfo)
	if !ok {
		return false
	}

	inodeStr := strconv.FormatUint(inode, inodeBase)
	if seenDirInodes[inodeStr] {
		return true
	}

	seenDirInodes[inodeStr] = true
	return false
}

// CheckFileDuplicate detects hardlinks using inode tracking.
func (p *DarwinOps) CheckFileDuplicate(filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) bool {
	if fileInfo == nil || seenInodes == nil {
		return false
	}

	inode, ok := getFileInode(fileInfo)
	if !ok {
		return false
	}

	inodeStr := strconv.FormatUint(inode, inodeBase)
	if seenInodes[inodeStr] {
		return true
	}

	seenInodes[inodeStr] = true
	return false
}

// ExtractOwnership extracts file ownership information (UID/GID).
func (p *DarwinOps) ExtractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo {
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
// Darwin uses: Atimespec, Mtimespec, Ctimespec.
func (p *DarwinOps) ExtractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	return &filepredicate.TimestampInfo{
		Accessed: time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec),
		Modified: time.Unix(stat.Mtimespec.Sec, stat.Mtimespec.Nsec),
		Created:  time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec),
	}
}

var _ Ops = (*DarwinOps)(nil) // Ensure interface compliance

// NewDarwinOps creates a new Darwin platform operations handler.
func NewDarwinOps() *DarwinOps {
	return &DarwinOps{}
}

// newOps returns the Darwin implementation (build-tag-selected factory).
func newOps() Ops {
	return NewDarwinOps()
}

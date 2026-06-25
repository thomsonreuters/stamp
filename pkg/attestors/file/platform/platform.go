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

	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// Ops defines platform-specific operations for file attestation.
// Implementations handle OS-specific details like inode tracking (Unix)
// vs path tracking (Windows), and platform-specific metadata extraction.
type Ops interface {
	// CheckCircularSymlink detects circular symlinks/junctions during directory traversal.
	// Returns true if a circular reference is detected.
	//
	// Unix: Uses inode-based tracking
	// Windows: Uses resolved path tracking
	CheckCircularSymlink(dirPath string, dirInfo os.FileInfo, seenDirInodes map[string]bool) bool

	// CheckFileDuplicate detects if a file has already been processed.
	// Returns true if the file is a duplicate (e.g., hardlink to already-processed file).
	//
	// Unix: Uses inode-based deduplication (inode as string)
	// Windows: Uses volume serial + file index (format: %08x-%016x)
	CheckFileDuplicate(filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) bool

	// ExtractOwnership extracts file ownership information.
	// Returns nil if ownership information cannot be extracted.
	//
	// Parameters:
	//   - filePath: full path to the file (required for Windows security APIs)
	//   - fileInfo: file information from os.Stat/os.Lstat
	//
	// Unix: Extracts UID/GID and resolves to username/groupname
	// Windows: Extracts SID (Security Identifier) and converts to account names
	ExtractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo

	// ExtractTimestamps extracts file timestamp information.
	// Returns nil if timestamp information cannot be extracted.
	//
	// Unix: Extracts access/modified/changed times with nanosecond precision
	// Windows: Extracts creation/modified/access times
	ExtractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo
}

// New returns the appropriate Ops implementation for the current OS.
// This function uses build tags to select the correct implementation at compile time,
// ensuring zero runtime overhead.
func New() Ops {
	return newOps()
}

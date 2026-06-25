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

package file

import (
	"fmt"
	"os"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// extractPermissions extracts file permissions in octal and symbolic format.
func (a *Attestor) extractPermissions(fileInfo os.FileInfo) *filepredicate.PermissionInfo {
	if !a.config.CapturePermissions {
		return nil
	}

	mode := fileInfo.Mode()
	return &filepredicate.PermissionInfo{
		Mode:     fmt.Sprintf("0%o", mode.Perm()),
		Symbolic: mode.String(),
	}
}

// extractOwnership extracts file ownership information (platform-specific).
func (a *Attestor) extractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo {
	if !a.config.CaptureOwnership {
		return nil
	}

	return a.platformOps.ExtractOwnership(filePath, fileInfo)
}

// extractTimestamps extracts file timestamps (platform-specific).
func (a *Attestor) extractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo {
	if !a.config.CaptureTimestamps {
		return nil
	}

	return a.platformOps.ExtractTimestamps(fileInfo)
}

// extractSymlinkInfo extracts symbolic link target if the file is a symlink.
func (a *Attestor) extractSymlinkInfo(filePath string, fileInfo os.FileInfo) (*filepredicate.SymlinkInfo, error) {
	if fileInfo.Mode()&os.ModeSymlink == 0 {
		return nil, nil //nolint:nilnil // Valid: nil symlink info with nil error indicates file is not a symlink
	}

	target, err := os.Readlink(filePath)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "file_attestor", "metadata",
			fmt.Sprintf("failed to read symlink target: %s", filePath))
	}

	return &filepredicate.SymlinkInfo{
		IsSymlink: true,
		Target:    target,
	}, nil
}

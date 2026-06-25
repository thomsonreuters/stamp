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
	"context"
	"fmt"
	"os"
	"path/filepath"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

// collectArtifacts collects all files and directories from configured paths.
func (a *Attestor) collectArtifacts(ctx context.Context) error {
	a.logger.InfoContext(ctx, "starting artifact collection", "path_count", len(a.config.Paths))

	seenFileInodes := make(map[string]bool)
	seenDirInodes := make(map[string]bool)

	for _, path := range a.config.Paths {
		select {
		case <-ctx.Done():
			return pkgerrors.WrapWithContext(ctx.Err(), "file_attestor", "collection", "artifact collection cancelled")
		default:
		}

		fileInfo, err := os.Lstat(path)
		if err != nil {
			if a.config.ErrorOnMissing {
				a.logger.ErrorContext(ctx, "failed to stat path", "path", path, "error", err.Error())
				return pkgerrors.WrapWithContext(err, "file_attestor", "collection", fmt.Sprintf("failed to stat path: %s", path))
			}
			a.logger.WarnContext(ctx, "failed to stat path, skipping", "path", path, "error", err.Error())
			continue
		}

		if a.shouldSkipPath(path, fileInfo.IsDir()) {
			continue
		}

		if fileInfo.IsDir() {
			if err := a.collectDirectory(ctx, path, 0, seenFileInodes, seenDirInodes); err != nil {
				a.logger.ErrorContext(ctx, "failed to collect directory", "path", path, "error", err.Error())
				return err
			}
		} else {
			if err := a.collectFile(ctx, path, fileInfo, seenFileInodes); err != nil {
				a.logger.ErrorContext(ctx, "failed to collect file", "path", path, "error", err.Error())
				return err
			}
		}
	}

	a.logger.InfoContext(ctx, "artifact collection completed",
		"total_files", a.totalFiles,
		"total_directories", a.totalDirectories,
		"total_size", a.totalSize)

	return nil
}

// collectDirectory collects directory metadata and recursively processes its contents.
func (a *Attestor) collectDirectory(
	ctx context.Context,
	dirPath string,
	depth int,
	seenFileInodes map[string]bool,
	seenDirInodes map[string]bool,
) error {
	if a.config.MaxDepth >= 0 && depth > a.config.MaxDepth {
		return nil
	}

	dirInfo, err := os.Lstat(dirPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "collection", fmt.Sprintf("failed to stat directory: %s", dirPath))
	}

	if a.platformOps.CheckCircularSymlink(dirPath, dirInfo, seenDirInodes) {
		return nil
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return pkgerrors.WrapWithContext(err, "file_attestor", "collection", fmt.Sprintf("failed to read directory: %s", dirPath))
	}

	var fileCount, dirCount int
	for _, entry := range entries {
		if entry.IsDir() {
			dirCount++
			continue
		}

		fileCount++
	}

	relPath, err := filepath.Rel(a.config.BasePath, dirPath)
	if err != nil {
		relPath = dirPath
	}
	if a.config.NormalizePaths {
		relPath = utils.NormalizePath(relPath)
	}

	dirMetadata := filepredicate.DirectoryInfo{
		Path:           relPath,
		Type:           "directory",
		Permissions:    a.extractPermissions(dirInfo),
		FileCount:      fileCount,
		DirectoryCount: dirCount,
	}
	a.directories = append(a.directories, dirMetadata)
	a.totalDirectories++

	if !a.config.Recursive {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return pkgerrors.WrapWithContext(ctx.Err(), "file_attestor", "collection", "artifact collection cancelled")
		default:
		}

		if utils.IsSpecialDirectory(entry.Name()) {
			continue
		}

		entryPath := filepath.Join(dirPath, entry.Name())

		if a.shouldSkipPath(entryPath, entry.IsDir()) {
			continue
		}

		entryInfo, err := os.Lstat(entryPath)
		if err != nil {
			a.logger.WarnContext(ctx, "failed to stat entry", "path", entryPath, "error", err.Error())
			continue
		}

		if entryInfo.IsDir() {
			if err := a.collectDirectory(ctx, entryPath, depth+1, seenFileInodes, seenDirInodes); err != nil {
				return err
			}
		} else {
			if err := a.collectFile(ctx, entryPath, entryInfo, seenFileInodes); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectFile collects file hash and metadata.
func (a *Attestor) collectFile(ctx context.Context, filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) error {
	relPath, err := filepath.Rel(a.config.BasePath, filePath)
	if err != nil {
		relPath = filePath
	}
	if a.config.NormalizePaths {
		relPath = utils.NormalizePath(relPath)
	}

	if a.config.Deduplicate {
		if a.platformOps.CheckFileDuplicate(filePath, fileInfo, seenInodes) {
			return nil
		}
	}

	artifactType := "file"
	var symlinkInfo *filepredicate.SymlinkInfo

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		artifactType = "symlink"

		symlinkInfo, err = a.extractSymlinkInfo(filePath, fileInfo)
		if err != nil {
			a.logger.WarnContext(ctx, "failed to extract symlink info", "path", filePath, "error", err.Error())
		}

		if a.config.FollowSymlinks {
			resolvedInfo, err := os.Stat(filePath)
			if err == nil {
				fileInfo = resolvedInfo
				artifactType = "file"
			}
		}
	}

	digests := make(map[string]string)
	if artifactType == "file" {
		result, err := a.hasher.HashFile(ctx, filePath)
		if err != nil || result.Error != nil {
			a.logger.ErrorContext(ctx, "failed to hash file", "path", filePath, "error", err.Error())
			return err
		}
		digests = result.Digests
	}

	artifact := filepredicate.ArtifactInfo{
		Path:        relPath,
		Type:        artifactType,
		Size:        fileInfo.Size(),
		Digests:     digests,
		Permissions: a.extractPermissions(fileInfo),
		Ownership:   a.extractOwnership(filePath, fileInfo),
		Timestamps:  a.extractTimestamps(fileInfo),
		Symlink:     symlinkInfo,
	}

	a.artifacts = append(a.artifacts, artifact)
	a.totalFiles++
	a.totalSize += fileInfo.Size()

	return nil
}

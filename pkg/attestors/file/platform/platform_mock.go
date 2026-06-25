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

	"github.com/stretchr/testify/mock"
	filepredicate "github.com/thomsonreuters/stamp/pkg/predicates/file/v1"
)

// MockOps is a mock implementation of Ops interface.
// It can be used in tests to simulate platform-specific behavior without
// depending on actual OS-level operations.
type MockOps struct {
	mock.Mock
}

// NewMockOps creates a new mock platform operations handler for testing.
func NewMockOps() *MockOps {
	return &MockOps{}
}

// CheckCircularSymlink mocks the circular symlink detection.
func (m *MockOps) CheckCircularSymlink(dirPath string, dirInfo os.FileInfo, seenDirInodes map[string]bool) bool {
	args := m.Called(dirPath, dirInfo, seenDirInodes)
	return args.Bool(0)
}

// CheckFileDuplicate mocks the file deduplication check.
func (m *MockOps) CheckFileDuplicate(filePath string, fileInfo os.FileInfo, seenInodes map[string]bool) bool {
	args := m.Called(filePath, fileInfo, seenInodes)
	return args.Bool(0)
}

// ExtractOwnership mocks the ownership extraction.
func (m *MockOps) ExtractOwnership(filePath string, fileInfo os.FileInfo) *filepredicate.OwnershipInfo {
	args := m.Called(filePath, fileInfo)
	if args.Get(0) == nil {
		return nil
	}
	result, _ := args.Get(0).(*filepredicate.OwnershipInfo)
	return result
}

// ExtractTimestamps mocks the timestamp extraction.
func (m *MockOps) ExtractTimestamps(fileInfo os.FileInfo) *filepredicate.TimestampInfo {
	args := m.Called(fileInfo)
	if args.Get(0) == nil {
		return nil
	}
	result, _ := args.Get(0).(*filepredicate.TimestampInfo)
	return result
}

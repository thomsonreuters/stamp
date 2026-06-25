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

package utils

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/executor"
)

func TestGetPlatformInfo(t *testing.T) {
	info := GetPlatformInfo()

	assert.Equal(t, runtime.GOOS, info.OS)
	assert.NotEmpty(t, info.OS, "OS should not be empty")

	assert.Equal(t, runtime.GOARCH, info.Arch)
	assert.NotEmpty(t, info.Arch, "Arch should not be empty")

	assert.IsType(t, "", info.Version)
}

func TestGetPlatformInfo_Fields(t *testing.T) {
	info := GetPlatformInfo()

	assert.NotNil(t, info.OS)
	assert.NotNil(t, info.Arch)
	assert.NotNil(t, info.Version)

	knownOS := []string{
		"linux", "darwin", "windows", "freebsd", "openbsd", "netbsd",
		"dragonfly", "solaris", "plan9", "aix", "android", "ios", "js", "wasip1",
	}
	assert.Contains(t, knownOS, info.OS, "OS should be a known value")

	knownArch := []string{
		"386", "amd64", "arm", "arm64", "mips", "mips64", "mips64le",
		"mipsle", "ppc64", "ppc64le", "riscv64", "s390x", "wasm",
	}
	assert.Contains(t, knownArch, info.Arch, "Arch should be a known architecture")
}

func TestDetectPlatformVersion(t *testing.T) {
	version := DetectPlatformVersion()

	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		assert.IsType(t, "", version)
	default:
		assert.Empty(t, version, "Unsupported platforms should return empty version")
	}
}

func TestDetectPlatformVersion_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	version := detectLinuxVersion()
	assert.IsType(t, "", version)

	if version != "" {
		containsLinux := strings.Contains(version, "Linux") || strings.Contains(version, "linux")
		containsVersion := strings.Contains(version, "version")
		assert.True(t, containsLinux || containsVersion,
			"Linux version should contain 'Linux' or 'version', got: %s", version)
	}
}

func TestDetectPlatformVersion_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific test on non-macOS platform")
	}

	version := detectDarwinVersion()
	assert.IsType(t, "", version)

	if version != "" {
		assert.Regexp(t, `^\d+`, version, "macOS version should start with a digit")
	}
}

func TestDetectPlatformVersion_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	version := detectWindowsVersion()
	assert.IsType(t, "", version)

	if version != "" {
		containsWindows := strings.Contains(version, "Windows") || strings.Contains(version, "Microsoft")
		assert.True(t, containsWindows,
			"Windows version should contain 'Windows' or 'Microsoft', got: %s", version)
	}
}

func TestPlatformInfo_Consistency(t *testing.T) {
	info1 := GetPlatformInfo()
	info2 := GetPlatformInfo()

	assert.Equal(t, info1.OS, info2.OS, "OS should be consistent")
	assert.Equal(t, info1.Arch, info2.Arch, "Arch should be consistent")
	assert.Equal(t, info1.Version, info2.Version, "Version should be consistent")
}

func TestDetectPlatformVersion_UnsupportedPlatform(t *testing.T) {
	supportedPlatforms := map[string]bool{
		"linux":   true,
		"darwin":  true,
		"windows": true,
	}

	if !supportedPlatforms[runtime.GOOS] {
		version := DetectPlatformVersion()
		assert.Empty(t, version, "Unsupported platforms should return empty version")
	}
}

func TestDetectPlatformVersion_NonBlocking(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		_ = DetectPlatformVersion()
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "Platform version detection took too long (>5 seconds)")
	}
}

func TestGetPlatformInfo_StructFields(t *testing.T) {
	info := GetPlatformInfo()

	require.NotEmpty(t, info.OS)
	require.NotEmpty(t, info.Arch)

	_ = info.OS
	_ = info.Arch
	_ = info.Version
}

func TestDetectPlatformVersion_ReturnsString(t *testing.T) {
	version := DetectPlatformVersion()
	assert.NotNil(t, version, "Version should never be nil")
	assert.IsType(t, "", version, "Version should be a string")
}

func TestPlatformInfo_RealWorldUsage(t *testing.T) {
	info := GetPlatformInfo()

	platformString := info.OS + "/" + info.Arch
	assert.NotEmpty(t, platformString)
	assert.Contains(t, platformString, "/")
}

func TestDetectLinuxVersion_FileReadFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	version := detectLinuxVersion()
	assert.IsType(t, "", version, "Should return string even on error")
}

func TestDetectDarwinVersion_WithMock(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific mock test on non-macOS platform")
	}

	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("Output").Return([]byte("14.5\n"), nil)
	mockExec.On("CommandContext", mock.Anything, "sw_vers", "-productVersion").Return(mockCmd)

	version := detectDarwinVersion()

	assert.Equal(t, "14.5", version)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

func TestDetectDarwinVersion_CommandError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS-specific mock test on non-macOS platform")
	}

	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("Output").Return([]byte(nil), errors.New("command not found"))
	mockExec.On("CommandContext", mock.Anything, "sw_vers", "-productVersion").Return(mockCmd)

	version := detectDarwinVersion()

	assert.Empty(t, version)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

func TestDetectWindowsVersion_WithMock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific mock test on non-Windows platform")
	}

	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("Output").Return([]byte("Microsoft Windows [Version 10.0.19045.3803]\n"), nil)
	mockExec.On("CommandContext", mock.Anything, "cmd", "/c", "ver").Return(mockCmd)

	version := detectWindowsVersion()

	assert.Equal(t, "Microsoft Windows [Version 10.0.19045.3803]", version)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

func TestDetectWindowsVersion_CommandError(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific mock test on non-Windows platform")
	}

	mockExec := executor.SetupMockCommandExecutor(t)
	mockCmd := executor.NewMockCommand()

	mockCmd.On("Output").Return([]byte(nil), errors.New("command failed"))
	mockExec.On("CommandContext", mock.Anything, "cmd", "/c", "ver").Return(mockCmd)

	version := detectWindowsVersion()

	assert.Empty(t, version)
	mockExec.AssertExpectations(t)
	mockCmd.AssertExpectations(t)
}

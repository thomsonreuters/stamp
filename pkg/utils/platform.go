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
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/thomsonreuters/stamp/pkg/executor"
)

const cmdTimeout = 3 * time.Second

type PlatformInfo struct {
	OS      string
	Arch    string
	Version string
}

func GetPlatformInfo() PlatformInfo {
	return PlatformInfo{
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Version: DetectPlatformVersion(),
	}
}

func DetectPlatformVersion() string {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxVersion()
	case "darwin":
		return detectDarwinVersion()
	case "windows":
		return detectWindowsVersion()
	default:
		return ""
	}
}

func detectLinuxVersion() string {
	version, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(version))
}

func detectDarwinVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	exec := executor.NewOSCommandExecutor()
	cmd := exec.CommandContext(ctx, "sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func detectWindowsVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	exec := executor.NewOSCommandExecutor()
	cmd := exec.CommandContext(ctx, "cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

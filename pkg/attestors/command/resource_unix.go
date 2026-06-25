//go:build linux || darwin

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

package command

import (
	"syscall"

	commandpredicate "github.com/thomsonreuters/stamp/pkg/predicates/command/v1"
)

func extractResourceMetrics(usage *syscall.Rusage) *commandpredicate.ResourceInfo {
	if usage == nil {
		return &commandpredicate.ResourceInfo{}
	}

	return &commandpredicate.ResourceInfo{
		CPU: commandpredicate.CPUInfo{
			User:   float64(usage.Utime.Sec) + float64(usage.Utime.Usec)/1e6,
			System: float64(usage.Stime.Sec) + float64(usage.Stime.Usec)/1e6,
		},
		Memory: commandpredicate.MemoryInfo{
			Peak: int64(usage.Maxrss), //nolint:unconvert // keep explicit conversion to support 32 bit systems.
		},
	}
}

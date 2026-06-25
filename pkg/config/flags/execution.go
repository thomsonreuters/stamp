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

package flags

import (
	"fmt"
	"strings"
	"time"

	"github.com/thomsonreuters/stamp/pkg/types"
	plugincobra "github.com/thomsonreuters/stamp/plugins/cobra"
)

// ExecutionFlags contains retry, timeout, and parallel execution settings.
var ExecutionFlags = plugincobra.FlagGroup{
	"max-retries": {
		Name:       "max-retries",
		ConfigPath: MaxRetries,
		Type:       plugincobra.IntFlag,
		Default:    0,
		Help:       "Maximum retry attempts (0 uses config default)",
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			MinValue: &[]int{0}[0],
		},
	},
	"retry-delay": {
		Name:       "retry-delay",
		ConfigPath: RetryDelay,
		Type:       plugincobra.DurationFlag,
		Default:    time.Duration(0),
		Help:       "Initial retry delay (0 uses config default)",
		Persistent: true,
	},
	"timeout": {
		Name:       "timeout",
		ConfigPath: Timeout,
		Type:       plugincobra.DurationFlag,
		Default:    30 * time.Second,
		Help:       "Operation timeout",
		Persistent: true,
	},
	"parallel": {
		Name:       "parallel",
		ConfigPath: Parallel,
		Type:       plugincobra.BoolFlag,
		Default:    false,
		Help:       "Enable parallel execution where applicable",
		Persistent: true,
	},
	"failure-policy": {
		Name:       "failure-policy",
		ConfigPath: PipelineFailurePolicy,
		Type:       plugincobra.StringFlag,
		Default:    types.FailurePolicyFailFast.String(),
		Help:       fmt.Sprintf("Failure handling policy (%s)", strings.Join(types.ValidFailurePolicies, ", ")),
		Persistent: true,
		Constraints: &plugincobra.FlagConstraints{
			ValidValues: types.ValidFailurePolicies,
		},
	},
}

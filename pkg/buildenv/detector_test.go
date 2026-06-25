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

package buildenv

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

func TestDetectionFatalError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner error")
	fatal := &DetectionFatalError{Err: inner}

	assert.Equal(t, "inner error", fatal.Error())
	assert.Equal(t, inner, fatal.Unwrap())
}

func TestDetectEnvironment_FatalErrorStopsChain(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

	_, err := DetectEnvironment(t.Context(), logger.NewNoop(), DetectOptions{})
	require.Error(t, err)

	var fatal *DetectionFatalError
	require.ErrorAs(t, err, &fatal)
	assert.Contains(t, fatal.Error(), "initialization failed")
}

func TestDetectEnvironment_GenericFallback(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")

	env, err := DetectEnvironment(t.Context(), logger.NewNoop(), DetectOptions{})
	require.NoError(t, err)
	assert.Equal(t, EnvironmentGeneric, env.Type())
}

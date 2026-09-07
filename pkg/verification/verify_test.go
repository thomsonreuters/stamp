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

package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerify_NoTrustedMaterial asserts Verify returns an error when it is
// called without any trust root. The full bundle-verification path is
// exercised end-to-end by docs/testing/c3-e2e/run-verify.sh; unit tests
// here cover only the local guards.
func TestVerify_NoTrustedMaterial(t *testing.T) {
	result, err := Verify(t.Context(), nil, nil, Config{})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no trusted material")
}

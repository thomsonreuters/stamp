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

package loaders

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry(t *testing.T) {
	for _, format := range []string{FormatNormalized, FormatSnyk} {
		l, err := Get(format)
		require.NoError(t, err, format)
		assert.NotNil(t, l)
		assert.True(t, IsValidFormat(format))
	}

	_, err := Get("bogus")
	require.Error(t, err)
	assert.False(t, IsValidFormat("bogus"))

	assert.Equal(t, []string{FormatNormalized, FormatSnyk}, Formats())

	_, err = Get("predicate")
	require.Error(t, err, "the internal predicate format must not be accepted as input")
}

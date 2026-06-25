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

package output

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrEncodeJSON(t *testing.T) {
	require.Error(t, ErrEncodeJSON)
	assert.Equal(t, "failed to encode JSON data", ErrEncodeJSON.Error())
}

func TestErrUnsupportedFormat(t *testing.T) {
	require.Error(t, ErrUnsupportedFormat)
	assert.Equal(t, "unsupported data output format", ErrUnsupportedFormat.Error())
}

func TestErrEncodeJSON_Wrapping(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(true))

	// Channels cannot be JSON encoded
	data := make(chan int)
	err := o.Data(nil, "test", data)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrEncodeJSON)

	// Verify error message contains context
	assert.Contains(t, err.Error(), "failed to encode JSON data")
}

func TestErrUnsupportedFormat_Wrapping(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf))

	err := o.writeDataWithFormat("data", "invalid-format")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedFormat)

	// Verify error message contains the invalid format
	assert.Contains(t, err.Error(), "unsupported data output format")
	assert.Contains(t, err.Error(), "invalid-format")
}

func TestWrappedErrorsCanBeUnwrapped(t *testing.T) {
	wrapped := fmt.Errorf("%w: channel value", ErrEncodeJSON)

	require.ErrorIs(t, wrapped, ErrEncodeJSON)
	assert.NotErrorIs(t, wrapped, ErrUnsupportedFormat)
}

func TestErrorsWithFormattedMessage(t *testing.T) {
	t.Run("ErrEncodeJSON with details", func(t *testing.T) {
		innerErr := errors.New("json: unsupported type: chan int")
		wrapped := fmt.Errorf("%w: %w", ErrEncodeJSON, innerErr)

		require.ErrorIs(t, wrapped, ErrEncodeJSON)
		assert.Contains(t, wrapped.Error(), "failed to encode JSON data")
		assert.Contains(t, wrapped.Error(), "json: unsupported type: chan int")
	})

	t.Run("ErrUnsupportedFormat with format name", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: %s", ErrUnsupportedFormat, "xml")

		require.ErrorIs(t, wrapped, ErrUnsupportedFormat)
		assert.Contains(t, wrapped.Error(), "unsupported data output format")
		assert.Contains(t, wrapped.Error(), "xml")
	})
}

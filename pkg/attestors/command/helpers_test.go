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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimitedWriter(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		buf := &bytes.Buffer{}
		lw := &limitedWriter{
			w:     buf,
			limit: 100,
		}

		data := []byte("hello world")
		n, err := lw.Write(data)

		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, "hello world", buf.String())
		assert.False(t, lw.truncated)
	})

	t.Run("exceeds limit", func(t *testing.T) {
		buf := &bytes.Buffer{}
		lw := &limitedWriter{
			w:     buf,
			limit: 5,
		}

		data := []byte("hello world")
		n, err := lw.Write(data)

		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, "hello", buf.String())
		assert.True(t, lw.truncated)
	})

	t.Run("multiple writes with truncation", func(t *testing.T) {
		buf := &bytes.Buffer{}
		lw := &limitedWriter{
			w:     buf,
			limit: 10,
		}

		n1, err1 := lw.Write([]byte("hello"))
		require.NoError(t, err1)
		assert.Equal(t, 5, n1)
		assert.False(t, lw.truncated)

		n2, err2 := lw.Write([]byte(" world!"))
		require.NoError(t, err2)
		assert.Equal(t, 7, n2)
		assert.Equal(t, "hello worl", buf.String())
		assert.True(t, lw.truncated)

		n3, err3 := lw.Write([]byte("more data"))
		require.NoError(t, err3)
		assert.Equal(t, 9, n3)
		assert.Equal(t, "hello worl", buf.String())
		assert.True(t, lw.truncated)
	})
}

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddNonEmpty_NonEmptyValue(t *testing.T) {
	m := map[string]any{}
	AddNonEmpty(m, "key", "value")
	assert.Equal(t, "value", m["key"])
}

func TestAddNonEmpty_EmptyValue(t *testing.T) {
	m := map[string]any{}
	AddNonEmpty(m, "key", "")
	_, exists := m["key"]
	assert.False(t, exists)
}

func TestAddNonEmpty_MultipleKeys(t *testing.T) {
	m := map[string]any{}
	AddNonEmpty(m, "a", "1")
	AddNonEmpty(m, "b", "")
	AddNonEmpty(m, "c", "3")

	assert.Len(t, m, 2)
	assert.Equal(t, "1", m["a"])
	assert.Equal(t, "3", m["c"])
}

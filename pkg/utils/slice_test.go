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

func TestAllIn(t *testing.T) {
	tests := []struct {
		name       string
		subset     []string
		superset   []string
		expected   bool
		expectedNF []string
	}{
		{
			name:       "all_elements_present",
			subset:     []string{"a", "b"},
			superset:   []string{"a", "b", "c"},
			expected:   true,
			expectedNF: []string{},
		},
		{
			name:       "some_elements_missing",
			subset:     []string{"a", "d"},
			superset:   []string{"a", "b", "c"},
			expected:   false,
			expectedNF: []string{"d"},
		},
		{
			name:       "empty_subset",
			subset:     []string{},
			superset:   []string{"a", "b", "c"},
			expected:   false,
			expectedNF: []string{},
		},
		{
			name:       "empty_superset_with_elements",
			subset:     []string{"a"},
			superset:   []string{},
			expected:   false,
			expectedNF: []string{"a"},
		},
		{
			name:       "both_empty",
			subset:     []string{},
			superset:   []string{},
			expected:   false,
			expectedNF: []string{},
		},
		{
			name:       "exact_match",
			subset:     []string{"a", "b", "c"},
			superset:   []string{"a", "b", "c"},
			expected:   true,
			expectedNF: []string{},
		},
		{
			name:       "subset_larger_than_superset",
			subset:     []string{"a", "b", "c", "d"},
			superset:   []string{"a", "b"},
			expected:   false,
			expectedNF: []string{"c", "d"},
		},
		{
			name:       "duplicates_in_subset",
			subset:     []string{"a", "a", "b"},
			superset:   []string{"a", "b", "c"},
			expected:   true,
			expectedNF: []string{},
		},
		{
			name:       "duplicates_in_superset",
			subset:     []string{"a", "b"},
			superset:   []string{"a", "a", "b", "c"},
			expected:   true,
			expectedNF: []string{},
		},
		{
			name:       "single_element_present",
			subset:     []string{"a"},
			superset:   []string{"a"},
			expected:   true,
			expectedNF: []string{},
		},
		{
			name:       "single_element_missing",
			subset:     []string{"a"},
			superset:   []string{"b"},
			expected:   false,
			expectedNF: []string{"a"},
		},
		{
			name:       "case_sensitive_strings",
			subset:     []string{"A"},
			superset:   []string{"a", "b"},
			expected:   false,
			expectedNF: []string{"A"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, notFound := SliceAllIn(tt.subset, tt.superset)
			assert.Equal(t, tt.expected, result, "AllIn(%v, %v)", tt.subset, tt.superset)
			if len(tt.expectedNF) == 0 {
				assert.Empty(t, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			} else {
				assert.Equal(t, tt.expectedNF, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			}
		})
	}
}

func TestAllIn_Integers(t *testing.T) {
	tests := []struct {
		name       string
		subset     []int
		superset   []int
		expected   bool
		expectedNF []int
	}{
		{
			name:       "all_integers_present",
			subset:     []int{1, 2},
			superset:   []int{1, 2, 3, 4},
			expected:   true,
			expectedNF: []int{},
		},
		{
			name:       "some_integers_missing",
			subset:     []int{1, 5},
			superset:   []int{1, 2, 3, 4},
			expected:   false,
			expectedNF: []int{5},
		},
		{
			name:       "negative_numbers",
			subset:     []int{-1, 0, 1},
			superset:   []int{-2, -1, 0, 1, 2},
			expected:   true,
			expectedNF: []int{},
		},
		{
			name:       "zero_values",
			subset:     []int{0},
			superset:   []int{0, 1, 2},
			expected:   true,
			expectedNF: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, notFound := SliceAllIn(tt.subset, tt.superset)
			assert.Equal(t, tt.expected, result, "AllIn(%v, %v)", tt.subset, tt.superset)
			if len(tt.expectedNF) == 0 {
				assert.Empty(t, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			} else {
				assert.Equal(t, tt.expectedNF, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			}
		})
	}
}

func TestAllIn_CustomTypes(t *testing.T) {
	type Algorithm string

	tests := []struct {
		name       string
		subset     []Algorithm
		superset   []Algorithm
		expected   bool
		expectedNF []Algorithm
	}{
		{
			name:       "custom_type_all_present",
			subset:     []Algorithm{"sha256", "sha512"},
			superset:   []Algorithm{"sha256", "sha512", "blake3"},
			expected:   true,
			expectedNF: []Algorithm{},
		},
		{
			name:       "custom_type_missing",
			subset:     []Algorithm{"sha256", "md5"},
			superset:   []Algorithm{"sha256", "sha512", "blake3"},
			expected:   false,
			expectedNF: []Algorithm{"md5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, notFound := SliceAllIn(tt.subset, tt.superset)
			assert.Equal(t, tt.expected, result, "AllIn(%v, %v)", tt.subset, tt.superset)
			if len(tt.expectedNF) == 0 {
				assert.Empty(t, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			} else {
				assert.Equal(t, tt.expectedNF, notFound, "NotFound(%v, %v)", tt.subset, tt.superset)
			}
		})
	}
}

func TestSliceIntersect(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected []string
	}{
		{
			name:     "common_elements",
			a:        []string{"a", "b", "c"},
			b:        []string{"b", "c", "d"},
			expected: []string{"b", "c"},
		},
		{
			name:     "no_common_elements",
			a:        []string{"a", "b"},
			b:        []string{"c", "d"},
			expected: []string{},
		},
		{
			name:     "empty_first_slice",
			a:        []string{},
			b:        []string{"a", "b"},
			expected: []string{},
		},
		{
			name:     "empty_second_slice",
			a:        []string{"a", "b"},
			b:        []string{},
			expected: []string{},
		},
		{
			name:     "both_empty",
			a:        []string{},
			b:        []string{},
			expected: []string{},
		},
		{
			name:     "identical_slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "single_common_element",
			a:        []string{"a", "b", "c"},
			b:        []string{"b"},
			expected: []string{"b"},
		},
		{
			name:     "duplicates_in_first",
			a:        []string{"a", "a", "b"},
			b:        []string{"a", "c"},
			expected: []string{"a", "a"},
		},
		{
			name:     "case_sensitive",
			a:        []string{"A", "b"},
			b:        []string{"a", "B"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SliceIntersect(tt.a, tt.b)
			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSliceIntersect_Integers(t *testing.T) {
	tests := []struct {
		name     string
		a        []int
		b        []int
		expected []int
	}{
		{
			name:     "common_integers",
			a:        []int{1, 2, 3},
			b:        []int{2, 3, 4},
			expected: []int{2, 3},
		},
		{
			name:     "negative_numbers",
			a:        []int{-1, 0, 1},
			b:        []int{0, 1, 2},
			expected: []int{0, 1},
		},
		{
			name:     "no_common",
			a:        []int{1, 2},
			b:        []int{3, 4},
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SliceIntersect(tt.a, tt.b)
			if len(tt.expected) == 0 {
				assert.Empty(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func BenchmarkSliceIntersect(b *testing.B) {
	a := []string{"a", "b", "c", "d", "e"}
	s := []string{"c", "d", "e", "f", "g"}

	for b.Loop() {
		_ = SliceIntersect(a, s)
	}
}

func BenchmarkAllIn_SmallSlices(b *testing.B) {
	subset := []string{"a", "b", "c"}
	superset := []string{"a", "b", "c", "d", "e"}

	for b.Loop() {
		_, _ = SliceAllIn(subset, superset)
	}
}

func BenchmarkAllIn_LargeSlices(b *testing.B) {
	subset := make([]int, 100)
	superset := make([]int, 1000)

	for i := range subset {
		subset[i] = i
	}
	for i := range superset {
		superset[i] = i
	}

	for b.Loop() {
		_, _ = SliceAllIn(subset, superset)
	}
}

func BenchmarkAllIn_NotFound(b *testing.B) {
	subset := []string{"a", "b", "z"}
	superset := []string{"a", "b", "c", "d", "e"}

	for b.Loop() {
		_, _ = SliceAllIn(subset, superset)
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "mixed_case",
			input:    []string{"Hello", "WORLD", "Go"},
			expected: []string{"hello", "world", "go"},
		},
		{
			name:     "already_lowercase",
			input:    []string{"hello", "world"},
			expected: []string{"hello", "world"},
		},
		{
			name:     "all_uppercase",
			input:    []string{"SHA256", "SHA512", "BLAKE3"},
			expected: []string{"sha256", "sha512", "blake3"},
		},
		{
			name:     "empty_slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single_element",
			input:    []string{"TEST"},
			expected: []string{"test"},
		},
		{
			name:     "with_spaces",
			input:    []string{"Hello World", "GO Lang"},
			expected: []string{"hello world", "go lang"},
		},
		{
			name:     "with_special_chars",
			input:    []string{"Test-123", "SHA3-256"},
			expected: []string{"test-123", "sha3-256"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SliceToLower(tt.input)
			assert.Equal(t, tt.expected, result, "ToLower(%v)", tt.input)
		})
	}
}

func TestToUpper(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "mixed_case",
			input:    []string{"Hello", "world", "Go"},
			expected: []string{"HELLO", "WORLD", "GO"},
		},
		{
			name:     "already_uppercase",
			input:    []string{"HELLO", "WORLD"},
			expected: []string{"HELLO", "WORLD"},
		},
		{
			name:     "all_lowercase",
			input:    []string{"sha256", "sha512", "blake3"},
			expected: []string{"SHA256", "SHA512", "BLAKE3"},
		},
		{
			name:     "empty_slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single_element",
			input:    []string{"test"},
			expected: []string{"TEST"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SliceToUpper(tt.input)
			assert.Equal(t, tt.expected, result, "ToUpper(%v)", tt.input)
		})
	}
}

func BenchmarkToLower(b *testing.B) {
	input := []string{"SHA256", "SHA512", "BLAKE3", "SHA3-256", "SHA3-512"}

	for b.Loop() {
		_ = SliceToLower(input)
	}
}

func BenchmarkToUpper(b *testing.B) {
	input := []string{"sha256", "sha512", "blake3", "sha3-256", "sha3-512"}

	for b.Loop() {
		_ = SliceToUpper(input)
	}
}

func TestToAnySlice(t *testing.T) {
	t.Run("strings", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		result := ToAnySlice(input)

		assert.Len(t, result, 3)
		assert.Equal(t, "a", result[0])
		assert.Equal(t, "b", result[1])
		assert.Equal(t, "c", result[2])
	})

	t.Run("integers", func(t *testing.T) {
		input := []int{1, 2, 3}
		result := ToAnySlice(input)

		assert.Len(t, result, 3)
		assert.Equal(t, 1, result[0])
		assert.Equal(t, 2, result[1])
		assert.Equal(t, 3, result[2])
	})

	t.Run("empty_slice", func(t *testing.T) {
		input := []string{}
		result := ToAnySlice(input)

		assert.Empty(t, result)
		assert.NotNil(t, result)
	})

	t.Run("nil_slice", func(t *testing.T) {
		var input []string
		result := ToAnySlice(input)

		assert.Empty(t, result)
	})

	t.Run("single_element", func(t *testing.T) {
		input := []string{"only"}
		result := ToAnySlice(input)

		assert.Len(t, result, 1)
		assert.Equal(t, "only", result[0])
	})

	t.Run("booleans", func(t *testing.T) {
		input := []bool{true, false, true}
		result := ToAnySlice(input)

		assert.Len(t, result, 3)
		assert.Equal(t, true, result[0])
		assert.Equal(t, false, result[1])
		assert.Equal(t, true, result[2])
	})

	t.Run("custom_type", func(t *testing.T) {
		type Algorithm string
		input := []Algorithm{"RS256", "ES256"}
		result := ToAnySlice(input)

		assert.Len(t, result, 2)
		assert.Equal(t, Algorithm("RS256"), result[0])
		assert.Equal(t, Algorithm("ES256"), result[1])
	})
}

func BenchmarkToAnySlice(b *testing.B) {
	input := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

	for b.Loop() {
		_ = ToAnySlice(input)
	}
}

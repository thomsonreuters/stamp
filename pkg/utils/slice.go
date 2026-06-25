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

import "strings"

// SliceAllIn checks if all elements in the first slice are present in the second slice.
func SliceAllIn[T comparable](subset, superset []T) (bool, []T) {
	if len(subset) == 0 {
		return false, []T{}
	}

	// Build lookup map from superset for O(1) access
	lookup := make(map[T]bool, len(superset))
	for _, item := range superset {
		lookup[item] = true
	}

	// Collect elements from subset that are not in superset
	var notFound []T
	for _, item := range subset {
		if !lookup[item] {
			notFound = append(notFound, item)
		}
	}

	return len(notFound) == 0, notFound
}

// SliceIntersect returns elements present in both slices.
func SliceIntersect[T comparable](a, b []T) []T {
	if len(a) == 0 || len(b) == 0 {
		return []T{}
	}

	lookup := make(map[T]bool, len(b))
	for _, item := range b {
		lookup[item] = true
	}

	var result []T
	for _, item := range a {
		if lookup[item] {
			result = append(result, item)
		}
	}

	return result
}

// SliceToLower converts all strings in a slice to lowercase.
// Returns a new slice with all strings converted to lowercase.
func SliceToLower(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	result := make([]string, len(slice))
	for i, s := range slice {
		result[i] = strings.ToLower(s)
	}
	return result
}

// SliceToUpper converts all strings in a slice to uppercase.
// Returns a new slice with all strings converted to uppercase.
func SliceToUpper(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	result := make([]string, len(slice))
	for i, s := range slice {
		result[i] = strings.ToUpper(s)
	}
	return result
}

// ToAnySlice converts a slice of any type to []any ([]interface{}).
func ToAnySlice[T any](s []T) []any {
	result := make([]any, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

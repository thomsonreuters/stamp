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

// Package sourcetest provides test helpers for the source-side predicates:
// enumerating schema-required fields and mutating statement JSON by path.
package sourcetest

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
)

const maxDepth = 8

// RequiredPaths returns the dot-separated path of every required property
// reachable from root, following $defs references. Array items are addressed
// through their first element ("0").
func RequiredPaths(root *jsonschema.Schema) []string {
	var out []string
	resolve := func(s *jsonschema.Schema) *jsonschema.Schema {
		for i := 0; s != nil && s.Ref != "" && i < maxDepth; i++ {
			s = root.Definitions[strings.TrimPrefix(s.Ref, "#/$defs/")]
		}
		return s
	}
	var walk func(s *jsonschema.Schema, prefix string, depth int)
	walk = func(s *jsonschema.Schema, prefix string, depth int) {
		s = resolve(s)
		if s == nil || depth > maxDepth {
			return
		}
		if s.Items != nil {
			walk(s.Items, join(prefix, "0"), depth+1)
		}
		if s.Properties == nil {
			return
		}
		required := make(map[string]bool, len(s.Required))
		for _, r := range s.Required {
			required[r] = true
		}
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			path := join(prefix, pair.Key)
			if required[pair.Key] {
				out = append(out, path)
			}
			walk(pair.Value, path, depth+1)
		}
	}
	walk(root, "", 0)
	return out
}

// DeletePath removes the object member at the dot-separated path from data.
// It reports false when the path does not exist.
func DeletePath(t *testing.T, data []byte, path string) ([]byte, bool) {
	t.Helper()
	return mutate(t, data, path, func(parent map[string]any, key string) bool {
		if _, ok := parent[key]; !ok {
			return false
		}
		delete(parent, key)
		return true
	})
}

// SetPath sets the object member at the dot-separated path. Its parent must exist.
func SetPath(t *testing.T, data []byte, path string, value any) []byte {
	t.Helper()
	out, ok := mutate(t, data, path, func(parent map[string]any, key string) bool {
		parent[key] = value
		return true
	})
	if !ok {
		t.Fatalf("SetPath: parent of %q not found", path)
	}
	return out
}

func mutate(t *testing.T, data []byte, path string, apply func(parent map[string]any, key string) bool) ([]byte, bool) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	segments := strings.Split(path, ".")
	node := doc
	for _, seg := range segments[:len(segments)-1] {
		next, ok := child(node, seg)
		if !ok {
			return data, false
		}
		node = next
	}
	parent, ok := node.(map[string]any)
	if !ok || !apply(parent, segments[len(segments)-1]) {
		return data, false
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out, true
}

func child(node any, seg string) (any, bool) {
	switch n := node.(type) {
	case map[string]any:
		v, ok := n[seg]
		return v, ok
	case []any:
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(n) {
			return nil, false
		}
		return n[i], true
	default:
		return nil, false
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

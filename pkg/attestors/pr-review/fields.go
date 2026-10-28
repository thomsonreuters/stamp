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

package prreview

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/thomsonreuters/stamp/pkg/clients/github"
)

// fieldReader extracts fields from GitHub responses and keeps the first error, so derivations read
// linearly. Each read names its source so a failure identifies the exact field.
type fieldReader struct {
	err error
}

func (r *fieldReader) raw(obj github.Object, src, key string) (any, bool) {
	if r.err != nil {
		return nil, false
	}
	v, ok := obj[key]
	if !ok || v == nil {
		r.err = fmt.Errorf("%w: %s.%s", ErrMissingField, src, key)
		return nil, false
	}
	return v, true
}

func (r *fieldReader) invalid(src, key, want string, got any) {
	r.err = fmt.Errorf("%w: %s.%s must be %s, got %T", ErrInvalidField, src, key, want, got)
}

func (r *fieldReader) str(obj github.Object, src, key string) string {
	v, ok := r.raw(obj, src, key)
	if !ok {
		return ""
	}
	s, isString := v.(string)
	if !isString {
		r.invalid(src, key, "a string", v)
		return ""
	}
	if s == "" {
		r.err = fmt.Errorf("%w: %s.%s is empty", ErrMissingField, src, key)
	}
	return s
}

// optStr returns "" when the field is absent or null.
func (r *fieldReader) optStr(obj github.Object, src, key string) string {
	if r.err != nil || obj[key] == nil {
		return ""
	}
	return r.str(obj, src, key)
}

func (r *fieldReader) integer(obj github.Object, src, key string) int64 {
	v, ok := r.raw(obj, src, key)
	if !ok {
		return 0
	}
	n, isInt := toInt64(v)
	if !isInt {
		r.invalid(src, key, "an integer", v)
	}
	return n
}

// optInteger returns nil when the field is absent or null.
func (r *fieldReader) optInteger(obj github.Object, src, key string) *int64 {
	if r.err != nil || obj[key] == nil {
		return nil
	}
	n := r.integer(obj, src, key)
	if r.err != nil {
		return nil
	}
	return &n
}

func (r *fieldReader) boolean(obj github.Object, src, key string) bool {
	v, ok := r.raw(obj, src, key)
	if !ok {
		return false
	}
	b, isBool := v.(bool)
	if !isBool {
		r.invalid(src, key, "a boolean", v)
	}
	return b
}

// coerceBool treats an absent or null field as false.
func (r *fieldReader) coerceBool(obj github.Object, src, key string) bool {
	if r.err != nil || obj[key] == nil {
		return false
	}
	return r.boolean(obj, src, key)
}

func (r *fieldReader) object(obj github.Object, src, key string) github.Object {
	v, ok := r.raw(obj, src, key)
	if !ok {
		return github.Object{}
	}
	o, isObject := v.(map[string]any)
	if !isObject {
		r.invalid(src, key, "an object", v)
		return github.Object{}
	}
	return o
}

// optObject returns an empty object when the field is absent or null.
func (r *fieldReader) optObject(obj github.Object, src, key string) github.Object {
	if r.err != nil || obj[key] == nil {
		return github.Object{}
	}
	return r.object(obj, src, key)
}

func (r *fieldReader) array(obj github.Object, src, key string) []any {
	v, ok := r.raw(obj, src, key)
	if !ok {
		return nil
	}
	a, isArray := v.([]any)
	if !isArray {
		r.invalid(src, key, "an array", v)
		return nil
	}
	return a
}

// optArray returns nil when the field is absent or null.
func (r *fieldReader) optArray(obj github.Object, src, key string) []any {
	if r.err != nil || obj[key] == nil {
		return nil
	}
	return r.array(obj, src, key)
}

// objects converts array elements to objects, failing on any non-object element.
func (r *fieldReader) objects(items []any, src string) []github.Object {
	out := make([]github.Object, 0, len(items))
	for i, item := range items {
		if r.err != nil {
			return nil
		}
		o, ok := item.(map[string]any)
		if !ok {
			r.err = fmt.Errorf("%w: %s[%d] must be an object, got %T", ErrInvalidField, src, i, item)
			return nil
		}
		out = append(out, o)
	}
	return out
}

// stringList converts array elements to strings, failing on any non-string element.
func (r *fieldReader) stringList(items []any, src string) []string {
	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			r.err = fmt.Errorf("%w: %s[%d] must be a string, got %T", ErrInvalidField, src, i, item)
			return nil
		}
		out = append(out, s)
	}
	return out
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		if n != math.Trunc(n) || n > math.MaxInt64 || n < math.MinInt64 {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

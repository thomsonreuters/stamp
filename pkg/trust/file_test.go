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

package trust

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileResolver_ValidPath(t *testing.T) {
	r := &fileResolver{path: "testdata/trusted_root.json"}
	tr, err := r.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestFileResolver_NotFound(t *testing.T) {
	r := &fileResolver{path: "testdata/does-not-exist.json"}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust: load trusted root from")
}

func TestFileResolver_Malformed(t *testing.T) {
	r := &fileResolver{path: "testdata/malformed.json"}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
}

func TestFileResolver_BytesBypass(t *testing.T) {
	// Minimal valid TrustedRoot JSON.
	body := []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)
	r := &fileResolver{bytes: body, path: "/should/not/be/read"}
	tr, err := r.Resolve(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestFileResolver_BytesMalformed(t *testing.T) {
	r := &fileResolver{bytes: []byte(`{ not json`)}
	_, err := r.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust: parse trusted root bytes")
}

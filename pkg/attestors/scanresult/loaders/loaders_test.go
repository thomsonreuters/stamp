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
	scanpredicate "github.com/thomsonreuters/stamp/pkg/predicates/scanresult/v1"
)

func TestRegistry(t *testing.T) {
	for _, format := range []string{FormatPredicate, FormatNormalized, FormatSnyk} {
		l, err := Get(format)
		require.NoError(t, err, format)
		assert.NotNil(t, l)
		assert.True(t, IsValidFormat(format))
	}

	_, err := Get("bogus")
	require.Error(t, err)
	assert.False(t, IsValidFormat("bogus"))

	assert.Equal(t, []string{FormatNormalized, FormatPredicate, FormatSnyk}, Formats())
}

func TestPredicateLoader_RoundTrip(t *testing.T) {
	const doc = `{
  "schemaVersion": "1.0",
  "scanClass": "sast",
  "scan": { "status": "success" },
  "scanner": { "name": "wiz" },
  "findings": [],
  "summary": { "findings": 0, "bySeverity": {} }
}`
	pred, err := predicateLoader{}.Load([]byte(doc), Options{})
	require.NoError(t, err)
	assert.Equal(t, scanpredicate.ScanClassSAST, pred.ScanClass)
	assert.Equal(t, "wiz", pred.Scanner.Name)
}

func TestPredicateLoader_UnknownFieldFailsClosed(t *testing.T) {
	_, err := predicateLoader{}.Load([]byte(`{"scanClass":"sast","surprise":1}`), Options{})
	require.Error(t, err)
}

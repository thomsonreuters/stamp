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

package purl

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentPURL_Supported(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkg       string
		version   string
		want      string
	}{
		{"npm", "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"pypi alias", "PyPI", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"maven group:artifact", "Maven", "com.google.guava:guava", "32.1.3", "pkg:maven/com.google.guava/guava@32.1.3"},
		{"golang module path", "golang", "github.com/spf13/cobra", "v1.10.2", "pkg:golang/github.com/spf13/cobra@v1.10.2"},
		{"deb alias", "debian", "openssl", "1.1.1", "pkg:deb/openssl@1.1.1"},
		{"no version", "gem", "rails", "", "pkg:gem/rails"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComponentPURL(tt.ecosystem, tt.pkg, tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComponentPURL_UnsupportedEcosystem(t *testing.T) {
	_, err := ComponentPURL("cobol-packages", "acme", "1.0.0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedEcosystem)

	var uee *UnsupportedEcosystemError
	require.True(t, errors.As(err, &uee))
	assert.Equal(t, "cobol-packages", uee.Ecosystem)
}

func TestComponentPURL_EmptyEcosystem(t *testing.T) {
	_, err := ComponentPURL("", "acme", "1.0.0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedEcosystem)
}

func TestComponentPURL_MissingName(t *testing.T) {
	_, err := ComponentPURL("npm", "", "1.0.0")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUnsupportedEcosystem)
}

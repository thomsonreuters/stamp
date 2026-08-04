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
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
)

type fileResolver struct {
	path  string
	bytes []byte
}

func (r *fileResolver) Resolve(_ context.Context) (*root.TrustedRoot, error) {
	if len(r.bytes) > 0 {
		tr, err := root.NewTrustedRootFromJSON(r.bytes)
		if err != nil {
			return nil, fmt.Errorf("trust: parse trusted root bytes: %w", err)
		}
		return tr, nil
	}
	tr, err := root.NewTrustedRootFromPath(r.path)
	if err != nil {
		return nil, fmt.Errorf("trust: load trusted root from %q: %w", r.path, err)
	}
	return tr, nil
}

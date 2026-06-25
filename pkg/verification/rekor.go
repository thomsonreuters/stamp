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

package verification

import (
	"context"

	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/transparency"
)

// verifyRekor verifies inclusion in Rekor transparency log and returns validity, warnings, and UUID.
func (v *Verifier) verifyRekor(ctx context.Context, envelope *intoto.Envelope) (bool, []string, string, error) {
	rekorClient, err := transparency.NewClient(v.config.RekorURL, v.config.Insecure, v.logger)
	if err != nil {
		return false, nil, "", err
	}

	return rekorClient.VerifyInclusionWithPolicyDetails(ctx, envelope, v.config.RekorTemporalPolicy)
}

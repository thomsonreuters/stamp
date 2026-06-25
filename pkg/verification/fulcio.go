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
	"time"

	"github.com/thomsonreuters/stamp/pkg/clients/fulcio"
	"github.com/thomsonreuters/stamp/pkg/intoto"
)

const (
	DefaultMaxCertValidityDuration = 24 * time.Hour
)

func (v *Verifier) verifyFulcioCertificate(ctx context.Context, envelope *intoto.Envelope) (bool, error) {
	client, err := fulcio.New(ctx, fulcio.Options{
		FulcioURL: v.config.FulcioURL,
		Insecure:  v.config.Insecure,
		Logger:    v.logger,
	})
	if err != nil {
		return false, err
	}

	certificates, err := envelope.ExtractCertificates()
	if err != nil {
		return false, err
	}

	for _, certificate := range certificates {
		if err := client.VerifyCertificate(ctx, certificate, DefaultMaxCertValidityDuration); err != nil {
			return false, err
		}
	}

	return true, nil
}

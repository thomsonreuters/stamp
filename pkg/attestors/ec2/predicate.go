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

package ec2

import (
	"fmt"
	"time"

	"github.com/thomsonreuters/stamp/pkg/core"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	ec2predicate "github.com/thomsonreuters/stamp/pkg/predicates/ec2/v1"
)

func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	start := time.Now()
	a.logger.Info("generating EC2 attestation predicate",
		"instance_id", a.metadata.IdentityDocument.InstanceID,
		"region", a.metadata.IdentityDocument.Region)

	// Ensure config is parsed (may not be if PreAttest wasn't called)
	a.parseConfig(config)

	a.logger.Debug("creating base EC2 predicate structure")
	predicate := ec2predicate.Predicate{
		Environment: a.metadata,
		Verification: ec2predicate.VerificationInfo{
			IMDS:            a.imdsInfo,
			AttestedAt:      time.Now().UTC(),
			AttestorVersion: "1.0.0",
		},
	}
	a.logger.Debug("base predicate structure created")

	if a.config.RedactAccountID {
		a.logger.Info("redacting account ID (redact-account-id=true)")
		predicate.Environment.IdentityDocument.AccountID = "[REDACTED]"
		a.logger.Info("account ID redacted in EC2 attestation",
			"instance_id", a.metadata.IdentityDocument.InstanceID)
	}

	if a.config.RedactPrivateIPs {
		a.logger.Info("redacting private IP addresses (redact-private-ips=true)")
		predicate.Environment.IdentityDocument.PrivateIP = "[REDACTED]"
		predicate.Environment.Network.PrivateIPv4 = "[REDACTED]"
		a.logger.Info("private IP addresses redacted in EC2 attestation",
			"instance_id", a.metadata.IdentityDocument.InstanceID)
	}

	if len(a.config.SensitiveFields) > 0 {
		a.logger.Debug("applying sensitive field redactions", "fields_count", len(a.config.SensitiveFields))
		predicate = a.redactSensitiveFields(predicate, a.config.SensitiveFields)
		a.logger.Info("sensitive fields redacted in EC2 attestation",
			"fields_count", len(a.config.SensitiveFields))
	}

	a.logger.Info("EC2 attestation predicate generated successfully",
		"predicate_uri", ec2predicate.PredicateURI,
		"duration_ms", time.Since(start).Milliseconds())
	return predicate, nil
}

func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	// Name format: ec2+{region}://{instanceId}
	// Provides a URI-style identifier that includes regional context
	name := fmt.Sprintf("ec2+%s://%s",
		a.metadata.IdentityDocument.Region,
		a.metadata.IdentityDocument.InstanceID)

	digest := map[string]string{
		"instanceId": a.metadata.IdentityDocument.InstanceID,
		"imageId":    a.metadata.IdentityDocument.ImageID,
		"accountId":  a.metadata.IdentityDocument.AccountID,
	}

	return []intoto.Subject{{
		Name:   name,
		Digest: digest,
	}}
}

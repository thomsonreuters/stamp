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

package pipeline

import (
	"fmt"
	"time"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	collectionV1 "github.com/thomsonreuters/stamp/pkg/predicates/collection/v1"
)

// CreateStructuredCollectionEnvelope bundles multiple attestation envelopes into a collection.
func CreateStructuredCollectionEnvelope(name string, envelopes []*intoto.Envelope) (*intoto.Envelope, error) {
	if len(envelopes) == 0 {
		return nil, pkgerrors.NewWithContext("conversion", "create_collection",
			fmt.Sprintf("cannot create collection '%s' from empty envelopes", name))
	}

	collectionAttestations := make([]collectionV1.CollectionAttestation, 0, len(envelopes))
	var allSubjects []intoto.Subject
	subjectMap := make(map[string]intoto.Subject)

	for _, env := range envelopes {
		statement, err := env.GetStatement()
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "conversion", "extract_statement",
				"failed to extract statement from envelope")
		}

		collectionAttestations = append(collectionAttestations, collectionV1.CollectionAttestation{
			PredicateType: statement.PredicateType,
			Predicate:     statement.Predicate,
			Subjects:      statement.Subject,
		})

		for _, subject := range statement.Subject {
			if _, exists := subjectMap[subject.Name]; !exists {
				subjectMap[subject.Name] = subject
				allSubjects = append(allSubjects, subject)
			}
		}
	}

	collectionPredicate := collectionV1.CollectionPredicate{
		Name:         name,
		Created:      time.Now().UTC(),
		Attestations: collectionAttestations,
	}

	collectionStatement, err := intoto.NewStatement(collectionV1.CollectionV1URI, collectionPredicate, allSubjects)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "conversion", "create_statement",
			fmt.Sprintf("failed to create collection statement for '%s' with %d envelopes", name, len(envelopes)))
	}

	collectionEnvelope, err := intoto.NewEnvelope(collectionStatement)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "conversion", "create_envelope",
			fmt.Sprintf("failed to create collection envelope for '%s'", name))
	}

	return collectionEnvelope, nil
}

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
	"encoding/json"
	"fmt"
	"time"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	collectionV1 "github.com/thomsonreuters/stamp/pkg/predicates/collection/v1"
)

// CreateStructuredCollectionStatement builds an in-toto collection Statement
// wrapping the given per-attestation statement JSON payloads.
func CreateStructuredCollectionStatement(name string, statements [][]byte) (*intoto.Statement, error) {
	if len(statements) == 0 {
		return nil, pkgerrors.NewWithContext("conversion", "create_collection",
			fmt.Sprintf("cannot create collection '%s' from empty statements", name))
	}

	collectionAttestations := make([]collectionV1.CollectionAttestation, 0, len(statements))
	var allSubjects []intoto.Subject
	subjectMap := make(map[string]intoto.Subject)

	for _, payload := range statements {
		var stmt intoto.Statement
		if err := json.Unmarshal(payload, &stmt); err != nil {
			return nil, pkgerrors.WrapWithContext(err, "conversion", "unmarshal_statement",
				"failed to unmarshal in-toto statement for collection")
		}

		collectionAttestations = append(collectionAttestations, collectionV1.CollectionAttestation{
			PredicateType: stmt.PredicateType,
			Predicate:     stmt.Predicate,
			Subjects:      stmt.Subject,
		})

		for _, subject := range stmt.Subject {
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
			fmt.Sprintf("failed to create collection statement for '%s' with %d attestations", name, len(statements)))
	}

	return collectionStatement, nil
}

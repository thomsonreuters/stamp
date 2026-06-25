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

package v1

import (
	"time"

	"github.com/thomsonreuters/stamp/pkg/intoto"
)

const (
	// CollectionV1URI is the predicate type URI for our custom collection format.
	// This is a custom predicate type specific to this attestation framework.
	CollectionV1URI = "https://github.com/thomsonreuters/stamp/collection/v1"
)

type CollectionPredicate struct {
	Name         string                  `json:"name"`
	Created      time.Time               `json:"created"`
	Attestations []CollectionAttestation `json:"attestations"`
}

// CollectionAttestation represents an individual attestation within a collection.
type CollectionAttestation struct {
	AttestorID    string           `json:"attestor_id"`
	PredicateType string           `json:"predicate_type"`
	Predicate     any              `json:"predicate"`
	Subjects      []intoto.Subject `json:"subjects"`
}

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

package intoto

import "errors"

// Envelope errors.
var (
	// ErrNilStatement is returned when attempting to create an envelope with a nil statement.
	ErrNilStatement = errors.New("statement cannot be nil")

	// ErrNoCertificate is returned when no valid certificate is found in signatures.
	ErrNoCertificate = errors.New("no valid certificate found in signatures")
)

// Statement errors.
var (
	// ErrEmptyPredicateType is returned when predicate type is empty.
	ErrEmptyPredicateType = errors.New("predicate type cannot be empty")

	// ErrNilPredicate is returned when predicate is nil.
	ErrNilPredicate = errors.New("predicate cannot be nil")

	// ErrNoSubjects is returned when no subjects are provided.
	ErrNoSubjects = errors.New("at least one subject is required")

	// ErrInvalidStatementType is returned when statement type doesn't match expected value.
	ErrInvalidStatementType = errors.New("invalid statement type")

	// ErrEmptySubjectName is returned when a subject has an empty name.
	ErrEmptySubjectName = errors.New("subject has empty name")

	// ErrNoSubjectDigests is returned when a subject has no digests.
	ErrNoSubjectDigests = errors.New("subject has no digests")
)

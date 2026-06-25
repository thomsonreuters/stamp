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

import (
	"encoding/json"
	"fmt"
)

const (
	// StatementType is the in-toto statement type URI.
	StatementType = "https://in-toto.io/Statement/v1"
)

// Statement represents an in-toto attestation statement.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

// Subject represents an in-toto subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// NewStatement creates a new in-toto statement.
func NewStatement(predicateType string, predicate any, subjects []Subject) (*Statement, error) {
	if predicateType == "" {
		return nil, ErrEmptyPredicateType
	}

	if predicate == nil {
		return nil, ErrNilPredicate
	}

	if len(subjects) == 0 {
		return nil, ErrNoSubjects
	}

	return &Statement{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: predicateType,
		Predicate:     predicate,
	}, nil
}

// ToJSON serializes the statement to JSON.
func (s *Statement) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ToJSONIndent serializes the statement to pretty-printed JSON.
func (s *Statement) ToJSONIndent() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Validate validates the statement structure.
func (s *Statement) Validate() error {
	if s.Type != StatementType {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidStatementType, StatementType, s.Type)
	}

	if len(s.Subject) == 0 {
		return ErrNoSubjects
	}

	for i, subject := range s.Subject {
		if subject.Name == "" {
			return fmt.Errorf("subject %d: %w", i, ErrEmptySubjectName)
		}
		if len(subject.Digest) == 0 {
			return fmt.Errorf("subject %d: %w", i, ErrNoSubjectDigests)
		}
	}

	if s.PredicateType == "" {
		return ErrEmptyPredicateType
	}

	if s.Predicate == nil {
		return ErrNilPredicate
	}

	return nil
}

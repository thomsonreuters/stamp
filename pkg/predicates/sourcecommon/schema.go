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

package sourcecommon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/invopop/jsonschema"
	validator "github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrNilSchema is returned when a builder or parser is called without a
// predicate schema. Schema enforcement is mandatory.
var ErrNilSchema = errors.New("predicate schema is required")

const fallbackSchemaURL = "urn:stamp:predicate-schema"

// PredicateSchema enforces a predicate's reflected JSON schema on its wire
// form. It is the single source of truth for which fields are required and
// whether unknown fields are accepted. Go zero values cannot distinguish an
// absent int or bool from 0 or false, so presence must be checked on the raw
// JSON before it is decoded.
type PredicateSchema struct {
	build    func() *jsonschema.Schema
	once     sync.Once
	compiled *validator.Schema
	err      error
}

// NewPredicateSchema returns a lazily compiled schema built by build, which is
// normally the predicate package's Schema function.
func NewPredicateSchema(build func() *jsonschema.Schema) *PredicateSchema {
	return &PredicateSchema{build: build}
}

func (s *PredicateSchema) compile() (*validator.Schema, error) {
	s.once.Do(func() {
		if s.build == nil {
			s.err = ErrNilSchema
			return
		}
		reflected := s.build()
		if reflected == nil {
			s.err = ErrNilSchema
			return
		}
		raw, err := json.Marshal(reflected)
		if err != nil {
			s.err = fmt.Errorf("marshal predicate schema: %w", err)
			return
		}
		doc, err := validator.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			s.err = fmt.Errorf("decode predicate schema: %w", err)
			return
		}
		url := fallbackSchemaURL
		if reflected.ID != "" {
			url = reflected.ID.String()
		}
		c := validator.NewCompiler()
		if err := c.AddResource(url, doc); err != nil {
			s.err = fmt.Errorf("load predicate schema: %w", err)
			return
		}
		s.compiled, s.err = c.Compile(url)
	})
	return s.compiled, s.err
}

// ValidateJSON checks raw predicate JSON against the schema. Violations wrap
// ErrInvalidPredicate.
func (s *PredicateSchema) ValidateJSON(raw []byte) error {
	if s == nil {
		return ErrNilSchema
	}
	compiled, err := s.compile()
	if err != nil {
		return err
	}
	inst, err := validator.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPredicate, err)
	}
	if err := compiled.Validate(inst); err != nil {
		return fmt.Errorf("%w: schema: %w", ErrInvalidPredicate, err)
	}
	return nil
}

// ValidateValue marshals v and checks it against the schema, so builders can
// never emit a predicate that their own parser would reject.
func (s *PredicateSchema) ValidateValue(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: marshal: %w", ErrInvalidPredicate, err)
	}
	return s.ValidateJSON(raw)
}

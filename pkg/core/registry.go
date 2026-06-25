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

package core

import (
	"fmt"
	"sync"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
)

// FactoryFunc is a function that creates an Attestor instance with the provided logger.
type FactoryFunc func(log logger.Logger) Attestor

// Entry represents a registered attestor with its metadata and factory function.
type Entry struct {
	ID           string
	PredicateURI string
	Name         string
	Description  string
	ConfigSchema []ConfigField
	Factory      FactoryFunc
}

// Registry manages attestor registration and discovery.
// It provides thread-safe operations for registering attestors and retrieving
// them by ID or predicate URI. The registry supports multiple attestors
// per predicate URI but requires unique IDs.
//
// Registry instances are safe for concurrent use.
type Registry struct {
	mu                      sync.RWMutex
	attestorsByID           map[string]Entry
	attestorsByPredicateURI map[string][]Entry
}

// RegisterAttestor registers an attestor factory with this registry instance.

func (r *Registry) RegisterAttestor(factory FactoryFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	instance := factory(logger.NewNoop())

	id := instance.ID()
	predicateURI := instance.PredicateURI()

	if _, exists := r.attestorsByID[id]; exists {
		return pkgerrors.NewWithContext("registry", "register_attestor", fmt.Sprintf("attestor with ID %q already registered", id))
	}

	entry := Entry{
		ID:           id,
		PredicateURI: predicateURI,
		Name:         instance.Name(),
		Description:  instance.Description(),
		ConfigSchema: instance.ConfigSchema(),
		Factory:      factory,
	}

	r.attestorsByID[id] = entry
	r.attestorsByPredicateURI[predicateURI] = append(r.attestorsByPredicateURI[predicateURI], entry)

	return nil
}

// GetAttestorByID retrieves an attestor by its unique identifier and creates a new instance.
func (r *Registry) GetAttestorByID(id string, log logger.Logger) (Attestor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.attestorsByID[id]
	if !exists {
		return nil, pkgerrors.NewWithContext("registry", "get_attestor", fmt.Sprintf("attestor with ID %q not found", id))
	}

	return entry.Factory(log), nil
}

// ListAttestors returns all registered attestors in the registry.
func (r *Registry) ListAttestors() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]Entry, 0, len(r.attestorsByID))
	for _, entry := range r.attestorsByID {
		entries = append(entries, entry)
	}

	return entries
}

// ListAttestorsByPredicateURI returns all attestors registered for the given predicate URI.
func (r *Registry) ListAttestorsByPredicateURI(predicateURI string) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries, exists := r.attestorsByPredicateURI[predicateURI]
	if !exists {
		return nil
	}

	result := make([]Entry, len(entries))
	copy(result, entries)
	return result
}

var globalRegistry = &Registry{
	attestorsByID:           make(map[string]Entry),
	attestorsByPredicateURI: make(map[string][]Entry),
}

// RegisterAttestor registers an attestor factory with the global registry.
func RegisterAttestor(factory FactoryFunc) error {
	return globalRegistry.RegisterAttestor(factory)
}

// GetAttestorByID retrieves an attestor by ID from the global registry and creates a new instance.
func GetAttestorByID(id string, log logger.Logger) (Attestor, error) {
	return globalRegistry.GetAttestorByID(id, log)
}

// ListAttestors returns all registered attestors from the global registry.
func ListAttestors() []Entry {
	return globalRegistry.ListAttestors()
}

// ListAttestorsByPredicateURI returns all attestors registered for the given predicate URI from the global registry.
func ListAttestorsByPredicateURI(predicateURI string) []Entry {
	return globalRegistry.ListAttestorsByPredicateURI(predicateURI)
}

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

package signing

import (
	"context"
	"fmt"
	"sync"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// Entry holds signer registration information.
type Entry struct {
	ID      string
	Factory FactoryFunc
}

// Registry manages signer registration and discovery.
type Registry struct {
	mu      sync.RWMutex
	signers map[string]Entry
}

// NewRegistry creates a new Registry.
func NewRegistry() *Registry {
	return &Registry{
		signers: make(map[string]Entry),
	}
}

// Register registers a signer factory with this registry.
// The id parameter should be a unique identifier for the signer (e.g., "file", "fulcio").
func (r *Registry) Register(id string, factory FactoryFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if id == "" {
		return pkgerrors.NewWithContext("signing", "register", "signer ID cannot be empty")
	}

	if _, exists := r.signers[id]; exists {
		return pkgerrors.NewWithContext("signing", "register", fmt.Sprintf("signer with ID %q already registered", id))
	}

	r.signers[id] = Entry{
		ID:      id,
		Factory: factory,
	}

	return nil
}

// Get returns a signer by ID using the factory.
func (r *Registry) Get(ctx context.Context, id string, config SignerConfig) (Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.signers[id]
	if !exists {
		return nil, pkgerrors.NewWithContext("signing", "get", fmt.Sprintf("signer with ID %q not found", id))
	}

	return entry.Factory(ctx, config)
}

// List returns all registered signer IDs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.signers))
	for id := range r.signers {
		ids = append(ids, id)
	}
	return ids
}

// Has checks if a signer is registered.
func (r *Registry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.signers[id]
	return exists
}

var globalRegistry = NewRegistry()

// Register registers a signer factory with the global registry.
// The id parameter should be a unique identifier for the signer (e.g., "file", "fulcio").
func Register(id string, factory FactoryFunc) error {
	return globalRegistry.Register(id, factory)
}

// Get returns a signer by ID from the global registry.
func Get(ctx context.Context, id string, config SignerConfig) (Signer, error) {
	return globalRegistry.Get(ctx, id, config)
}

// List returns all registered signer IDs from the global registry.
func List() []string {
	return globalRegistry.List()
}

// Has checks if a signer is registered in the global registry.
func Has(id string) bool {
	return globalRegistry.Has(id)
}

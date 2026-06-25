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

package destination

import (
	"fmt"
	"sort"
	"sync"
)

// DestinationFactory is a function that creates a new destination instance.
type DestinationFactory func() Destination

// registry holds registered destination factories.
var (
	registry   = make(map[string]DestinationFactory)
	registryMu sync.RWMutex
)

// Register registers a destination factory with the given type name.
// This should be called in init() functions of destination implementations.
// Panics if the type is already registered.
func Register(destType string, factory DestinationFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[destType]; exists {
		panic(fmt.Sprintf("destination type %q already registered", destType))
	}

	registry[destType] = factory
}

// Get returns a new instance of the destination with the given type.
// Returns ErrDestinationNotFound if the type is not registered.
func Get(destType string) (Destination, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	factory, exists := registry[destType]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDestinationNotFound, destType)
	}

	return factory(), nil
}

// MustGet returns a new instance of the destination with the given type.
// Panics if the type is not registered.
func MustGet(destType string) Destination {
	dest, err := Get(destType)
	if err != nil {
		panic(err)
	}
	return dest
}

// List returns a sorted list of all registered destination types.
func List() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]string, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// IsRegistered checks if a destination type is registered.
func IsRegistered(destType string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()

	_, exists := registry[destType]
	return exists
}

// Unregister removes a destination type from the registry.
// This is primarily useful for testing.
func Unregister(destType string) {
	registryMu.Lock()
	defer registryMu.Unlock()

	delete(registry, destType)
}

// ClearRegistry removes all registered destinations.
// This is primarily useful for testing.
func ClearRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()

	registry = make(map[string]DestinationFactory)
}

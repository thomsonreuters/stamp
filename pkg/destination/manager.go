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
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Manager orchestrates writing to multiple destinations.
type Manager struct {
	destinations map[string]Destination // Instance name -> destination
	config       *ManagerConfig
	logger       logger.Logger
	mu           sync.RWMutex
}

// ManagerConfig configures the destination manager.
type ManagerConfig struct {
	// MaxParallel is the maximum number of parallel writes
	MaxParallel int

	// DefaultTimeout is the default timeout for write operations
	DefaultTimeout time.Duration

	// RetryPolicy defines retry behavior
	RetryPolicy RetryPolicy
}

// RetryPolicy defines how to retry failed operations.
type RetryPolicy struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int

	// InitialDelay is the initial delay between retries
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier
	Multiplier float64
}

// ManagerWriteResult represents the result of writing to multiple destinations.
type ManagerWriteResult struct {
	// Successful contains results from successful writes
	Successful map[string]*WriteResult

	// Failed contains errors from failed writes
	Failed map[string]error

	// Duration is the total time taken
	Duration time.Duration
}

// NewManager creates a new destination manager.
func NewManager(config *ManagerConfig, log logger.Logger) *Manager {
	config = applyManagerConfigDefaults(config)

	return &Manager{
		destinations: make(map[string]Destination),
		config:       config,
		logger:       log,
	}
}

// applyManagerConfigDefaults applies default values to the config.
func applyManagerConfigDefaults(config *ManagerConfig) *ManagerConfig {
	if config == nil {
		return &ManagerConfig{
			MaxParallel:    10,
			DefaultTimeout: 30 * time.Second,
			RetryPolicy: RetryPolicy{
				MaxAttempts:  3,
				InitialDelay: 1 * time.Second,
				MaxDelay:     30 * time.Second,
				Multiplier:   2.0,
			},
		}
	}

	if config.MaxParallel == 0 {
		config.MaxParallel = 10
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}
	if config.RetryPolicy.MaxAttempts == 0 {
		config.RetryPolicy.MaxAttempts = 3
	}
	if config.RetryPolicy.InitialDelay == 0 {
		config.RetryPolicy.InitialDelay = 1 * time.Second
	}
	if config.RetryPolicy.MaxDelay == 0 {
		config.RetryPolicy.MaxDelay = 30 * time.Second
	}
	if config.RetryPolicy.Multiplier == 0 {
		config.RetryPolicy.Multiplier = 2.0
	}

	return config
}

// Add registers a destination instance with the manager.
func (m *Manager) Add(name string, dest Destination) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.destinations[name]; exists {
		return fmt.Errorf("destination %s already exists", name)
	}

	m.destinations[name] = dest
	m.logger.DebugContext(context.Background(), "destination added",
		"name", name,
		"type", dest.Type())

	return nil
}

// Remove removes a destination instance from the manager.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dest, exists := m.destinations[name]
	if !exists {
		return fmt.Errorf("destination %s not found", name)
	}

	// Close the destination before removing
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dest.Close(ctx); err != nil {
		m.logger.WarnContext(ctx, "error closing destination during removal",
			"name", name,
			"error", err)
	}

	delete(m.destinations, name)
	m.logger.DebugContext(ctx, "destination removed", "name", name)

	return nil
}

// Write sends an attestation to the configured destinations.
func (m *Manager) Write(ctx context.Context, attestation *Attestation, opts WriteOptions) (*ManagerWriteResult, error) {
	start := time.Now()

	destinations := m.selectDestinations(opts.Destinations)
	if len(destinations) == 0 {
		return nil, ErrNoDestinationsConfigured
	}

	// Calculate appropriate timeout for retries
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = m.calculateTimeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var result *ManagerWriteResult
	var err error

	if opts.Parallel {
		result, err = m.writeParallel(ctx, attestation, destinations, opts.FailurePolicy, opts.QuorumCount)
	} else {
		result, err = m.writeSequential(ctx, attestation, destinations, opts.FailurePolicy, opts.QuorumCount)
	}

	result.Duration = time.Since(start)

	m.logger.InfoContext(ctx, "write completed",
		"attestation_id", attestation.ID,
		"predicate_type", attestation.PredicateType,
		"successful_destinations", len(result.Successful),
		"failed_destinations", len(result.Failed),
		"total_destinations", len(destinations),
		"duration_ms", result.Duration.Milliseconds(),
		"parallel", opts.Parallel,
		"failure_policy", string(opts.FailurePolicy))

	return result, err
}

// calculateTimeout calculates an appropriate timeout based on retry policy.
func (m *Manager) calculateTimeout() time.Duration {
	perRequestTimeout := m.config.DefaultTimeout

	// Calculate total delay time for exponential backoff
	totalDelay := time.Duration(0)
	delay := m.config.RetryPolicy.InitialDelay
	for i := 1; i < m.config.RetryPolicy.MaxAttempts; i++ {
		totalDelay += delay
		delay = time.Duration(float64(delay) * m.config.RetryPolicy.Multiplier)
		delay = min(delay, m.config.RetryPolicy.MaxDelay)
	}

	// Total timeout = (attempts * per-request timeout) + total delays + buffer
	return (time.Duration(m.config.RetryPolicy.MaxAttempts) * perRequestTimeout) + totalDelay + (5 * time.Second)
}

// selectDestinations returns the destinations to write to based on the options.
func (m *Manager) selectDestinations(requestedDestinations []string) map[string]Destination {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(requestedDestinations) == 0 {
		// Return all destinations
		destinations := make(map[string]Destination, len(m.destinations))
		maps.Copy(destinations, m.destinations)
		return destinations
	}

	// Return only requested destinations
	destinations := make(map[string]Destination)
	for _, name := range requestedDestinations {
		if dest, exists := m.destinations[name]; exists {
			destinations[name] = dest
		}
	}

	return destinations
}

// writeParallel writes to multiple destinations concurrently.
func (m *Manager) writeParallel(
	ctx context.Context,
	attestation *Attestation,
	destinations map[string]Destination,
	policy FailurePolicy,
	quorum int,
) (*ManagerWriteResult, error) {
	result := &ManagerWriteResult{
		Successful: make(map[string]*WriteResult),
		Failed:     make(map[string]error),
	}

	sem := make(chan struct{}, m.config.MaxParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, dest := range destinations {
		wg.Add(1)
		go func(name string, dest Destination) {
			defer wg.Done()

			writeStart := time.Now()
			sem <- struct{}{}
			defer func() { <-sem }()

			writeResult, err := m.writeWithRetry(ctx, dest, attestation)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				result.Failed[name] = err
				m.logger.ErrorContext(ctx, "destination write failed",
					"destination_name", name,
					"destination_type", dest.Type(),
					"attestation_id", attestation.ID,
					"error", err,
					"retryable", IsRetryable(err))
			} else {
				result.Successful[name] = writeResult
				m.logger.DebugContext(ctx, "destination write succeeded",
					"destination_name", name,
					"destination_type", dest.Type(),
					"attestation_id", attestation.ID,
					"location", writeResult.Location,
					"size_bytes", writeResult.Size,
					"write_duration_ms", time.Since(writeStart).Milliseconds())
			}
		}(name, dest)
	}

	wg.Wait()

	return m.evaluateResults(result, policy, quorum)
}

// writeSequential writes to destinations one at a time.
func (m *Manager) writeSequential(
	ctx context.Context,
	attestation *Attestation,
	destinations map[string]Destination,
	policy FailurePolicy,
	quorum int,
) (*ManagerWriteResult, error) {
	result := &ManagerWriteResult{
		Successful: make(map[string]*WriteResult),
		Failed:     make(map[string]error),
	}

	for name, dest := range destinations {
		writeResult, err := m.writeWithRetry(ctx, dest, attestation)

		if err != nil {
			result.Failed[name] = err
			m.logger.ErrorContext(ctx, "destination write failed",
				"destination_name", name,
				"destination_type", dest.Type(),
				"attestation_id", attestation.ID,
				"error", err,
				"retryable", IsRetryable(err))

			// Handle failure based on policy
			switch policy {
			case FailurePolicyFailFast:
				m.logger.WarnContext(ctx, "failing fast due to destination error",
					"destination_name", name,
					"policy", string(policy))
				return result, fmt.Errorf("destination %s failed: %w", name, err)
			case FailurePolicyWarn:
				m.logger.WarnContext(ctx, "destination failed but continuing",
					"destination_name", name,
					"destination_type", dest.Type(),
					"policy", string(policy))
			case FailurePolicyIgnore:
				m.logger.DebugContext(ctx, "destination failed, ignoring per policy",
					"destination_name", name,
					"destination_type", dest.Type(),
					"policy", string(policy))
			case FailurePolicyQuorum:
				// For quorum policy, we continue and check at the end
				m.logger.DebugContext(ctx, "destination failed, checking quorum at end",
					"destination_name", name,
					"destination_type", dest.Type(),
					"policy", string(policy))
			}
		} else {
			result.Successful[name] = writeResult
			m.logger.DebugContext(ctx, "destination write succeeded",
				"destination_name", name,
				"destination_type", dest.Type(),
				"attestation_id", attestation.ID,
				"location", writeResult.Location,
				"size_bytes", writeResult.Size)
		}
	}

	return m.evaluateResults(result, policy, quorum)
}

// evaluateResults determines success/failure based on policy.
func (m *Manager) evaluateResults(result *ManagerWriteResult, policy FailurePolicy, quorum int) (*ManagerWriteResult, error) {
	successful := len(result.Successful)
	failed := len(result.Failed)

	switch policy {
	case FailurePolicyIgnore:
		// Always succeed, just return results
		return result, nil

	case FailurePolicyWarn:
		// Succeed but warn about failures
		if failed > 0 {
			m.logger.WarnContext(context.Background(), "some destinations failed",
				"successful", successful,
				"failed", failed)
		}
		return result, nil

	case FailurePolicyFailFast:
		// Already handled inline, but check for all failed
		if successful == 0 {
			return result, errors.New("all destinations failed")
		}
		return result, nil

	case FailurePolicyQuorum:
		// Require minimum successful writes
		if successful < quorum {
			return result, fmt.Errorf("quorum not met: %d successful < %d required", successful, quorum)
		}
		return result, nil

	default:
		// Default to warn behavior
		return result, nil
	}
}

// writeWithRetry attempts to write with exponential backoff retry.
func (m *Manager) writeWithRetry(ctx context.Context, dest Destination, attestation *Attestation) (*WriteResult, error) {
	var lastErr error
	delay := m.config.RetryPolicy.InitialDelay

	for attempt := 1; attempt <= m.config.RetryPolicy.MaxAttempts; attempt++ {
		result, err := dest.Write(ctx, attestation)
		if err == nil {
			return result, nil
		}

		lastErr = err

		if !IsRetryable(err) {
			return nil, err
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if attempt == m.config.RetryPolicy.MaxAttempts {
			break
		}

		m.logger.WarnContext(ctx, "retrying destination write",
			"destination", dest.Type(),
			"attempt", attempt,
			"delay", delay,
			"error", err)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		delay = time.Duration(float64(delay) * m.config.RetryPolicy.Multiplier)
		delay = min(delay, m.config.RetryPolicy.MaxDelay)
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", m.config.RetryPolicy.MaxAttempts, lastErr)
}

// HealthCheck verifies all destinations are healthy.
func (m *Manager) HealthCheck(ctx context.Context) map[string]error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]error)

	for name, dest := range m.destinations {
		if err := dest.HealthCheck(ctx); err != nil {
			results[name] = err
		}
	}

	return results
}

// GetDestination returns a specific destination by name.
func (m *Manager) GetDestination(name string) Destination {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.destinations[name]
}

// ListDestinations returns the names of all registered destination instances.
func (m *Manager) ListDestinations() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.destinations))
	for name := range m.destinations {
		names = append(names, name)
	}

	return names
}

// Close gracefully shuts down all destinations.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	for name, dest := range m.destinations {
		if err := dest.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to close destination %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close some destinations: %v", errs)
	}

	return nil
}

// HasDestinations returns true if the manager has any destinations registered.
func (m *Manager) HasDestinations() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.destinations) > 0
}

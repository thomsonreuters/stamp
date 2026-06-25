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
	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
)

// Options configures pipeline behavior.
type Options struct {
	// Config provides configuration values for the pipeline
	Config config.ConfigurationIface

	// Logger for logging operations (optional, defaults to noop)
	Logger logger.Logger

	// Output for user-facing messages (optional, defaults to noop)
	Output output.OutputIface

	// AttestorID specifies the attestor ID for registry lookup
	AttestorID string

	// InstanceName is the unique name for this attestor instance
	InstanceName string

	// WorkflowName sets the workflow context (empty for standalone execution)
	WorkflowName string
}

// DefaultOptions returns sensible defaults for pipeline options.
func DefaultOptions() Options {
	return Options{
		Logger: logger.NewNoop(),
		Output: output.NewNoop(),
	}
}

// Option is a functional option for configuring pipelines.
type Option func(*Options)

// WithConfig sets the configuration.
func WithConfig(cfg config.ConfigurationIface) Option {
	return func(o *Options) { o.Config = cfg }
}

// WithLogger sets the logger.
func WithLogger(log logger.Logger) Option {
	return func(o *Options) { o.Logger = log }
}

// WithOutput sets the output handler.
func WithOutput(out output.OutputIface) Option {
	return func(o *Options) { o.Output = out }
}

// WithAttestorID sets the attestor ID.
func WithAttestorID(attestorID string) Option {
	return func(o *Options) { o.AttestorID = attestorID }
}

// WithInstanceName sets the instance name.
func WithInstanceName(name string) Option {
	return func(o *Options) { o.InstanceName = name }
}

// WithWorkflow sets the workflow context.
func WithWorkflow(workflowName string) Option {
	return func(o *Options) { o.WorkflowName = workflowName }
}

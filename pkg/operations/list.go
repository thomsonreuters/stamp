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

package operations

import (
	"context"
	"fmt"

	"github.com/thomsonreuters/stamp/pkg/config"
	"github.com/thomsonreuters/stamp/pkg/config/flags"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/output"
)

// attestorView is a JSON-serializable view of core.Entry (excludes Factory).
type attestorView struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	PredicateURI string             `json:"predicate_uri"`
	ConfigSchema []core.ConfigField `json:"config_schema,omitempty"`
}

// ListOp implements the operation for listing available attestors and their configurations.
type ListOp struct {
	config config.ConfigurationIface
	logger logger.Logger
	output output.OutputIface
}

// outputAttestorsAsData outputs attestor entries as structured JSON (for quiet mode).
func (o *ListOp) outputAttestorsAsData(entries []core.Entry, includeConfig bool) error {
	items := make([]any, len(entries))
	for i, e := range entries {
		view := attestorView{
			ID:           e.ID,
			Name:         e.Name,
			Description:  e.Description,
			PredicateURI: e.PredicateURI,
		}
		if includeConfig {
			view.ConfigSchema = e.ConfigSchema
		}
		items[i] = view
	}
	return o.output.DataBatch(items)
}

// displayExample renders a configuration field's example value to output.
func (o *ListOp) displayExample(field core.ConfigField) {
	switch field.Type {
	case "[]string":
		if examples, ok := field.Example.([]string); ok && len(examples) > 0 {
			o.output.Info("      Example: %s", examples[0])
			for _, ex := range examples[1:] {
				o.output.Info("               %s", ex)
			}
		} else {
			o.output.Info("      Example: %v", field.Example)
		}
	default:
		o.output.Info("      Example: %v", field.Example)
	}
}

// displayConfigFieldDetailed renders a configuration field with full details.
func (o *ListOp) displayConfigFieldDetailed(field core.ConfigField) {
	requiredMarker := ""
	if field.Required {
		requiredMarker = " [REQUIRED]"
	}

	o.output.List("%s%s", field.Name, requiredMarker)
	o.output.Info("      Type: %s", field.Type)
	o.output.Info("      Description: %s", field.Description)

	if field.Default != nil {
		o.output.Info("      Default: %v", field.Default)
	}

	if field.Example != nil {
		o.displayExample(field)
	}

	o.output.NewLine()
}

// showSingleAttestor displays detailed information for a specific attestor.
func (o *ListOp) showSingleAttestor(ctx context.Context, attestorID string) error {
	o.logger.InfoContext(ctx, "showing single attestor detail", "attestor_id", attestorID)

	entries := core.ListAttestors()
	var found *core.Entry
	for _, entry := range entries {
		if entry.ID == attestorID {
			found = &entry
			break
		}
	}

	if found == nil {
		o.logger.WarnContext(ctx, "attestor not found", "attestor_id", attestorID)
		return pkgerrors.NewUsageError(
			fmt.Sprintf("attestor '%s' not found", attestorID),
			"Use 'stamp list' to see available attestors")
	}

	if o.output.IsQuiet() {
		return o.outputAttestorsAsData([]core.Entry{*found}, true)
	}

	o.output.Heading(fmt.Sprintf("Attestor: %s", found.ID))
	o.output.List("Name: %s", found.Name)
	o.output.List("Description: %s", found.Description)
	o.output.List("Predicate: %s", found.PredicateURI)

	o.output.NewLine()
	o.output.Heading("Configuration Options")

	if len(found.ConfigSchema) == 0 {
		o.output.List("This attestor has no configuration options")
	} else {
		for _, field := range found.ConfigSchema {
			o.displayConfigFieldDetailed(field)
		}
	}

	o.logger.InfoContext(ctx, "attestor configuration shown")
	return nil
}

// showAttestorWithConfig displays an attestor entry with its configuration schema.
func (o *ListOp) showAttestorWithConfig(entry core.Entry) {
	o.output.Info("> %s", entry.ID)
	o.output.List("Name: %s", entry.Name)
	o.output.List("Description: %s", entry.Description)
	o.output.List("Predicate: %s", entry.PredicateURI)

	if len(entry.ConfigSchema) > 0 {
		o.output.List("Configuration:")
		for _, field := range entry.ConfigSchema {
			requiredMarker := ""
			if field.Required {
				requiredMarker = " (required)"
			}
			o.output.Info("    - %s (%s)%s", field.Name, field.Type, requiredMarker)
			o.output.Info("      %s", field.Description)
			if field.Default != nil {
				o.output.Info("      Default: %v", field.Default)
			}
		}
	} else {
		o.output.List("Configuration: None")
	}
	o.output.NewLine()
	o.output.NewLine()
}

// listAll displays all registered attestors with optional configuration details.
func (o *ListOp) listAll(ctx context.Context, showConfig bool) error {
	entries := core.ListAttestors()
	o.logger.DebugContext(ctx, "attestor registry query completed", "total_attestors", len(entries))

	if len(entries) == 0 {
		o.logger.WarnContext(ctx, "no attestors found in registry")
		// In quiet mode, output empty array
		if o.output.IsQuiet() {
			return o.output.DataBatch([]any{})
		}
		o.output.Warning("No attestors registered")
		return nil
	}

	if o.output.IsQuiet() {
		return o.outputAttestorsAsData(entries, showConfig)
	}

	o.output.Progress("Loading all registered attestors")
	o.output.Success("Found %d available attestor(s)", len(entries))
	o.output.NewLine()

	o.output.Heading("Available attestors")
	if showConfig {
		for _, entry := range entries {
			o.showAttestorWithConfig(entry)
		}
	} else {
		// Calculate maximum ID length for alignment
		maxIDLen := 0
		for _, entry := range entries {
			if len(entry.ID) > maxIDLen {
				maxIDLen = len(entry.ID)
			}
		}

		// Print with aligned descriptions
		for _, entry := range entries {
			o.output.List("%-*s	%s", maxIDLen, entry.ID, entry.Description)
		}
	}

	o.logger.InfoContext(ctx, "stamp listing completed")
	return nil
}

// Execute performs the list operation to display available attestors.
func (o *ListOp) Execute(ctx context.Context, args []string) error {
	if len(args) == 1 {
		o.logger.InfoContext(ctx, "showing single attestor information")
		return o.showSingleAttestor(ctx, args[0])
	}

	o.logger.InfoContext(ctx, "starting stamp listing")
	showConfig := o.config.GetBool(flags.ListShowConfig)

	return o.listAll(ctx, showConfig)
}

// NewListOp creates a new ListOp instance with the provided configuration, logger, and output handler.
func NewListOp(config config.ConfigurationIface, logger logger.Logger, output output.OutputIface) *ListOp {
	return &ListOp{
		config: config,
		logger: logger,
		output: output,
	}
}

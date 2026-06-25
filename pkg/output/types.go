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

package output

import (
	"io"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

// ColorCode represents ANSI color codes for terminal output.
type ColorCode string

// Color constants for terminal output.
const (
	ColorReset  ColorCode = ANSIReset
	ColorRed    ColorCode = ANSIRed
	ColorGreen  ColorCode = ANSIGreen
	ColorYellow ColorCode = ANSIYellow
	ColorBlue   ColorCode = ANSIBlue
)

// Writer defines a simple interface for output operations.
type Writer interface {
	Info(message string, args ...any)
	Success(message string, args ...any)
	Warning(message string, args ...any)
	Error(message string, args ...any)
	Progress(message string, args ...any)
	Debug(message string, args ...any)
	Heading(text string)
	List(text string, args ...any)
	NewLine()
	Bold(text string) string
}

// OutputIface defines the complete interface for output operations.
type OutputIface interface {
	Writer

	// Data output
	Data(logger logger.Logger, message string, data any) error
	DataBatch(items []any) error

	// Configuration
	SetQuiet(quiet bool)
	IsQuiet() bool
	SetNoColor(noColor bool)
	IsNoColor() bool
	SetDebug(debug bool)
	IsDebug() bool
	SetFormat(format string)
	GetFormat() string
	SetDataEnabled(enabled bool)
	IsDataOutputEnabled() bool
	GetDataFormat() string
	IsConfigured() bool

	// Resources
	Close() error
	Writer() io.Writer
}

// Ensure *Output implements the required interfaces.
var (
	_ Writer      = (*Output)(nil)
	_ OutputIface = (*Output)(nil)
)

// JSONMessage represents a structured message for JSON output.
type JSONMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

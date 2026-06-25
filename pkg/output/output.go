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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/thomsonreuters/stamp/pkg/logger"
)

// Output is the main output handler that provides formatted console output.
type Output struct {
	mu sync.RWMutex

	// Configuration
	quiet   bool
	logOnly bool
	debug   bool
	noColor bool
	format  string

	// Writers
	writer    io.Writer
	errWriter io.Writer

	// State
	configured  bool
	dataEnabled bool
}

// Info prints an informational message.
func (o *Output) Info(message string, args ...any) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeInfo, Message: fmt.Sprintf(message, args...)})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	_, _ = fmt.Fprintf(o.writer, message+"\n", args...)
}

// Success prints a success message with green checkmark.
func (o *Output) Success(message string, args ...any) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeSuccess, Message: fmt.Sprintf(message, args...)})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	checkmark := o.colorize(ColorGreen, IconSuccess)
	_, _ = fmt.Fprintf(o.writer, "%s %s\n", checkmark, fmt.Sprintf(message, args...))
}

// Warning prints a warning message with yellow warning icon.
func (o *Output) Warning(message string, args ...any) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeWarning, Message: fmt.Sprintf(message, args...)})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	warningIcon := o.colorize(ColorYellow, IconWarning)
	_, _ = fmt.Fprintf(o.writer, "%s %s\n", warningIcon, fmt.Sprintf(message, args...))
}

// Error prints an error message with red X.
// Note: Error messages are always shown regardless of quiet mode.
func (o *Output) Error(message string, args ...any) {
	if o.isJSONFormat() {
		_ = json.NewEncoder(o.errWriter).Encode(JSONMessage{Type: MsgTypeError, Message: fmt.Sprintf(message, args...)})
		return
	}
	errorIcon := o.colorize(ColorRed, IconError)
	_, _ = fmt.Fprintf(o.errWriter, "%s %s\n", errorIcon, fmt.Sprintf(message, args...))
}

// Progress prints a progress message with blue arrow.
func (o *Output) Progress(message string, args ...any) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeProgress, Message: fmt.Sprintf(message, args...)})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	arrow := o.colorize(ColorBlue, IconProgress)
	_, _ = fmt.Fprintf(o.writer, "%s %s\n", arrow, fmt.Sprintf(message, args...))
}

// Debug prints a debug message (only shown in debug mode).
func (o *Output) Debug(message string, args ...any) {
	o.mu.RLock()
	debug := o.debug
	format := o.format
	o.mu.RUnlock()

	if !debug {
		return
	}

	if format == LogFormatVerbose || format == LogFormatJSON {
		if format == LogFormatJSON {
			_ = o.printJSON(JSONMessage{Type: MsgTypeDebug, Message: fmt.Sprintf(message, args...)})
		}
		return
	}

	debugIcon := o.colorize(ColorYellow, IconDebug)
	_, _ = fmt.Fprintf(o.writer, "%s [DEBUG] %s\n", debugIcon, fmt.Sprintf(message, args...))
}

// Heading prints a formatted heading.
func (o *Output) Heading(text string) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeHeading, Message: text})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	_, _ = fmt.Fprintf(o.writer, "\n%s\n", o.Bold(text))
}

// List prints a bulleted list item.
func (o *Output) List(text string, args ...any) {
	if o.isJSONFormat() {
		_ = o.printJSON(JSONMessage{Type: MsgTypeListItem, Message: fmt.Sprintf(text, args...)})
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	bullet := o.colorize(ColorBlue, IconBullet)
	_, _ = fmt.Fprintf(o.writer, "  %s %s\n", bullet, fmt.Sprintf(text, args...))
}

// NewLine prints an empty line.
func (o *Output) NewLine() {
	if o.isJSONFormat() {
		return
	}
	if !o.shouldShowUserOutput() {
		return
	}
	_, _ = fmt.Fprintln(o.writer)
}

// Bold formats text in bold (if colors are enabled).
func (o *Output) Bold(text string) string {
	if o.IsNoColor() {
		return text
	}
	return ANSIBold + text + ANSIReset
}

// Data outputs data with operation context.
func (o *Output) Data(log logger.Logger, message string, data any) error {
	if !o.IsDataOutputEnabled() {
		return nil
	}

	format := o.GetFormat()

	if format == LogFormatVerbose || format == LogFormatJSON {
		if log != nil {
			log.Info(message, "data", data)
			return nil
		}
	}

	dataFormat := o.GetDataFormat()
	return o.writeDataWithFormat(data, dataFormat)
}

// DataBatch writes multiple data items as a JSON array.
func (o *Output) DataBatch(items []any) error {
	if len(items) == 0 || !o.IsDataOutputEnabled() {
		return nil
	}
	format := o.GetDataFormat()
	return o.writeDataWithFormat(items, format)
}

// SetQuiet enables or disables quiet mode.
func (o *Output) SetQuiet(quiet bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.quiet = quiet
}

// IsQuiet returns whether quiet mode is enabled.
func (o *Output) IsQuiet() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.quiet
}

// SetNoColor enables or disables color output.
func (o *Output) SetNoColor(noColor bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.noColor = noColor
}

// IsNoColor returns whether color output is disabled.
func (o *Output) IsNoColor() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.noColor
}

// SetDebug enables or disables debug mode.
func (o *Output) SetDebug(debug bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.debug = debug
}

// IsDebug returns whether debug mode is enabled.
func (o *Output) IsDebug() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.debug
}

// SetFormat sets the output format.
func (o *Output) SetFormat(f string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.format = f
}

// GetFormat returns the current output format.
func (o *Output) GetFormat() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.format
}

// SetDataEnabled controls whether data output is enabled.
func (o *Output) SetDataEnabled(enabled bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dataEnabled = enabled
}

// IsDataOutputEnabled returns whether data output is enabled.
func (o *Output) IsDataOutputEnabled() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.logOnly {
		return false
	}
	return o.dataEnabled
}

// GetDataFormat returns the data output format.
func (o *Output) GetDataFormat() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return DataFormatJSON
}

// IsConfigured returns whether this Output has been configured.
func (o *Output) IsConfigured() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.configured
}

// Close releases any resources held by the Output.
func (o *Output) Close() error {
	return nil
}

// Writer returns the underlying io.Writer.
func (o *Output) Writer() io.Writer {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.writer
}

func (o *Output) shouldShowUserOutput() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.quiet {
		return false
	}
	if o.format == LogFormatVerbose || o.format == LogFormatJSON {
		return false
	}
	return true
}

func (o *Output) isJSONFormat() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.format == LogFormatJSON
}

func (o *Output) colorize(color ColorCode, text string) string {
	if o.IsNoColor() {
		return text
	}
	return string(color) + text + string(ColorReset)
}

func (o *Output) printJSON(data any) error {
	encoder := json.NewEncoder(o.writer)
	return encoder.Encode(data)
}

func (o *Output) writeDataWithFormat(v any, format string) error {
	switch format {
	case DataFormatJSON:
		enc := json.NewEncoder(o.writer)
		if err := enc.Encode(v); err != nil {
			return fmt.Errorf("%w: %w", ErrEncodeJSON, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
}

func newOutput(opts ...Option) *Output {
	o := &Output{
		quiet:       false,
		logOnly:     false,
		debug:       false,
		noColor:     false,
		format:      LogFormatConsole,
		writer:      os.Stdout,
		errWriter:   os.Stderr,
		dataEnabled: true,
		configured:  true,
	}

	if os.Getenv(EnvNoColor) != "" {
		o.noColor = true
	}
	if IsCI() || !IsTTY() {
		o.noColor = true
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// New creates a new Output instance with the given options.
var New = newOutput

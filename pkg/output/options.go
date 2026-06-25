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

import "io"

// Option is a functional option for configuring Output.
type Option func(*Output)

// WithWriter sets the output writer.
func WithWriter(w io.Writer) Option {
	return func(o *Output) { o.writer = w }
}

// WithErrorWriter sets the error output writer.
func WithErrorWriter(w io.Writer) Option {
	return func(o *Output) { o.errWriter = w }
}

// WithQuiet enables or disables quiet mode.
func WithQuiet(quiet bool) Option {
	return func(o *Output) { o.quiet = quiet }
}

// WithLogOnly enables or disables log-only mode (suppresses data output).
func WithLogOnly(logOnly bool) Option {
	return func(o *Output) { o.logOnly = logOnly }
}

// WithDebug enables or disables debug mode.
func WithDebug(debug bool) Option {
	return func(o *Output) { o.debug = debug }
}

// WithNoColor disables color output.
func WithNoColor(noColor bool) Option {
	return func(o *Output) { o.noColor = noColor }
}

// WithFormat sets the output format (console, verbose, json).
func WithFormat(format string) Option {
	return func(o *Output) { o.format = format }
}

// WithDataEnabled enables or disables data output.
func WithDataEnabled(enabled bool) Option {
	return func(o *Output) { o.dataEnabled = enabled }
}

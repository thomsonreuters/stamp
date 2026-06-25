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

package types

import "slices"

// LogLevel represents the logging level.
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// String returns the string representation of the log level.
func (l LogLevel) String() string {
	return string(l)
}

// LogFormat represents the logging output format.
type LogFormat string

const (
	LogFormatJSON    LogFormat = "json"
	LogFormatConsole LogFormat = "console"
)

// String returns the string representation of the log format.
func (f LogFormat) String() string {
	return string(f)
}

// ValidLogLevels contains all valid log level values.
var ValidLogLevels = []string{
	LogLevelDebug.String(),
	LogLevelInfo.String(),
	LogLevelWarn.String(),
	LogLevelError.String(),
}

// IsValidLogLevel checks if the given value is a valid log level.
func IsValidLogLevel(level string) bool {
	return slices.Contains(ValidLogLevels, level)
}

// ValidLogFormats contains all valid log format values.
var ValidLogFormats = []string{
	LogFormatJSON.String(),
	LogFormatConsole.String(),
}

// IsValidLogFormat checks if the given value is a valid log format.
func IsValidLogFormat(format string) bool {
	return slices.Contains(ValidLogFormats, format)
}

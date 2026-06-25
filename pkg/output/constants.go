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

// Environment variables.
const (
	EnvNoColor = "NO_COLOR"
)

// ANSI escape codes.
const (
	ANSIReset  = "\033[0m"
	ANSIBold   = "\033[1m"
	ANSIRed    = "\033[31m"
	ANSIGreen  = "\033[32m"
	ANSIYellow = "\033[33m"
	ANSIBlue   = "\033[34m"
)

// Icons for terminal output.
const (
	IconSuccess  = "✓"
	IconError    = "✗"
	IconWarning  = "⚠"
	IconProgress = "→"
	IconBullet   = "•"
	IconDebug    = "⚙"
)

// Log format modes.
const (
	LogFormatConsole = "console"
	LogFormatVerbose = "verbose"
	LogFormatJSON    = "json"
)

// Data output formats.
const (
	DataFormatJSON = "json"
)

// Message types for JSON output.
const (
	MsgTypeInfo     = "info"
	MsgTypeSuccess  = "success"
	MsgTypeWarning  = "warning"
	MsgTypeError    = "error"
	MsgTypeProgress = "progress"
	MsgTypeHeading  = "heading"
	MsgTypeListItem = "list_item"
	MsgTypeDebug    = "debug"
)

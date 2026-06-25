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

package logger

import "context"

// Noop provides a no-op logger implementation that discards all log messages.
type Noop struct{}

func NewNoop() Logger {
	return &Noop{}
}

func (n *Noop) Debug(msg string, args ...any)                             {}
func (n *Noop) Info(msg string, args ...any)                              {}
func (n *Noop) Warn(msg string, args ...any)                              {}
func (n *Noop) Error(msg string, args ...any)                             {}
func (n *Noop) DebugContext(ctx context.Context, msg string, args ...any) {}
func (n *Noop) InfoContext(ctx context.Context, msg string, args ...any)  {}
func (n *Noop) WarnContext(ctx context.Context, msg string, args ...any)  {}
func (n *Noop) ErrorContext(ctx context.Context, msg string, args ...any) {}
func (n *Noop) With(args ...any) Logger                                   { return n }
func (n *Noop) WithGroup(name string) Logger                              { return n }

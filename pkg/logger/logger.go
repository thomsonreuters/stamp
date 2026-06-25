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

// Package logger provides a structured logging interface based on slog.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/thomsonreuters/stamp/pkg/types"
)

// Logger defines the interface for logging operations.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	With(args ...any) Logger
	WithGroup(name string) Logger
}

type Config struct {
	Level     types.LogLevel
	Format    types.LogFormat
	Writer    io.Writer
	AddSource bool
}

func DefaultConfig() *Config {
	return &Config{
		Level:     types.LogLevelInfo,
		Format:    types.LogFormatJSON,
		Writer:    os.Stdout,
		AddSource: false,
	}
}

// ParseLogLevel converts a LogLevel to slog.Level.
func ParseLogLevel(level types.LogLevel) slog.Level {
	switch level {
	case types.LogLevelDebug:
		return slog.LevelDebug
	case types.LogLevelInfo:
		return slog.LevelInfo
	case types.LogLevelWarn:
		return slog.LevelWarn
	case types.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type slogLogger struct {
	logger *slog.Logger
}

func New(cfg *Config) Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}

	opts := &slog.HandlerOptions{
		Level:     ParseLogLevel(cfg.Level),
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch cfg.Format {
	case types.LogFormatJSON:
		handler = slog.NewJSONHandler(cfg.Writer, opts)
	case types.LogFormatConsole:
		handler = slog.NewTextHandler(cfg.Writer, opts)
	default:
		handler = slog.NewJSONHandler(cfg.Writer, opts)
	}

	return &slogLogger{
		logger: slog.New(handler),
	}
}

func NewDefault() Logger {
	return New(DefaultConfig())
}

func (l *slogLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

func (l *slogLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

func (l *slogLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

func (l *slogLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

func (l *slogLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

func (l *slogLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

func (l *slogLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

func (l *slogLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{
		logger: l.logger.With(args...),
	}
}

func (l *slogLogger) WithGroup(name string) Logger {
	return &slogLogger{
		logger: l.logger.WithGroup(name),
	}
}

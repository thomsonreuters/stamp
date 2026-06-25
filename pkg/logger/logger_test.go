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

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/types"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, types.LogLevelInfo, cfg.Level)
	assert.Equal(t, types.LogFormatJSON, cfg.Format)
	assert.NotNil(t, cfg.Writer)
	assert.False(t, cfg.AddSource)
}

func TestNewDefault(t *testing.T) {
	logger := NewDefault()
	require.NotNil(t, logger)
	assert.IsType(t, &slogLogger{}, logger)
}

func TestNew_WithNilConfig(t *testing.T) {
	logger := New(nil)
	require.NotNil(t, logger)
	assert.IsType(t, &slogLogger{}, logger)
}

func TestNew_WithCustomConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := &Config{
		Level:     types.LogLevelDebug,
		Format:    types.LogFormatConsole,
		Writer:    buf,
		AddSource: true,
	}
	logger := New(cfg)
	require.NotNil(t, logger)
	assert.IsType(t, &slogLogger{}, logger)
}

func TestNew_AllLevels(t *testing.T) {
	levels := []types.LogLevel{types.LogLevelDebug, types.LogLevelInfo, types.LogLevelWarn, types.LogLevelError}
	for _, level := range levels {
		buf := &bytes.Buffer{}
		cfg := &Config{
			Level:  level,
			Format: types.LogFormatJSON,
			Writer: buf,
		}
		logger := New(cfg)
		require.NotNil(t, logger)
	}
}

func TestLogger_Debug(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelDebug,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Debug("debug message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "DEBUG")
}

func TestLogger_Info(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("info message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "INFO")
}

func TestLogger_Warn(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelWarn,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Warn("warn message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "WARN")
}

func TestLogger_Error(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelError,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Error("error message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "error message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
	assert.Contains(t, output, "ERROR")
}

func TestLogger_DebugContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelDebug,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	ctx := context.Background()
	logger.DebugContext(ctx, "debug message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "DEBUG")
}

func TestLogger_InfoContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	ctx := context.Background()
	logger.InfoContext(ctx, "info message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "INFO")
}

func TestLogger_WarnContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelWarn,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	ctx := context.Background()
	logger.WarnContext(ctx, "warn message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "WARN")
}

func TestLogger_ErrorContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelError,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	ctx := context.Background()
	logger.ErrorContext(ctx, "error message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "error message")
	assert.Contains(t, output, "ERROR")
}

func TestLogger_With(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	childLogger := logger.With("request_id", "123")
	require.NotNil(t, childLogger)
	assert.IsType(t, &slogLogger{}, childLogger)

	childLogger.Info("message")

	output := buf.String()
	assert.Contains(t, output, "message")
	assert.Contains(t, output, "request_id")
	assert.Contains(t, output, "123")
}

func TestLogger_WithGroup(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	groupLogger := logger.WithGroup("http")
	require.NotNil(t, groupLogger)
	assert.IsType(t, &slogLogger{}, groupLogger)

	groupLogger.Info("request", "method", "GET")

	output := buf.String()
	assert.Contains(t, output, "request")
	assert.Contains(t, output, "http")
	assert.Contains(t, output, "method")
}

func TestLogger_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("test message", "key", "value")

	output := buf.String()
	var logEntry map[string]any
	err := json.Unmarshal([]byte(output), &logEntry)
	require.NoError(t, err)
	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value", logEntry["key"])
}

func TestLogger_TextFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatConsole,
		Writer: buf,
	})

	logger.Info("test message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key=value")
}

func TestLogger_LevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		level      types.LogLevel
		logFunc    func(Logger)
		shouldLog  bool
		checkLevel string
	}{
		{
			name:  "Debug logs at Debug level",
			level: types.LogLevelDebug,
			logFunc: func(l Logger) {
				l.Debug("debug")
			},
			shouldLog:  true,
			checkLevel: "DEBUG",
		},
		{
			name:  "Debug does not log at Info level",
			level: types.LogLevelInfo,
			logFunc: func(l Logger) {
				l.Debug("debug")
			},
			shouldLog: false,
		},
		{
			name:  "Info logs at Info level",
			level: types.LogLevelInfo,
			logFunc: func(l Logger) {
				l.Info("info")
			},
			shouldLog:  true,
			checkLevel: "INFO",
		},
		{
			name:  "Info does not log at Warn level",
			level: types.LogLevelWarn,
			logFunc: func(l Logger) {
				l.Info("info")
			},
			shouldLog: false,
		},
		{
			name:  "Warn logs at Warn level",
			level: types.LogLevelWarn,
			logFunc: func(l Logger) {
				l.Warn("warn")
			},
			shouldLog:  true,
			checkLevel: "WARN",
		},
		{
			name:  "Warn does not log at Error level",
			level: types.LogLevelError,
			logFunc: func(l Logger) {
				l.Warn("warn")
			},
			shouldLog: false,
		},
		{
			name:  "Error logs at Error level",
			level: types.LogLevelError,
			logFunc: func(l Logger) {
				l.Error("error")
			},
			shouldLog:  true,
			checkLevel: "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := New(&Config{
				Level:  tt.level,
				Format: types.LogFormatJSON,
				Writer: buf,
			})

			tt.logFunc(logger)

			output := buf.String()
			if tt.shouldLog {
				assert.NotEmpty(t, output)
				if tt.checkLevel != "" {
					assert.Contains(t, output, tt.checkLevel)
				}
			} else {
				assert.Empty(t, output)
			}
		})
	}
}

func TestLogger_AddSource(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:     types.LogLevelInfo,
		Format:    types.LogFormatJSON,
		Writer:    buf,
		AddSource: true,
	})

	logger.Info("test message")

	output := buf.String()
	assert.Contains(t, output, "source")
	assert.Contains(t, output, "logger.go")
}

func TestLogger_MultipleAttributes(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("message",
		"key1", "value1",
		"key2", 123,
		"key3", true,
	)

	output := buf.String()
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "123")
	assert.Contains(t, output, "key3")
	assert.Contains(t, output, "true")
}

func TestLogger_ChainedWith(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger1 := logger.With("key1", "value1")
	logger2 := logger1.With("key2", "value2")
	logger2.Info("message")

	output := buf.String()
	assert.Contains(t, output, "key1")
	assert.Contains(t, output, "value1")
	assert.Contains(t, output, "key2")
	assert.Contains(t, output, "value2")
}

func TestLogger_NilWriter(t *testing.T) {
	cfg := &Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: nil,
	}
	logger := New(cfg)
	require.NotNil(t, logger)
}

func TestLogger_InvalidLevel(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := &Config{
		Level:  types.LogLevel("invalid"),
		Format: types.LogFormatJSON,
		Writer: buf,
	}
	logger := New(cfg)
	require.NotNil(t, logger)

	logger.Info("test")
	output := buf.String()
	assert.NotEmpty(t, output)
}

func TestLogger_InvalidFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := &Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormat("invalid"),
		Writer: buf,
	}
	logger := New(cfg)
	require.NotNil(t, logger)

	logger.Info("test")
	output := buf.String()
	assert.NotEmpty(t, output)
}

type CustomLogger struct{}

func (c *CustomLogger) Debug(msg string, args ...any)                             {}
func (c *CustomLogger) Info(msg string, args ...any)                              {}
func (c *CustomLogger) Warn(msg string, args ...any)                              {}
func (c *CustomLogger) Error(msg string, args ...any)                             {}
func (c *CustomLogger) DebugContext(ctx context.Context, msg string, args ...any) {}
func (c *CustomLogger) InfoContext(ctx context.Context, msg string, args ...any)  {}
func (c *CustomLogger) WarnContext(ctx context.Context, msg string, args ...any)  {}
func (c *CustomLogger) ErrorContext(ctx context.Context, msg string, args ...any) {}
func (c *CustomLogger) With(args ...any) Logger                                   { return c }
func (c *CustomLogger) WithGroup(name string) Logger                              { return c }

func TestCustomLogger_Interface(t *testing.T) {
	var _ Logger = (*CustomLogger)(nil)

	cl := &CustomLogger{}
	assert.Implements(t, (*Logger)(nil), cl)
}

func TestLogger_EmptyMessage(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("")
	output := buf.String()
	assert.NotEmpty(t, output)
}

func TestLogger_NoAttributes(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("message")
	output := buf.String()
	assert.Contains(t, output, "message")
}

func TestLogger_ContextPropagation(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("key"), "value")

	logger.InfoContext(ctx, "message")
	output := buf.String()
	assert.Contains(t, output, "message")
}

func TestLogger_LongMessage(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	longMsg := strings.Repeat("a", 1000)
	logger.Info(longMsg)

	output := buf.String()
	assert.Contains(t, output, longMsg)
}

func TestLogger_SpecialCharacters(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(&Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: buf,
	})

	logger.Info("message", "key", "value with \"quotes\" and \nnewlines")
	output := buf.String()
	assert.NotEmpty(t, output)
}

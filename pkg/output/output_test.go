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
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"github.com/thomsonreuters/stamp/pkg/types"
)

func TestNew(t *testing.T) {
	o := New()
	require.NotNil(t, o)
	assert.True(t, o.IsConfigured())
	assert.Equal(t, LogFormatConsole, o.GetFormat())
}

func TestNew_WithOptions(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(
		WithWriter(buf),
		WithQuiet(true),
		WithDebug(true),
		WithNoColor(true),
	)

	require.NotNil(t, o)
	assert.True(t, o.IsQuiet())
	assert.True(t, o.IsDebug())
	assert.True(t, o.IsNoColor())
}

func TestNewNoop(t *testing.T) {
	o := NewNoop()
	require.NotNil(t, o)
	assert.True(t, o.IsQuiet())
	assert.True(t, o.IsNoColor())
	assert.False(t, o.IsDataOutputEnabled())
	assert.True(t, o.IsConfigured())
}

func TestNewSimple(t *testing.T) {
	buf := &bytes.Buffer{}
	o := NewSimple(buf)
	require.NotNil(t, o)
	assert.True(t, o.IsNoColor())
	assert.True(t, o.IsDataOutputEnabled())
	assert.True(t, o.IsConfigured())
	assert.Equal(t, LogFormatConsole, o.GetFormat())
}

func TestOutput_Info(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Info("test message")
	assert.Contains(t, buf.String(), "test message\n")
}

func TestOutput_Info_WithArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Info("hello %s", "world")
	assert.Contains(t, buf.String(), "hello world\n")
}

func TestOutput_Info_QuietMode(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithQuiet(true))

	o.Info("test message")
	assert.Empty(t, buf.String())
}

func TestOutput_Info_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.Info("test message")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeInfo, msg.Type)
	assert.Equal(t, "test message", msg.Message)
}

func TestOutput_Success(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Success("operation completed")
	output := buf.String()
	assert.Contains(t, output, IconSuccess)
	assert.Contains(t, output, "operation completed")
}

func TestOutput_Success_WithColor(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(false))

	o.Success("operation completed")
	output := buf.String()
	assert.Contains(t, output, ANSIGreen)
	assert.Contains(t, output, ANSIReset)
}

func TestOutput_Success_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.Success("operation completed")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeSuccess, msg.Type)
	assert.Equal(t, "operation completed", msg.Message)
}

func TestOutput_Warning(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Warning("warning message")
	output := buf.String()
	assert.Contains(t, output, IconWarning)
	assert.Contains(t, output, "warning message")
}

func TestOutput_Warning_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.Warning("warning message")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeWarning, msg.Type)
	assert.Equal(t, "warning message", msg.Message)
}

func TestOutput_Error(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithErrorWriter(buf), WithNoColor(true))

	o.Error("error message")
	output := buf.String()
	assert.Contains(t, output, IconError)
	assert.Contains(t, output, "error message")
}

func TestOutput_Error_AlwaysShown(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithErrorWriter(buf), WithQuiet(true), WithNoColor(true))

	// Error should be shown even in quiet mode
	o.Error("error message")
	output := buf.String()
	assert.Contains(t, output, "error message")
}

func TestOutput_Error_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithErrorWriter(buf), WithFormat(LogFormatJSON))

	o.Error("error message")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, msg.Type)
	assert.Equal(t, "error message", msg.Message)
}

func TestOutput_Progress(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Progress("processing...")
	output := buf.String()
	assert.Contains(t, output, IconProgress)
	assert.Contains(t, output, "processing...")
}

func TestOutput_Progress_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.Progress("processing...")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeProgress, msg.Type)
	assert.Equal(t, "processing...", msg.Message)
}

func TestOutput_Debug(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDebug(true), WithNoColor(true))

	o.Debug("debug message")
	output := buf.String()
	assert.Contains(t, output, IconDebug)
	assert.Contains(t, output, "[DEBUG]")
	assert.Contains(t, output, "debug message")
}

func TestOutput_Debug_NotShownWhenDisabled(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDebug(false))

	o.Debug("debug message")
	assert.Empty(t, buf.String())
}

func TestOutput_Debug_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDebug(true), WithFormat(LogFormatJSON))

	o.Debug("debug message")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeDebug, msg.Type)
	assert.Equal(t, "debug message", msg.Message)
}

func TestOutput_Debug_VerboseFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDebug(true), WithFormat(LogFormatVerbose))

	// In verbose mode, debug messages should not produce console output
	o.Debug("debug message")
	assert.Empty(t, buf.String())
}

func TestOutput_Heading(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.Heading("Section Title")
	output := buf.String()
	assert.Contains(t, output, "Section Title")
	assert.True(t, strings.HasPrefix(output, "\n"))
}

func TestOutput_Heading_WithBold(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(false))

	o.Heading("Section Title")
	output := buf.String()
	assert.Contains(t, output, ANSIBold)
	assert.Contains(t, output, ANSIReset)
}

func TestOutput_Heading_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.Heading("Section Title")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHeading, msg.Type)
	assert.Equal(t, "Section Title", msg.Message)
}

func TestOutput_List(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.List("list item")
	output := buf.String()
	assert.Contains(t, output, IconBullet)
	assert.Contains(t, output, "list item")
	assert.True(t, strings.HasPrefix(output, "  "))
}

func TestOutput_List_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.List("list item")

	var msg JSONMessage
	err := json.Unmarshal(buf.Bytes(), &msg)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeListItem, msg.Type)
	assert.Equal(t, "list item", msg.Message)
}

func TestOutput_NewLine(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	o.NewLine()
	assert.Equal(t, "\n", buf.String())
}

func TestOutput_NewLine_QuietMode(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithQuiet(true))

	o.NewLine()
	assert.Empty(t, buf.String())
}

func TestOutput_NewLine_JSONFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatJSON))

	o.NewLine()
	// In JSON format, NewLine should not produce output
	assert.Empty(t, buf.String())
}

func TestOutput_Bold(t *testing.T) {
	o := New(WithNoColor(false))
	result := o.Bold("text")
	assert.Equal(t, ANSIBold+"text"+ANSIReset, result)
}

func TestOutput_Bold_NoColor(t *testing.T) {
	o := New(WithNoColor(true))
	result := o.Bold("text")
	assert.Equal(t, "text", result)
}

func TestOutput_SetQuiet(t *testing.T) {
	o := New()
	assert.False(t, o.IsQuiet())

	o.SetQuiet(true)
	assert.True(t, o.IsQuiet())

	o.SetQuiet(false)
	assert.False(t, o.IsQuiet())
}

func TestOutput_SetNoColor(t *testing.T) {
	o := New(WithNoColor(false))

	o.SetNoColor(true)
	assert.True(t, o.IsNoColor())

	o.SetNoColor(false)
	assert.False(t, o.IsNoColor())
}

func TestOutput_SetDebug(t *testing.T) {
	o := New()
	assert.False(t, o.IsDebug())

	o.SetDebug(true)
	assert.True(t, o.IsDebug())

	o.SetDebug(false)
	assert.False(t, o.IsDebug())
}

func TestOutput_SetFormat(t *testing.T) {
	o := New()
	assert.Equal(t, LogFormatConsole, o.GetFormat())

	o.SetFormat(LogFormatJSON)
	assert.Equal(t, "json", o.GetFormat())

	o.SetFormat(LogFormatVerbose)
	assert.Equal(t, LogFormatVerbose, o.GetFormat())
}

func TestOutput_SetDataEnabled(t *testing.T) {
	o := New()

	o.SetDataEnabled(true)
	assert.True(t, o.IsDataOutputEnabled())

	o.SetDataEnabled(false)
	assert.False(t, o.IsDataOutputEnabled())
}

func TestOutput_IsDataOutputEnabled_LogOnly(t *testing.T) {
	o := New(WithLogOnly(true), WithDataEnabled(true))
	// Even if dataEnabled is true, logOnly should suppress it
	assert.False(t, o.IsDataOutputEnabled())
}

func TestOutput_GetDataFormat(t *testing.T) {
	o := New()
	assert.Equal(t, "json", o.GetDataFormat())
}

func TestOutput_Data(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(true))

	data := map[string]string{"key": "value"}
	err := o.Data(nil, "test", data)
	require.NoError(t, err)

	var result map[string]string
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestOutput_Data_Disabled(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(false))

	data := map[string]string{"key": "value"}
	err := o.Data(nil, "test", data)
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestOutput_Data_WithLogger(t *testing.T) {
	logBuf := &bytes.Buffer{}
	log := logger.New(&logger.Config{
		Level:  types.LogLevelInfo,
		Format: types.LogFormatJSON,
		Writer: logBuf,
	})

	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(true), WithFormat(LogFormatVerbose))

	data := map[string]string{"key": "value"}
	err := o.Data(log, "test message", data)
	require.NoError(t, err)

	// Data should go to logger in verbose mode
	assert.Contains(t, logBuf.String(), "test message")
	// But not to the output writer
	assert.Empty(t, buf.String())
}

// TestOutput_Data_PrettyJSON removed - pretty flag no longer supported

func TestOutput_DataBatch(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(true))

	items := []any{
		map[string]string{"a": "1"},
		map[string]string{"b": "2"},
	}
	err := o.DataBatch(items)
	require.NoError(t, err)

	var result []map[string]string
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestOutput_DataBatch_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(true))

	err := o.DataBatch([]any{})
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestOutput_DataBatch_Disabled(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithDataEnabled(false))

	items := []any{map[string]string{"a": "1"}}
	err := o.DataBatch(items)
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestOutput_Writer(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf))

	assert.Equal(t, buf, o.Writer())
}

func TestOutput_Close(t *testing.T) {
	o := New()
	err := o.Close()
	require.NoError(t, err)
}

func TestOutput_IsConfigured(t *testing.T) {
	o := New()
	assert.True(t, o.IsConfigured())

	o2 := &Output{}
	assert.False(t, o2.IsConfigured())
}

func TestOutput_Colorize(t *testing.T) {
	o := New(WithNoColor(false))
	result := o.colorize(ColorRed, "error")
	assert.Equal(t, string(ColorRed)+"error"+string(ColorReset), result)
}

func TestOutput_Colorize_NoColor(t *testing.T) {
	o := New(WithNoColor(true))
	result := o.colorize(ColorRed, "error")
	assert.Equal(t, "error", result)
}

func TestOutput_WriteDataWithFormat_UnsupportedFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf))

	err := o.writeDataWithFormat("data", "invalid")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
}

func TestOutput_WriteDataWithFormat_EncodeError(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf))

	// Channels cannot be JSON encoded
	data := make(chan int)
	err := o.writeDataWithFormat(data, DataFormatJSON)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEncodeJSON)
}

func TestOutput_VerboseFormat_SuppressesUserOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithFormat(LogFormatVerbose))

	o.Info("test")
	o.Success("test")
	o.Warning("test")
	o.Progress("test")

	// Verbose format should suppress user-facing output
	assert.Empty(t, buf.String())
}

func TestOutput_ThreadSafety(t *testing.T) {
	buf := &bytes.Buffer{}
	o := New(WithWriter(buf), WithNoColor(true))

	done := make(chan bool)
	for i := range 10 {
		go func(n int) {
			for j := range 100 {
				o.Info("message %d-%d", n, j)
				o.SetQuiet(j%2 == 0)
				o.IsQuiet()
				o.SetDebug(j%2 == 0)
				o.IsDebug()
			}
			done <- true
		}(i)
	}

	for range 10 {
		<-done
	}
}

// Ensure interfaces are implemented.
func TestOutput_ImplementsInterfaces(t *testing.T) {
	var _ Writer = (*Output)(nil)
	var _ OutputIface = (*Output)(nil)
	var _ io.Closer = (*Output)(nil)
}

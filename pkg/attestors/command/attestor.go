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

// Package command provides an attestor that captures comprehensive evidence of command execution
// within CI/CD pipelines and deployment workflows.
package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/invopop/jsonschema"
	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/executor"
	"github.com/thomsonreuters/stamp/pkg/intoto"
	"github.com/thomsonreuters/stamp/pkg/logger"
	commandpredicate "github.com/thomsonreuters/stamp/pkg/predicates/command/v1"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

const (
	id          = "command"
	name        = "Command Run Attestor"
	description = "Captures comprehensive evidence of command execution"

	defaultTimeout       = 600      // 10 minutes
	defaultMaxOutputSize = 10485760 // 10MB

	statusSuccess   = "success"
	statusFailure   = "failure"
	statusTimeout   = "timeout"
	statusCancelled = "cancelled"
)

const (
	// MaxOutputSizeLimit is the maximum allowed output size in bytes (100MB).
	MaxOutputSizeLimit = 100 * 1024 * 1024

	// ScriptSummaryThreshold is the line count threshold for showing script summaries.
	ScriptSummaryThreshold = 100
)

// getDefaultShell returns the platform-appropriate default shell.
func getDefaultShell() string {
	if runtime.GOOS == "windows" {
		return "cmd.exe"
	}
	return "/bin/bash"
}

// getShellFlag returns the command flag for the given shell.
func getShellFlag(shell string) string {
	if shell == "cmd.exe" || shell == "cmd" {
		return "/c"
	}
	return "-c"
}

func init() {
	if err := core.RegisterAttestor(func(log logger.Logger) core.Attestor {
		logger := log.With("attestor_id", id)

		return &Attestor{
			logger:        logger,
			executor:      executor.NewOSCommandExecutor(),
			redactRegexps: make([]*regexp.Regexp, 0),
		}
	}); err != nil {
		panic(fmt.Sprintf("failed to register command attestor: %v", err))
	}
}

// Attestor implements the core.Attestor interface for command execution attestation.
type Attestor struct {
	config        Config
	evidence      *CommandEvidence
	logger        logger.Logger
	executor      executor.CommandExecutor
	redactRegexps []*regexp.Regexp
	cmd           executor.Command
	outputBuffers struct {
		stdout *bytes.Buffer
		stderr *bytes.Buffer
	}
}

func (a *Attestor) ID() string {
	return id
}

func (a *Attestor) PredicateURI() string {
	return commandpredicate.PredicateURI
}

func (a *Attestor) Name() string {
	return name
}

func (a *Attestor) Description() string {
	return description
}

func (a *Attestor) ConfigSchema() []core.ConfigField {
	return []core.ConfigField{
		{
			Name:        "command",
			Type:        "string",
			Required:    true,
			Description: "The command to execute and attest",
			Example:     "npm run build",
		},
		{
			Name:        "execution_mode",
			Type:        "string",
			Default:     "shell",
			Required:    false,
			Description: "How to execute: shell (with shell features), direct (no shell), or script (as script file)",
			Example:     "shell",
		},
		{
			Name:        "working_directory",
			Type:        "string",
			Default:     "",
			Required:    false,
			Description: "Directory to execute the command in",
			Example:     "/app/src",
		},
		{
			Name:        "shell",
			Type:        "string",
			Default:     getDefaultShell(),
			Required:    false,
			Description: "Shell interpreter to use (for shell and script modes)",
			Example:     "/bin/bash",
		},
		{
			Name:        "timeout",
			Type:        "int",
			Default:     defaultTimeout,
			Required:    false,
			Description: "Command timeout in seconds",
			Example:     600,
		},
		{
			Name:        "capture_stdout",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Whether to capture stdout",
			Example:     true,
		},
		{
			Name:        "capture_stderr",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Whether to capture stderr",
			Example:     true,
		},
		{
			Name:        "max_output_size",
			Type:        "int",
			Default:     defaultMaxOutputSize,
			Required:    false,
			Description: "Maximum output size in bytes",
			Example:     10485760,
		},
		{
			Name:        "redact_patterns",
			Type:        "[]string",
			Default:     []string{},
			Required:    false,
			Description: "Regex patterns for redacting sensitive data",
			Example:     []string{"password=.*", "token=[A-Za-z0-9]+"},
		},
		{
			Name:        "allowed_exit_codes",
			Type:        "[]string",
			Default:     []string{"0"},
			Required:    false,
			Description: "Exit codes that indicate success",
			Example:     []string{"0", "1", "2"},
		},
		{
			Name:        "fail_on_error",
			Type:        "bool",
			Default:     true,
			Required:    false,
			Description: "Whether to fail attestation on non-zero exit",
			Example:     true,
		},
		{
			Name:        "environment_variables",
			Type:        "map[string]string",
			Default:     nil,
			Required:    false,
			Description: "Additional environment variables to set for the command (use KEY=VALUE format)",
			Example:     map[string]string{"NODE_ENV": "production", "DEBUG": "false"},
		},
	}
}

func (a *Attestor) PreAttest(ctx context.Context, config core.Config) error {
	a.logger.InfoContext(ctx, "initializing command run attestor")

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		a.logger.InfoContext(ctx, "pre-attestation completed", "duration_ms", duration.Milliseconds())
	}()

	a.parseConfig(config)

	if err := a.compileRedactPatterns(); err != nil {
		return pkgerrors.WrapWithContext(err, "command", "pre-attest", "failed to compile redaction patterns")
	}

	if err := a.validateEnvironment(); err != nil {
		return pkgerrors.WrapWithContext(err, "command", "pre-attest", "environment validation failed")
	}

	a.logger.DebugContext(ctx, "pre-attestation setup complete",
		"command", a.config.Command,
		"working_dir", a.config.WorkingDirectory,
		"timeout", a.config.Timeout,
		"capture_output", a.config.CaptureStdout || a.config.CaptureStderr,
	)

	return nil
}

func (a *Attestor) Attest(ctx context.Context, config core.Config) error {
	a.logger.InfoContext(ctx, "starting command execution attestation")

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		a.logger.InfoContext(ctx, "attestation completed",
			"duration_ms", duration.Milliseconds(),
			"status", a.evidence.Execution.Status,
		)
	}()

	a.logger.InfoContext(ctx, "executing command",
		"command", a.sanitizeForLog(a.config.Command),
		"working_dir", a.config.WorkingDirectory,
		"timeout_seconds", a.config.Timeout,
	)

	result, err := a.executeCommand(ctx)
	// Only fail immediately on critical execution errors, not on exit codes
	if err != nil && result == nil {
		return pkgerrors.WrapWithContext(err, "command", "attest", "command execution failed")
	}

	a.evidence = &CommandEvidence{
		Command: a.buildCommandInfo(),
		Execution: commandpredicate.ExecutionInfo{
			StartTime: result.StartTime,
			EndTime:   result.EndTime,
			Duration:  result.Duration.Milliseconds(),
			ExitCode:  result.ExitCode,
			Status:    result.Status,
		},
		Environment: a.captureEnvironment(),
	}

	if a.config.CaptureStdout || a.config.CaptureStderr {
		a.processOutput(result)
	}

	a.captureResourceMetrics()
	a.applyRedaction()

	a.logger.InfoContext(ctx, "command execution completed",
		"exit_code", result.ExitCode,
		"duration_ms", result.Duration.Milliseconds(),
		"status", result.Status,
	)

	// Only fail on disallowed exit codes if fail_on_error is true
	if a.config.FailOnError && !a.isAllowedExitCode(result.ExitCode) {
		return pkgerrors.NewWithContext("command", "attest",
			fmt.Sprintf("command exited with disallowed code %d (allowed: %v)",
				result.ExitCode, a.config.AllowedExitCodes))
	}

	return nil
}

func (a *Attestor) PostAttest(ctx context.Context, config core.Config) error {
	a.logger.InfoContext(ctx, "cleaning up after attestation")

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		a.logger.InfoContext(ctx, "post-attestation cleanup completed", "duration_ms", duration.Milliseconds())
	}()

	// Only attempt to kill the process if it hasn't exited yet
	if process := a.getOSProcess(); process != nil && a.cmd.GetProcessState() == nil {
		if err := process.Kill(); err != nil {
			a.logger.WarnContext(ctx, "failed to kill process", "error", err)
		}
	}

	a.outputBuffers.stdout = nil
	a.outputBuffers.stderr = nil

	for i := range a.redactRegexps {
		a.redactRegexps[i] = nil
	}
	a.redactRegexps = a.redactRegexps[:0]

	a.logger.Debug("cleanup completed successfully")

	return nil
}

func (a *Attestor) GeneratePredicate(config core.Config) (any, error) {
	if a.evidence == nil {
		return nil, pkgerrors.NewWithContext("command", "generate-predicate",
			"no evidence collected - Attest must be called before GeneratePredicate")
	}

	predicate := commandpredicate.Predicate{
		Command:     a.evidence.Command,
		Execution:   a.evidence.Execution,
		Environment: a.evidence.Environment,
		Output:      a.evidence.Output,
		Resources:   a.evidence.Resources,
	}

	return predicate, nil
}

func (a *Attestor) Subjects(config core.Config) []intoto.Subject {
	if a.evidence == nil {
		return []intoto.Subject{}
	}

	commandHash := sha256.Sum256([]byte(a.config.Command))

	subject := intoto.Subject{
		Name: fmt.Sprintf("pkg:generic/command-execution@%s", id),
		Digest: map[string]string{
			"sha256": hex.EncodeToString(commandHash[:]),
		},
	}

	return []intoto.Subject{subject}
}

func (a *Attestor) Schema() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  false,
		RequiredFromJSONSchemaTags: true,
	}

	schema := reflector.Reflect(&commandpredicate.Predicate{})
	schema.Title = "Command Run Attestation"
	schema.Description = "Evidence of command execution in CI/CD pipeline"

	return schema
}

func (a *Attestor) ValidateConfig(config core.Config) error {
	if err := config.Validate(a.ConfigSchema()); err != nil {
		return pkgerrors.WrapWithContext(err, "command", "validate", "schema validation failed")
	}

	command := config.GetString("command", "")
	if command == "" {
		return pkgerrors.NewWithContext("command", "validate", "command is required and cannot be empty")
	}

	executionMode := config.GetString("execution_mode", "shell")
	switch ExecutionMode(executionMode) {
	case ExecutionModeShell, ExecutionModeDirect, ExecutionModeScript, "":
		// valid modes
	default:
		return pkgerrors.NewWithContext("command", "validate",
			fmt.Sprintf("invalid execution_mode '%s', must be one of: shell, direct, script",
				executionMode))
	}

	timeout := config.GetInt("timeout", defaultTimeout)
	if timeout < 1 || timeout > 86400 {
		return pkgerrors.NewWithContext("command", "validate", fmt.Sprintf("timeout must be between 1 and 86400 seconds, got %d", timeout))
	}

	maxOutputSize := config.GetInt64("max_output_size", defaultMaxOutputSize)
	if maxOutputSize < 1024 || maxOutputSize > MaxOutputSizeLimit {
		return pkgerrors.NewWithContext("command", "validate", fmt.Sprintf("max_output_size must be between 1KB and 100MB, got %d", maxOutputSize))
	}

	patterns := config.GetStringSlice("redact_patterns")
	for _, pattern := range patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return pkgerrors.WrapWithContext(err, "command", "validate", fmt.Sprintf("invalid redaction pattern '%s'", pattern))
		}
	}

	workingDir := config.GetString("working_directory", "")
	if workingDir != "" {
		if info, err := os.Stat(workingDir); err != nil {
			return pkgerrors.WrapWithContext(err, "command", "validate", fmt.Sprintf("working directory '%s' does not exist", workingDir))
		} else if !info.IsDir() {
			return pkgerrors.NewWithContext("command", "validate", fmt.Sprintf("working directory '%s' is not a directory", workingDir))
		}
	}

	shell := config.GetString("shell", getDefaultShell())
	if _, err := exec.LookPath(shell); err != nil {
		return pkgerrors.WrapWithContext(err, "command", "validate", fmt.Sprintf("shell '%s' not found in PATH", shell))
	}

	return nil
}

func (a *Attestor) parseConfig(config core.Config) {
	executionModeStr := config.GetString("execution_mode", "shell")
	executionMode := ExecutionModeShell
	if executionModeStr != "" {
		executionMode = ExecutionMode(executionModeStr)
	}

	a.config = Config{
		Command:          config.GetString("command", ""),
		ExecutionMode:    executionMode,
		WorkingDirectory: config.GetString("working_directory", ""),
		Shell:            config.GetString("shell", getDefaultShell()),
		Timeout:          config.GetInt("timeout", defaultTimeout),
		CaptureStdout:    config.GetBool("capture_stdout", true),
		CaptureStderr:    config.GetBool("capture_stderr", true),
		MaxOutputSize:    config.GetInt64("max_output_size", defaultMaxOutputSize),
		RedactPatterns:   config.GetStringSlice("redact_patterns"),
		FailOnError:      config.GetBool("fail_on_error", true),
	}

	a.config.EnvironmentVariables = config.GetMap("environment_variables")

	allowedCodes := config.GetStringSlice("allowed_exit_codes")
	if len(allowedCodes) == 0 {
		a.config.AllowedExitCodes = []int{0}
	} else {
		a.config.AllowedExitCodes = make([]int, 0, len(allowedCodes))
		for _, code := range allowedCodes {
			var exitCode int
			if _, err := fmt.Sscanf(code, "%d", &exitCode); err == nil {
				a.config.AllowedExitCodes = append(a.config.AllowedExitCodes, exitCode)
			}
		}
	}
}

func (a *Attestor) executeCommand(ctx context.Context) (*ExecutionResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(a.config.Timeout)*time.Second)
	defer cancel()

	var cmd executor.Command

	switch a.config.ExecutionMode {
	case ExecutionModeShell, "":
		cmd = a.executor.CommandContext(timeoutCtx, a.config.Shell, getShellFlag(a.config.Shell), a.config.Command)

	case ExecutionModeDirect:
		parts, err := utils.ParseCommand(a.config.Command)
		if err != nil {
			return nil, pkgerrors.WrapWithContext(err, "command", "execute", "failed to parse command")
		}
		if len(parts) == 0 || parts[0] == "" {
			return nil, pkgerrors.NewWithContext("command", "execute", "no command to execute in direct mode")
		}
		cmd = a.executor.CommandContext(timeoutCtx, parts[0], parts[1:]...)

	case ExecutionModeScript:
		scriptFile, scriptErr := os.CreateTemp("", "attestor-script-*.sh")
		if scriptErr != nil {
			return nil, pkgerrors.WrapWithContext(scriptErr, "command", "execute", "failed to create script file")
		}
		defer func() { _ = os.Remove(scriptFile.Name()) }()

		if _, scriptErr = scriptFile.WriteString(a.config.Command); scriptErr != nil {
			_ = scriptFile.Close()
			return nil, pkgerrors.WrapWithContext(scriptErr, "command", "execute", "failed to write script")
		}

		if scriptErr = scriptFile.Close(); scriptErr != nil {
			return nil, pkgerrors.WrapWithContext(scriptErr, "command", "execute", "failed to close script file")
		}

		if scriptErr = os.Chmod(scriptFile.Name(), 0700); scriptErr != nil {
			return nil, pkgerrors.WrapWithContext(scriptErr, "command", "execute", "failed to make script executable")
		}

		cmd = a.executor.CommandContext(timeoutCtx, a.config.Shell, scriptFile.Name())

	default:
		return nil, pkgerrors.NewWithContext("command", "execute", fmt.Sprintf("unsupported execution mode: %s", a.config.ExecutionMode))
	}

	if a.config.WorkingDirectory != "" {
		cmd.SetDir(a.config.WorkingDirectory)
	}

	// Build environment with proper variable override handling
	cmd.SetEnv(utils.BuildEnv(os.Environ(), a.config.EnvironmentVariables))

	a.outputBuffers.stdout = &bytes.Buffer{}
	a.outputBuffers.stderr = &bytes.Buffer{}

	var stdoutWriter, stderrWriter *limitedWriter

	if a.config.CaptureStdout {
		stdoutWriter = &limitedWriter{
			w:     a.outputBuffers.stdout,
			limit: a.config.MaxOutputSize,
		}
		cmd.SetStdout(stdoutWriter)
	}

	if a.config.CaptureStderr {
		stderrWriter = &limitedWriter{
			w:     a.outputBuffers.stderr,
			limit: a.config.MaxOutputSize,
		}
		cmd.SetStderr(stderrWriter)
	}

	a.cmd = cmd
	startTime := time.Now()

	err := cmd.Run()

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	result := &ExecutionResult{
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Stdout:    a.outputBuffers.stdout.Bytes(),
		Stderr:    a.outputBuffers.stderr.Bytes(),
	}

	if stdoutWriter != nil && stdoutWriter.truncated {
		result.Truncated = true
	}
	if stderrWriter != nil && stderrWriter.truncated {
		result.Truncated = true
	}

	if err != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.As(err, &exitErr):
			result.ExitCode = exitErr.ExitCode()
			result.Status = statusFailure
		case errors.Is(timeoutCtx.Err(), context.DeadlineExceeded):
			result.Status = statusTimeout
			result.TimedOut = true
			result.ExitCode = -1
		case errors.Is(timeoutCtx.Err(), context.Canceled):
			result.Status = statusCancelled
			result.ExitCode = -1
		default:
			result.Status = statusFailure
			result.ExitCode = -1
		}
	} else {
		result.ExitCode = 0
		result.Status = statusSuccess
	}

	return result, nil
}

func (a *Attestor) compileRedactPatterns() error {
	defaultPatterns := []string{
		`password=[\S]+`,
		`token=[\S]+`,
		`api[_-]?key=[\S]+`,
		`secret=[\S]+`,
	}

	allPatterns := make([]string, 0, len(defaultPatterns)+len(a.config.RedactPatterns))
	allPatterns = append(allPatterns, defaultPatterns...)
	allPatterns = append(allPatterns, a.config.RedactPatterns...)

	a.redactRegexps = make([]*regexp.Regexp, 0, len(allPatterns))

	for _, pattern := range allPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "command", "compile-patterns", fmt.Sprintf("failed to compile pattern '%s'", pattern))
		}
		a.redactRegexps = append(a.redactRegexps, re)
	}

	return nil
}

func (a *Attestor) validateEnvironment() error {
	if a.config.WorkingDirectory != "" {
		if _, err := os.Stat(a.config.WorkingDirectory); err != nil {
			return pkgerrors.WrapWithContext(err, "command", "validate-environment", "working directory not accessible")
		}
	}

	switch a.config.ExecutionMode {
	case ExecutionModeDirect:
		parts, err := utils.ParseCommand(a.config.Command)
		if err != nil {
			return pkgerrors.WrapWithContext(err, "command", "validate-environment", "failed to parse command")
		}
		if len(parts) == 0 {
			return pkgerrors.NewWithContext("command", "validate-environment", "no executable found in command")
		}

		executable := parts[0]
		if !filepath.IsAbs(executable) {
			if _, lookupErr := exec.LookPath(executable); lookupErr != nil {
				return pkgerrors.WrapWithContext(
					lookupErr,
					"command",
					"validate-environment",
					fmt.Sprintf("executable '%s' not found in PATH", executable),
				)
			}
		} else {
			if _, statErr := os.Stat(executable); statErr != nil {
				return pkgerrors.WrapWithContext(
					statErr,
					"command",
					"validate-environment",
					fmt.Sprintf("executable '%s' not found", executable),
				)
			}
		}

	case ExecutionModeScript, ExecutionModeShell, "":
		if _, err := exec.LookPath(a.config.Shell); err != nil {
			return pkgerrors.WrapWithContext(err, "command", "validate-environment", fmt.Sprintf("shell '%s' not found", a.config.Shell))
		}
	}

	return nil
}

func (a *Attestor) captureEnvironment() commandpredicate.EnvironmentInfo {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()

	workDirectory := a.config.WorkingDirectory
	if workDirectory == "" {
		workDirectory, _ = os.Getwd()
	}

	platformInfo := utils.GetPlatformInfo()
	platform := commandpredicate.PlatformInfo{
		OS:      platformInfo.OS,
		Arch:    platformInfo.Arch,
		Version: platformInfo.Version,
	}

	env := commandpredicate.EnvironmentInfo{
		WorkingDirectory: workDirectory,
		Hostname:         hostname,
		Platform:         platform,
	}

	if currentUser != nil {
		env.User = currentUser.Username
	}

	return env
}

func (a *Attestor) buildCommandInfo() commandpredicate.CommandInfo {
	info := commandpredicate.CommandInfo{
		CommandLine: a.config.Command,
	}

	switch a.config.ExecutionMode {
	case ExecutionModeShell:
		info.Shell = a.config.Shell

	case ExecutionModeDirect:
		parts, err := utils.ParseCommand(a.config.Command)
		if err != nil {
			a.logger.Warn("failed to parse command for command info", "error", err)
		} else if len(parts) > 0 {
			info.Executable = parts[0]
			if len(parts) > 1 {
				info.Arguments = parts[1:]
			}
		}

	case ExecutionModeScript:
		info.Shell = a.config.Shell
		if len(a.config.Command) > ScriptSummaryThreshold {
			// For long scripts, show a summary
			info.CommandLine = fmt.Sprintf("[script: %d lines]", strings.Count(a.config.Command, "\n")+1)
		}
	}

	return info
}

func (a *Attestor) processOutput(result *ExecutionResult) {
	output := &commandpredicate.OutputInfo{
		Size: commandpredicate.OutputSize{
			Stdout: int64(len(result.Stdout)),
			Stderr: int64(len(result.Stderr)),
		},
		Truncated: result.Truncated,
	}

	if a.config.CaptureStdout && len(result.Stdout) > 0 {
		if utf8.Valid(result.Stdout) {
			output.Stdout = string(result.Stdout)
			output.StdoutEncoding = "utf-8"
		} else {
			output.Stdout = base64.StdEncoding.EncodeToString(result.Stdout)
			output.StdoutEncoding = "base64"
		}
		h := sha256.Sum256(result.Stdout)
		output.Digest.Stdout = "sha256:" + hex.EncodeToString(h[:])
	}

	if a.config.CaptureStderr && len(result.Stderr) > 0 {
		if utf8.Valid(result.Stderr) {
			output.Stderr = string(result.Stderr)
			output.StderrEncoding = "utf-8"
		} else {
			output.Stderr = base64.StdEncoding.EncodeToString(result.Stderr)
			output.StderrEncoding = "base64"
		}
		h := sha256.Sum256(result.Stderr)
		output.Digest.Stderr = "sha256:" + hex.EncodeToString(h[:])
	}

	a.evidence.Output = output
}

func (a *Attestor) captureResourceMetrics() {
	a.evidence.Resources = extractResourceMetrics(a.getResourceUsage())
}

func (a *Attestor) applyRedaction() {
	if a.evidence == nil || a.evidence.Output == nil {
		return
	}

	for _, re := range a.redactRegexps {
		if a.evidence.Output.Stdout != "" {
			a.evidence.Output.Stdout = re.ReplaceAllString(a.evidence.Output.Stdout, "[REDACTED]")
		}
		if a.evidence.Output.Stderr != "" {
			a.evidence.Output.Stderr = re.ReplaceAllString(a.evidence.Output.Stderr, "[REDACTED]")
		}
	}

	if a.evidence.Command.CommandLine != "" {
		for _, re := range a.redactRegexps {
			a.evidence.Command.CommandLine = re.ReplaceAllString(a.evidence.Command.CommandLine, "[REDACTED]")
		}
	}
}

func (a *Attestor) isAllowedExitCode(code int) bool {
	return slices.Contains(a.config.AllowedExitCodes, code)
}

func (a *Attestor) sanitizeForLog(value string) string {
	sanitized := value
	for _, re := range a.redactRegexps {
		sanitized = re.ReplaceAllString(sanitized, "[REDACTED]")
	}
	return sanitized
}

func (a *Attestor) getOSProcess() *os.Process {
	if a.cmd == nil {
		return nil
	}

	proc := a.cmd.GetProcess()
	if proc == nil {
		return nil
	}

	process, _ := proc.(*os.Process)
	return process
}

// getResourceUsage safely extracts syscall.Rusage from the process state.
// Returns nil if the command, process state, or usage is not available.
func (a *Attestor) getResourceUsage() *syscall.Rusage {
	if a.cmd == nil {
		return nil
	}

	state := a.cmd.GetProcessState()
	if state == nil {
		return nil
	}

	processState, ok := state.(*os.ProcessState)
	if !ok {
		return nil
	}

	usage, _ := processState.SysUsage().(*syscall.Rusage)
	return usage
}

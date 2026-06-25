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

package executor

import (
	"context"
	"os/exec"
)

// Command represents a command that can be executed.
type Command interface {
	Output() ([]byte, error)
	CombinedOutput() ([]byte, error)
	Run() error
	Start() error
	Wait() error
	StdoutPipe() (any, error)
	StderrPipe() (any, error)
	SetDir(dir string)
	SetEnv(env []string)
	SetStdout(stdout any)
	SetStderr(stderr any)
	GetProcess() any
	GetProcessState() any
}

// CommandExecutor provides an interface for executing commands.
type CommandExecutor interface {
	CommandContext(ctx context.Context, name string, args ...string) Command
}

type OSCommandExecutor struct{}

// CommandContext creates a real os/exec command.
func (e *OSCommandExecutor) CommandContext(ctx context.Context, name string, args ...string) Command {
	return &osCommand{cmd: exec.CommandContext(ctx, name, args...)} //nolint:gosec // executor by design runs commands with caller-provided arguments
}

type osCommand struct {
	cmd *exec.Cmd
}

func (c *osCommand) Output() ([]byte, error) {
	return c.cmd.Output()
}

func (c *osCommand) CombinedOutput() ([]byte, error) {
	return c.cmd.CombinedOutput()
}

func (c *osCommand) Run() error {
	return c.cmd.Run()
}

func (c *osCommand) Start() error {
	return c.cmd.Start()
}

func (c *osCommand) Wait() error {
	return c.cmd.Wait()
}

func (c *osCommand) StdoutPipe() (any, error) {
	return c.cmd.StdoutPipe()
}

func (c *osCommand) StderrPipe() (any, error) {
	return c.cmd.StderrPipe()
}

func (c *osCommand) SetDir(dir string) {
	c.cmd.Dir = dir
}

func (c *osCommand) SetEnv(env []string) {
	c.cmd.Env = env
}

func (c *osCommand) SetStdout(stdout any) {
	if w, ok := stdout.(interface{ Write([]byte) (int, error) }); ok {
		c.cmd.Stdout = w
	}
}

func (c *osCommand) SetStderr(stderr any) {
	if w, ok := stderr.(interface{ Write([]byte) (int, error) }); ok {
		c.cmd.Stderr = w
	}
}

func (c *osCommand) GetProcess() any {
	return c.cmd.Process
}

func (c *osCommand) GetProcessState() any {
	return c.cmd.ProcessState
}

func newOSCommandExecutor() CommandExecutor {
	return &OSCommandExecutor{}
}

var NewOSCommandExecutor = newOSCommandExecutor

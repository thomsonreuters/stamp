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

package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	// MinSecurePasswordLength is the minimum recommended password length for security warnings.
	MinSecurePasswordLength = 8
)

// Sentinel errors for password operations.
var (
	ErrNotTerminal        = errors.New("not running in a terminal")
	ErrEmptyPassword      = errors.New("password cannot be empty")
	ErrPasswordMismatch   = errors.New("passwords do not match")
	ErrPasswordReadFailed = errors.New("failed to read password")
	ErrPasswordFileFailed = errors.New("failed to read password file")
)

type KeyPasswordConfig struct {
	Password      string
	PasswordFile  string
	PromptEnabled bool
	// PromptText overrides the default prompt string. Optional.
	PromptText string
}

// ResolveKeyPassword returns the private-key password using the standard
// precedence: --password > --password-file > --prompt. An empty return
// with no error means "no password" (unencrypted key).
func ResolveKeyPassword(cfg KeyPasswordConfig) (string, error) {
	if cfg.Password != "" {
		return cfg.Password, nil
	}
	if cfg.PasswordFile != "" {
		return ReadPasswordFromFile(cfg.PasswordFile)
	}
	if cfg.PromptEnabled {
		prompt := cfg.PromptText
		if prompt == "" {
			prompt = "Enter password for private key"
		}
		return PromptPassword(prompt)
	}
	return "", nil
}

// ReadPasswordFromFile reads a password from a file and trims whitespace.
func ReadPasswordFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrPasswordFileFailed, path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// PromptPassword prompts for a password with terminal echo disabled.
func PromptPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("%w: cannot prompt for password", ErrNotTerminal)
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPasswordReadFailed, err)
	}

	password := string(passwordBytes)
	if strings.TrimSpace(password) == "" {
		return "", ErrEmptyPassword
	}

	return password, nil
}

// PasswordResult contains the password and any warnings about its strength.
type PasswordResult struct {
	Password string
	Warnings []string
}

// PromptPasswordWithConfirm prompts for a password twice and validates they match.
// Returns a PasswordResult with the password and any warnings (e.g., weak password).
// The caller is responsible for displaying warnings to the user.
func PromptPasswordWithConfirm(prompt string) (*PasswordResult, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("%w: cannot prompt for password", ErrNotTerminal)
	}

	password1, err := PromptPassword(prompt)
	if err != nil {
		return nil, err
	}

	password2, err := PromptPassword("Confirm password")
	if err != nil {
		return nil, err
	}

	if password1 != password2 {
		return nil, ErrPasswordMismatch
	}

	result := &PasswordResult{
		Password: password1,
		Warnings: []string{},
	}

	if len(password1) < MinSecurePasswordLength {
		result.Warnings = append(
			result.Warnings,
			fmt.Sprintf("Password is less than %d characters. Consider using a stronger password.", MinSecurePasswordLength),
		)
	}

	return result, nil
}

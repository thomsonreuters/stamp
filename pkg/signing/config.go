// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package signing

import "errors"

var (
	ErrProviderRequired = errors.New("provider is required")
)

// KeySignerConfig contains configuration for key-based signing.
type KeySignerConfig struct {
	KeyPath         string `json:"key_path"                yaml:"key_path"                mapstructure:"key_path"`
	KeyPassword     string `json:"password,omitempty"      yaml:"password,omitempty"      mapstructure:"password,omitempty"`
	KeyPasswordFile string `json:"password_file,omitempty" yaml:"password_file,omitempty" mapstructure:"password_file,omitempty"`
}

// FulcioSignerConfig contains configuration for Fulcio certificate-based signing.
type FulcioSignerConfig struct {
	FulcioURL        string `json:"fulcio_url"                   yaml:"fulcio_url"                   mapstructure:"fulcio_url"`
	Token            string `json:"token,omitempty"              yaml:"token,omitempty"              mapstructure:"token,omitempty"`
	TokenPath        string `json:"token_path,omitempty"         yaml:"token_path,omitempty"         mapstructure:"token_path,omitempty"`
	UseSpire         bool   `json:"use_spire,omitempty"          yaml:"use_spire,omitempty"          mapstructure:"use_spire,omitempty"`
	SpireAgentSocket string `json:"spire_agent_socket,omitempty" yaml:"spire_agent_socket,omitempty" mapstructure:"spire_agent_socket,omitempty"`
	UseGitHub        bool   `json:"use_github,omitempty"         yaml:"use_github,omitempty"         mapstructure:"use_github,omitempty"`
	Insecure         bool   `json:"insecure,omitempty"           yaml:"insecure,omitempty"           mapstructure:"insecure,omitempty"`
}

// SignerConfig holds configuration for attestation signing operations.
// It supports both file-based and certificate-based signing methods.
type SignerConfig struct {
	Provider string              `json:"backend"          yaml:"backend"          mapstructure:"backend"`
	Key      *KeySignerConfig    `json:"key,omitempty"    yaml:"key,omitempty"    mapstructure:"key,omitempty"`
	Fulcio   *FulcioSignerConfig `json:"fulcio,omitempty" yaml:"fulcio,omitempty" mapstructure:"fulcio,omitempty"`
}

func (c *SignerConfig) Validate() error {
	if c.Provider == "" {
		return ErrProviderRequired
	}

	return nil
}

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

package jwt

import (
	"crypto"
	"time"
)

type TokenInfo struct {
	Header Header
	Claims Claims
}

func (t *TokenInfo) Validate() error {
	if t.Header.Algorithm == "" {
		return ErrInvalidHeader
	}
	return nil
}

type Header struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ,omitempty"`
	KeyID     string   `json:"kid,omitempty"`
	X5C       []string `json:"x5c,omitempty"`
	X5T       string   `json:"x5t,omitempty"`
	X5TS256   string   `json:"x5t#S256,omitempty"`
}

type Claims struct {
	Issuer       string         `json:"iss,omitempty"`
	Subject      string         `json:"sub,omitempty"`
	Audience     any            `json:"aud,omitempty"`
	ExpiresAt    int64          `json:"exp,omitempty"`
	NotBefore    int64          `json:"nbf,omitempty"`
	IssuedAt     int64          `json:"iat,omitempty"`
	JWTID        string         `json:"jti,omitempty"`
	CustomClaims map[string]any `json:"-"`
}

func (c *Claims) IsExpired() bool {
	return c.ExpiresAt != 0 && time.Now().Unix() > c.ExpiresAt
}

func (c *Claims) IsNotYetValid() bool {
	return c.NotBefore != 0 && time.Now().Unix() < c.NotBefore
}

type VerificationResult struct {
	Verified     bool
	Method       string
	Source       string
	DiscoveryURL string
	VerifiedAt   time.Time
	KeyID        string
	Algorithm    string
	Error        error
}

type KeyInfo struct {
	Method       string           `json:"method"`
	Source       string           `json:"source"`
	DiscoveryURL string           `json:"discovery_url,omitempty"`
	KeyID        string           `json:"key_id,omitempty"`
	Algorithm    string           `json:"algorithm,omitempty"`
	VerifiedAt   time.Time        `json:"verified_at"`
	PublicKey    crypto.PublicKey `json:"-"`
}

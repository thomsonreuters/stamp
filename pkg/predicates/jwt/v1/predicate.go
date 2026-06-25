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

// Package v1 provides version 1 predicate definitions for JWT token attestations.
package v1

import (
	"time"
)

const (
	// PredicateURI is the custom predicate type URI for JWT token attestations.
	// Following in-toto specification for custom predicate types.
	PredicateURI = "https://witness.dev/attestations/jwt/v0.1"
)

type Predicate struct {
	Source       string    `json:"source"`
	Digest       string    `json:"digest"`
	Header       JWTHeader `json:"header"`
	Claims       JWTClaims `json:"claims"`
	Verification string    `json:"verification"`
	Key          *Key      `json:"key,omitempty"`
}

type Key struct {
	Method       string    `json:"method"`
	Source       string    `json:"source"`
	DiscoveryURL string    `json:"discovery_url,omitempty"`
	VerifiedAt   time.Time `json:"verified_at"`
}

type JWTHeader struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	KeyID     string   `json:"kid,omitempty"`
	X5C       []string `json:"x5c,omitempty"`
	X5T       string   `json:"x5t,omitempty"`
	X5TS256   string   `json:"x5t#S256,omitempty"`
}

type JWTClaims struct {
	Issuer       string         `json:"iss,omitempty"`
	Subject      string         `json:"sub,omitempty"`
	Audience     any            `json:"aud,omitempty"`
	ExpiresAt    int64          `json:"exp,omitempty"`
	NotBefore    int64          `json:"nbf,omitempty"`
	IssuedAt     int64          `json:"iat,omitempty"`
	JWTID        string         `json:"jti,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
}

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

package v1

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/thomsonreuters/stamp/pkg/intoto"
)

// BypassActorUser is the canonical actor kind for an individually identified
// user; other actor kinds are conservatively classified as broad.
const BypassActorUser = "user"

var (
	ErrIncompleteControls = errors.New("source-onboarding: control evidence is incomplete")
	ErrInvalidCommit      = errors.New("source-onboarding: invalid branch-tip gitCommit digest")
	ErrTierMismatch       = errors.New("source-onboarding: predicate tier does not match observed controls")
)

// ObservedControls is a complete, single-observation snapshot of branch controls.
type ObservedControls struct {
	RequiredApprovals       int
	RequiresCodeownerReview bool
	LinearHistory           bool
	DismissStaleApprovals   bool
	RestrictsForcePush      bool
	BypassActors            []BypassActor
	EvidenceComplete        bool
}

// DeriveTier classifies a complete control snapshot. Explicit individual user
// bypass actors are narrow; group, role, organization, and unknown actor kinds
// are conservatively considered broad.
func DeriveTier(controls ObservedControls) (string, error) {
	if !controls.EvidenceComplete || controls.BypassActors == nil {
		return "", ErrIncompleteControls
	}
	if controls.RequiredApprovals < 0 {
		return "", errors.New("source-onboarding: requiredApprovals must be non-negative")
	}
	for i, actor := range controls.BypassActors {
		if strings.TrimSpace(actor.ActorType) == "" || strings.TrimSpace(actor.ActorID) == "" {
			return "", fmt.Errorf("source-onboarding: bypass actor %d must include actor type and ID", i)
		}
		if err := validateStringList(actor.BypassModes); err != nil {
			return "", fmt.Errorf("source-onboarding: bypass actor %d modes: %w", i, err)
		}
		if err := validateStringList(actor.BypassScopes); err != nil {
			return "", fmt.Errorf("source-onboarding: bypass actor %d scopes: %w", i, err)
		}
	}

	if controls.RequiredApprovals == 0 {
		return Untiered, nil
	}
	if controls.RequiredApprovals >= 2 &&
		controls.RequiresCodeownerReview &&
		controls.LinearHistory &&
		controls.DismissStaleApprovals &&
		controls.RestrictsForcePush &&
		!hasBroadBypassActor(controls.BypassActors) {
		return Tier1Protected, nil
	}
	return Tier2, nil
}

// BuildStatement binds the predicate to the observed branch-tip commit and
// emits the source-onboarding in-toto statement.
func BuildStatement(predicate Predicate, branchTipCommit string) (*intoto.Statement, error) {
	if err := predicate.Validate(); err != nil {
		return nil, fmt.Errorf("source-onboarding: invalid predicate: %w", err)
	}
	if !validGitCommitDigest(branchTipCommit) {
		return nil, ErrInvalidCommit
	}
	derivedTier, err := DeriveTier(ObservedControls{
		RequiredApprovals:       predicate.RequiredApprovals,
		RequiresCodeownerReview: predicate.RequiresCodeownerReview,
		LinearHistory:           predicate.LinearHistory,
		DismissStaleApprovals:   predicate.DismissStaleApprovals,
		RestrictsForcePush:      predicate.RestrictsForcePush,
		BypassActors:            predicate.BypassActors,
		EvidenceComplete:        true,
	})
	if err != nil {
		return nil, err
	}
	if predicate.Tier != derivedTier {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrTierMismatch, predicate.Tier, derivedTier)
	}

	subject := intoto.Subject{
		Name:   predicate.Repository + "@" + predicate.Branch,
		Digest: map[string]string{"gitCommit": branchTipCommit},
	}
	statement, err := intoto.NewStatement(PredicateURI, predicate, []intoto.Subject{subject})
	if err != nil {
		return nil, fmt.Errorf("source-onboarding: create statement: %w", err)
	}
	return statement, nil
}

func hasBroadBypassActor(actors []BypassActor) bool {
	for _, actor := range actors {
		if strings.ToLower(strings.TrimSpace(actor.ActorType)) != BypassActorUser {
			return true
		}
	}
	return false
}

func validGitCommitDigest(digest string) bool {
	if len(digest) != 40 && len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

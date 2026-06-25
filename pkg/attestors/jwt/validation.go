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
	"fmt"
	"os"
	"slices"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
	"github.com/thomsonreuters/stamp/pkg/utils"
)

func (a *Attestor) validateTokenSource() error {
	count := 0

	if a.config.TokenFile != "" {
		count++
	}
	if a.config.FromStdin {
		count++
	}
	if a.config.FromEnv != "" {
		count++
	}
	if a.config.AutoDiscoverGitHub {
		count++
	}
	if a.config.AutoDiscoverAWS {
		count++
	}
	if a.config.AutoDiscoverK8s {
		count++
	}

	switch count {
	case 0:
		return ErrNoTokenSource
	case 1:
		return nil
	default:
		return ErrMultipleTokenSources
	}
}

func (a *Attestor) validateFilePaths() error {
	paths := map[string]string{
		"jwt-token-file":      a.config.TokenFile,
		"jwt-public-key-file": a.config.PublicKeyFile,
		"jwt-ca-cert":         a.config.CACert,
	}

	for name, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return pkgerrors.WrapWithContext(err, attestorID, "validate",
				fmt.Sprintf("%s '%s' does not exist or is not accessible", name, path))
		}
	}

	return nil
}

func (a *Attestor) validateAlgorithms() error {
	allowed := a.config.AllowedAlgorithms
	denied := a.config.DeniedAlgorithms

	if len(allowed) == 0 && len(denied) == 0 {
		return nil
	}

	validate := func(algorithms []string, listName string) error {
		for _, alg := range algorithms {
			if !slices.Contains(ValidAlgorithms, alg) {
				return pkgerrors.WrapWithContext(ErrUnsupportedAlgorithm, attestorID, "validate",
					fmt.Sprintf("invalid algorithm '%s' in %s", alg, listName))
			}
		}
		return nil
	}

	if err := validate(allowed, "jwt-allowed-algorithms"); err != nil {
		return err
	}
	if err := validate(denied, "jwt-denied-algorithms"); err != nil {
		return err
	}

	if conflicts := utils.SliceIntersect(allowed, denied); len(conflicts) > 0 {
		return pkgerrors.NewWithContext(attestorID, "validate",
			fmt.Sprintf("algorithms in both allow and deny lists: %v", conflicts))
	}

	return nil
}

func (a *Attestor) validateClaimsFiltering() error {
	allowlist := a.config.ClaimsAllowlist
	denylist := a.config.ClaimsDenylist
	redactList := a.config.RedactClaims

	if len(allowlist) > 0 && len(denylist) > 0 {
		return pkgerrors.NewWithContext(attestorID, "validate",
			"cannot specify both jwt-claims-allowlist and jwt-claims-denylist")
	}

	if len(allowlist) > 0 && a.config.IncludeAllClaims {
		a.logger.Warn("jwt-claims-allowlist specified with jwt-include-all-claims=true")
	}

	warnStandardClaims := func(claims []string, listName string) {
		for _, claim := range claims {
			if slices.Contains(StandardClaims, claim) {
				a.logger.Warn(
					"standard claim in "+listName+" has no effect — standard claims (sub, iss, aud, exp, iat, nbf, jti) are always included as structured predicate fields and cannot be filtered",
					"claim",
					claim,
					"list",
					listName,
				)
			}
		}
	}
	warnStandardClaims(allowlist, "jwt-claims-allowlist")
	warnStandardClaims(denylist, "jwt-claims-denylist")

	for _, claim := range utils.SliceIntersect(redactList, allowlist) {
		a.logger.Warn("claim in both allowlist and redact list", "claim", claim)
	}
	for _, claim := range utils.SliceIntersect(redactList, denylist) {
		a.logger.Warn("claim in both denylist and redact list", "claim", claim)
	}

	return nil
}

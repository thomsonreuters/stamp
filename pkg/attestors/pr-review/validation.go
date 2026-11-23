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

package prreview

import (
	"net/url"

	"github.com/thomsonreuters/stamp/pkg/core"
	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// ValidateConfig validates the attestor configuration against the schema and business rules.
func (a *Attestor) ValidateConfig(config core.Config) error {
	if err := config.Validate(a.ConfigSchema()); err != nil {
		return err
	}

	a.parseConfig(config)

	v := pkgerrors.NewValidatorFor(id)
	if !repositoryPattern.MatchString(a.config.Repository) {
		v.AddError(configRepository, "must be in owner/name form")
	}
	if a.config.PullRequest <= 0 {
		v.AddError(configPullRequest, "must be a positive integer")
	}
	if u, err := url.Parse(a.config.APIURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		v.AddError(configAPIURL, "must be an https URL without credentials")
	}
	if !envNamePattern.MatchString(a.config.TokenEnv) {
		v.AddError(configTokenEnv, "must be a valid environment variable name")
	}
	if v.HasErrors() {
		return v
	}
	return nil
}

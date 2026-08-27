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

package flags

// =============================================================================
// CONFIGURATION KEY CONSTANTS
// =============================================================================
//
// Organized by functional domain (not by command).

// ============================================================================
// LOGGING CONFIGURATION
// ============================================================================

const (
	// LogLevel specifies logging level: "debug", "info", "warn", "error".
	LogLevel = "log.level"

	// LogFormat specifies log format: "console" or "json".
	// "console" - human-readable text logs.
	// "json" - JSON structured logs (machine-parseable).
	LogFormat = "log.format"

	// LogFile specifies log file path for file output.
	LogFile = "log.file"
)

// ============================================================================
// GENERAL APPLICATION SETTINGS
// ============================================================================

const (
	// Quiet suppresses all logs and user messages, showing only data output.
	Quiet = "settings.quiet"

	// LogOnly suppresses data output, showing only logs and user messages.
	LogOnly = "settings.log_only"

	// Debug enables debug mode.
	Debug = "settings.debug"

	// NoColor disables colored output.
	NoColor = "settings.no_color"

	// Insecure allows insecure connections globally (skip TLS verification).
	Insecure = "settings.insecure"
)

// ============================================================================
// RETRY AND TIMEOUT CONFIGURATION
// ============================================================================

const (
	// MaxRetries specifies maximum retry attempts.
	MaxRetries = "settings.max_retries"

	// RetryDelay specifies initial retry delay duration.
	RetryDelay = "settings.retry_delay"

	// MaxDelay specifies maximum retry delay duration.
	MaxDelay = "settings.max_delay"

	// Timeout specifies operation timeout duration.
	Timeout = "settings.timeout"
)

// ============================================================================
// PARALLEL EXECUTION CONFIGURATION
// ============================================================================

const (
	// Parallel enables parallel execution where applicable.
	Parallel = "settings.parallel"
)

// ============================================================================
// OUTPUT CONFIGURATION
// ============================================================================

const (
	// OutputMode specifies output mode: "individual", "collection", "both".
	OutputMode = "output.mode"
)

// ============================================================================
// SIGNING CONFIGURATION
// ============================================================================

const (
	// Signer defines the signing method: "key" (local keys) or "fulcio" (keyless).
	Signer = "pipeline.signing.signer"

	// FulcioURL specifies the Fulcio certificate authority server URL.
	FulcioURL = "pipeline.signing.fulcio_url"

	// OIDCToken specifies the OIDC token string to use when requesting a certificate to Fulcio.
	OIDCToken = "pipeline.signing.oidc_token"

	// OIDCTokenFile specifies the file containing OIDC token.
	OIDCTokenFile = "pipeline.signing.oidc_token_file"

	// UseSpire enables the use of the SPIRE workload API for OIDC token acquisition.
	UseSpire = "pipeline.signing.use_spire"

	// SPIRESocket specifies custom SPIRE agent socket path.
	SPIRESocket = "pipeline.signing.spire_socket"

	// UseGitHub enables GitHub Actions OIDC token acquisition.
	UseGitHub = "pipeline.signing.use_github"
)

// ============================================================================
// KEY PASSWORD CONFIGURATION
// ============================================================================

const (
	// CryptographyKeyPassword provides password for encrypting private key.
	CryptographyKeyPassword = "cryptography.key.password" //nolint:gosec // Configuration key, not a credential.

	// CryptographyKeyPasswordFile specifies file containing password for encrypted private key.
	CryptographyKeyPasswordFile = "cryptography.key.password_file" //nolint:gosec // Configuration key, not a credential.

	// CryptographyKeyPasswordPrompt enables interactive password prompt for encrypted private key.
	CryptographyKeyPasswordPrompt = "cryptography.key.password_prompt" //nolint:gosec // Configuration key, not a credential.
)

// ============================================================================
// KEY FILE CONFIGURATION
// ============================================================================

const (
	// PrivateKey specifies the private key file path.
	PrivateKey = "cryptography.key.private_key"

	// PublicKey specifies the public key file path.
	PublicKey = "cryptography.key.public_key"
)

// ============================================================================
// TRANSPARENCY LOG CONFIGURATION (REKOR)
// ============================================================================

const (
	// TransparencyEnable controls Rekor transparency log usage.
	TransparencyEnable = "pipeline.rekor.enable"

	// RekorURL specifies the Rekor transparency log server URL.
	RekorURL = "pipeline.rekor.url"

	// RekorUploadTarget specifies what to upload: "individual", "collection", "both".
	RekorUploadTarget = "pipeline.rekor.upload_target"

	// RekorTemporalPolicy specifies temporal validation policy: "strict" (fail), "warn", "ignore".
	RekorTemporalPolicy = "pipeline.rekor.temporal_policy"

	// RekorVersion specifies the Rekor API version to speak: 1 (default) or 2.
	RekorVersion = "pipeline.rekor.version"
)

// ============================================================================
// TIMESTAMP AUTHORITY (TSA) CONFIGURATION
// ============================================================================

const (
	// TSAURL specifies the RFC 3161 Timestamp Authority server URL. Required
	// when using Rekor v2 because integrated_time is always 0 in v2 entries.
	TSAURL = "pipeline.tsa.url"
)

// ============================================================================
// TRUST CONFIGURATION
// ============================================================================

const (
	TrustedRootPath   = "pipeline.trust.trusted_root"
	TUFURL            = "pipeline.trust.tuf.url"
	TUFRootPath       = "pipeline.trust.tuf.root"
	TUFRootChecksum   = "pipeline.trust.tuf.root_checksum"
	FulcioCertChain   = "pipeline.trust.fulcio.cert_chain"
	RekorPublicKey    = "pipeline.trust.rekor.public_key"
	TSACertChain      = "pipeline.trust.tsa.cert_chain"
	SigningConfigPath = "pipeline.trust.signing_config.path"
	UseSigningConfig  = "pipeline.trust.signing_config.use"
)

// ============================================================================
// PIPELINE SETTINGS
// ============================================================================

const (
	// PipelineFailurePolicy specifies failure handling for workflows.
	PipelineFailurePolicy = "pipeline.settings.failure_policy"
)

// ============================================================================
// RETRY POLICY CONFIGURATION
// ============================================================================

const (
	// RetryDefault specifies default retry policy configuration.
	RetryDefault = "pipeline.retry.default"

	// RetrySigning specifies signing-specific retry policy.
	RetrySigning = "pipeline.retry.signing"

	// RetryRekor specifies Rekor-specific retry policy.
	RetryRekor = "pipeline.retry.rekor"
)

// ============================================================================
// WORKFLOWS CONFIGURATION
// ============================================================================

const (
	// Workflows specifies the workflows section in config files.
	Workflows = "workflows"
)

// ============================================================================
// RUN COMMAND CONFIGURATION
// ============================================================================

const (
	// RunAttestor specifies single attestor type to execute.
	RunAttestor = "commands.run.attestor"

	// RunWorkflow specifies workflow name to execute from config file.
	RunWorkflow = "commands.run.workflow"

	// RunTemplate specifies file path template when using --persist flag.
	RunTemplate = "commands.run.template"

	// RunPersist enables writing attestations to files in addition to stdout.
	RunPersist = "commands.run.persist"

	// RunForce enables overwriting existing files when using --persist.
	RunForce = "commands.run.force"

	// RunSet specifies attestor configuration overrides (key=value pairs).
	RunSet = "commands.run.set"

	// RunAll selects all workflows for execution.
	RunAll = "commands.run.all"

	// RunTags filters workflows by tags.
	RunTags = "commands.run.tags"

	// RunInclude includes workflows matching glob pattern.
	RunInclude = "commands.run.include"

	// RunExclude excludes workflows matching glob pattern.
	RunExclude = "commands.run.exclude"

	// RunContinueOnError continues execution on errors.
	RunContinueOnError = "commands.run.continue_on_error"
)

// ============================================================================
// LIST COMMAND CONFIGURATION
// ============================================================================

const (
	// ListShowConfig shows detailed configuration schema for attestors.
	ListShowConfig = "commands.list.show_config"
)

// ============================================================================
// FETCH COMMAND CONFIGURATION
// ============================================================================

const (
	// FetchFile specifies path to attestation file.
	FetchFile = "commands.fetch.file"

	// FetchUUID specifies Rekor entry UUID.
	FetchUUID = "commands.fetch.uuid"

	// FetchLogIndex specifies Rekor log index.
	FetchLogIndex = "commands.fetch.log_index"

	// FetchRaw outputs raw Rekor API response instead of processed format.
	FetchRaw = "commands.fetch.raw"

	// FetchOutputFile saves fetched entry to JSON file.
	FetchOutputFile = "commands.fetch.output_file"
)

// ============================================================================
// GENERATE-KEY COMMAND CONFIGURATION
// ============================================================================

const (
	// GenerateKeyType specifies key type for generation.
	GenerateKeyType = "commands.generatekey.type"

	// GenerateKeyOutput specifies output path for generated keys.
	GenerateKeyOutput = "commands.generatekey.output"

	// GenerateKeyOverwrite allows overwriting existing key files.
	GenerateKeyOverwrite = "commands.generatekey.overwrite"
)

// ============================================================================
// VERIFY COMMAND CONFIGURATION
// ============================================================================

const (
	// VerifyOutputFile saves detailed verification result to JSON file.
	VerifyOutputFile = "commands.verify.output_file"

	// VerifyExpectedSAN is the exact SubjectAlternativeName the signing
	// certificate must match.
	VerifyExpectedSAN = "commands.verify.expected_san"

	// VerifyExpectedSANRegex is a regexp the signing certificate SAN must
	// match.
	VerifyExpectedSANRegex = "commands.verify.expected_san_regex"

	// VerifyExpectedIssuer is the exact OIDC issuer the signing certificate
	// must carry.
	VerifyExpectedIssuer = "commands.verify.expected_issuer"

	// VerifyExpectedIssuerRegex is a regexp the signing certificate OIDC
	// issuer must match.
	VerifyExpectedIssuerRegex = "commands.verify.expected_issuer_regex"

	// VerifyAllowUnverifiedIdentity skips identity checks (unsafe).
	VerifyAllowUnverifiedIdentity = "commands.verify.allow_unverified_identity"

	// VerifyPublicKey is the PEM path of the public key used to verify a key-signed bundle.
	VerifyPublicKey = "commands.verify.public_key"
)

// ============================================================================
// UPLOAD COMMAND CONFIGURATION
// ============================================================================

const (
	// UploadPublicKey specifies path to public key file.
	UploadPublicKey = "commands.upload.public_key"
)

// ============================================================================
// CONTAINER SIGN COMMAND CONFIGURATION
// ============================================================================

const (
	// ContainerSignOutput specifies path for the sigstore Bundle v0.3 JSON
	// output. Empty means write to stdout.
	ContainerSignOutput = "commands.container.sign.output"

	// ContainerSignOverwrite allows overwriting an existing bundle file
	// at ContainerSignOutput. Ignored when writing to stdout.
	ContainerSignOverwrite = "commands.container.sign.overwrite"
)

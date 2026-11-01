# Policy Engine: Architecture, governance, and integration

**Version:** 1.0\
**Date:** October 2026\
**Authors:** ISRM Product Security

**Scope.** This paper defines the architecture, governance model, and integration patterns for an open-source policy engine that validates `in-toto` attestations across the software development lifecycle (SDLC). It covers the policy and profile model, the attestation discovery and linking algorithm, the evaluation pipeline, distribution via OCI registries, the credential model, and the three deployment modes — a developer/CI-CD CLI, a central evaluation server with a REST API, and a Kubernetes admission webhook.

**Out of scope.** This paper does not define the producers of attestations (build systems, scanners, signing services), the PKI underlying signature verification, the storage backends in any specific technology, or the deployment pipelines for the engine itself. It also does not define a formal threat model. That is a companion document. The source-side (GitHub) attestation architecture — four-eye review chains, checkpoint VSAs, fleet onboarding, and the exception/break-glass model — is specified in the companion paper *GitHub Source Attestations: Verified Review and Promotion Chains*. Examples occasionally reference Thomson Reuters–specific deployment artefacts (registry hostname, ownership identifiers, identity portal). These are clearly labelled and are not part of the engine's contract. Open-source adopters MUST be able to run, extend, and govern the engine without reproducing any TR-specific component.

---

## 1. Executive summary and problem statement

A modern software supply chain produces evidence at every step. A pull request is reviewed by two engineers. The build emits an SLSA Provenance recording how the artefact was constructed and from which source commit. An SBOM enumerates the transitive components. A vulnerability scanner annotates the SBOM with severities. An image signer records who attested the binary. A deployment pipeline records into which environment the artefact was rolled. Every one of these steps can produce an `in-toto` attestation — a structured, signed statement about an immutable artefact.

The value of these attestations is not in their existence. Their value is in being **automatically and authoritatively verified** before each gate in the SDLC: before a pull request merges, before a container image is promoted from staging to production, before a deployment is admitted to a Kubernetes cluster. Without that verification step, attestations are evidence that is collected and never read.

This paper specifies the design of a **policy engine** that closes that gap. It evaluates `in-toto` attestations against a versioned, code-reviewed corpus of policies authored by platform security teams, business-unit security teams, and product teams. It enforces those policies at three points in the SDLC: in CI/CD pipelines (via a CLI), at admission time on Kubernetes clusters (via a validating webhook), and behind a stable REST API for any other consumer. All three modes share a single evaluation core: the same policy YAML, the same Rego rules, the same attestation discovery logic.

The architectural commitments documented in this paper are deliberate and load-bearing. They include:

- **Subject-digest as the canonical key.** Attestations are linked to artefacts and source commits by their cryptographic digest, not by an organization-specific identifier. The engine walks the in-toto subject graph, using SLSA Provenance's `resolvedDependencies` as the bridge between source-stage and build-stage attestations.
- **Profile composition as the only mechanism for policy customization.** Profiles either compose other profiles or list policies directly — never both. Parameter customization is achieved by authoring a downstream profile, not by a sidecar configuration object. The composition tree is capped at three levels.
- **OCI as the distribution substrate.** Policies are published as OCI artefacts and assembled into a single global bundle. Sources are pluggable so that non-Git origins can be added without architectural change.
- **A platform-agnostic credential model.** The engine reads file-mounted credentials (preferred) or environment variables (fallback). It does not manage rotation, scoping, or storage of secrets — that is the deployment platform's responsibility. The central server is the single egress point for credentialed reads of external data.
- **Fail-closed by default.** When evaluation cannot complete deterministically — missing required evidence, unreachable external dependency, signature failure — the engine denies. The Kubernetes admission mode additionally treats any Rego panic as a denial, regardless of the authored `panic` value.
- **REST as the default surface.** Every external API is exposed as REST first. A surface MAY use gRPC only if it can justify the choice on streaming, per-RPC efficiency, or generated-client grounds. No surface in v1 meets that bar.

The result is an engine that an open-source community can adopt without inheriting any single organization's SDLC vocabulary, and that a regulated enterprise can deploy with the governance guarantees auditors expect.

---

## 2. Educational primer

This section grounds non-expert readers. Reviewers familiar with `in-toto`, SLSA, and OPA/Rego may skim it. The terminology established here is used normatively in subsequent sections.

### 2.1 `in-toto` attestations and Sigstore bundles

An `in-toto` attestation is a structured statement that some attester *X* observed some property *P* about a software artefact *A*. The `in-toto` Attestation Framework v1 specifies the wrapper:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "myapp", "digest": { "sha256": "a3f8…" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": { "buildDefinition": { } }
}
```

The **subject** is a list of `ResourceDescriptor` objects. Each subject is an immutable artefact identified by a cryptographic digest — typically `sha256` for binaries and container images, or `gitCommit` for source-stage statements. Subjects may also carry a name, a URI, and other locators, but the digest is what makes them reliably identifiable.

The **predicate** is the attester's claim. Its shape is defined by the **predicateType** URI. A few that the engine routinely sees: `https://slsa.dev/provenance/v1` (build provenance), `https://cyclonedx.org/bom/v1.4` (SBOM), `https://in-toto.io/attestation/vulns/v0.2` (vulnerability scan), and per-organization custom predicates.

Statements are signed and distributed as **Sigstore bundles** (`application/vnd.dev.sigstore.bundle.v0.3+json`). A bundle carries the statement inside a DSSE envelope (Dead Simple Signing Envelope), which holds the signature over the canonical statement bytes, together with the verification material needed to check that signature offline: the signing certificate (or a public-key hint for static keys) and the transparency-log entry with its inclusion proof. The Sigstore bundle is the unit the engine stores, retrieves, and verifies. The policy logic operates on the verified statement.

> **Note:** The engine treats predicates as opaque JSON until a policy declares interest in a specific `predicateType`. The engine does not embed predicate-specific schemas. Policies that consume a predicate are responsible for understanding its shape.

### 2.2 SLSA: Provenance and Verification Summary Attestations

The SLSA framework (Supply-chain Levels for Software Artefacts) defines two predicate types that are central to this design:

- **SLSA Provenance** records *how* an artefact was built — which build platform produced it, from which source commit, with what build parameters, and with what dependencies. Provenance is the keystone of artefact-to-source traceability.
- **Verification Summary Attestations (VSAs)** record *that* an artefact passed a defined set of policy checks at a defined point in time, attested by some verifier. VSAs allow a downstream consumer to short-circuit re-verification: rather than re-walking the attestation graph, they trust a VSA from a known verifier.

The engine consumes SLSA Provenance to bridge source-stage and build-stage attestations (Section 5). It produces VSAs as the output of CI/CD evaluations when requested (Section 6.4).

### 2.3 OPA and Rego

OPA (the Open Policy Agent) is a general-purpose policy engine that evaluates **Rego** policies against arbitrary JSON-shaped input. Rego is a declarative query language built around partial evaluation: a policy describes the conditions under which violations exist, and OPA returns the set of violations that match.

A typical Rego policy in this engine evaluates against a fixed input contract (Section 6.3) and emits a `violations` set:

```rego
package policy.global.platform.require_signed_images.v1

import rego.v1

violations contains v if {
    some att in input.attestations
    att.verification.signature != "valid"
    v := {
        "code": "UNSIGNED_IMAGE",
        "message": sprintf("Image %s is not signed", [att.subject.name]),
    }
}
```

OPA is shipped as a library, embedded inside the engine. There is no separate OPA process. Policies are distributed as **OPA bundles** — tar archives containing Rego files, optional reference data, and a manifest. The engine loads a single bundle at startup and re-loads it on a configurable cadence.

### 2.4 Policies, profiles, and the separation of concerns

The engine separates two questions:

- **What does it mean for an artefact to be compliant?** A **policy** answers this. A policy is a single, focused, testable statement: *"images MUST be signed by a known signer"*, *"an SBOM document MUST have been generated*, *"the vulnerability scan MUST have run within the last 7 days"*. Each policy is authored once and reused.
- **Which policies apply at this gate?** A **profile** answers this. A profile assembles a set of policies (or other profiles) into an evaluable unit appropriate for a specific use: *"tier-1 production gate"*, *"PCI-DSS pre-deployment checks"*, *"baseline source-stage hygiene"*.

This separation lets policies be authored by domain owners (platform security writes signing policies, vulnerability-scanning teams write scan-result policies) and assembled by consumption owners (product teams compose the profile that gates their pipeline). Section 4 specifies this model in full.

### 2.5 The shape of the work

A single evaluation, in plain language, proceeds as follows:

1. The caller hands the engine a **subject** — an artefact digest (`sha256:…`), a source commit (`gitCommit:…`), or both — and a **profile reference**.
2. The engine **resolves** the relevant attestations from its configured storage backends: it walks the subject graph, hopping from the artefact's SLSA Provenance to the source commit it depends on, gathering everything in scope.
3. The engine **verifies** those Sigstore bundles: signatures, certificates, and transparency-log proofs.
4. The engine **prepares** the input for each policy: it merges parameter precedence, fetches any external data the profile needs, and pre-filters attestations by `predicateType` so each policy sees only what it cares about.
5. The engine **evaluates** every policy in parallel.
6. The engine **aggregates** the results and, if requested, emits a Verification Summary Attestation.

Sections 5 and 6 specify this pipeline in normative detail.

---

## 3. Architectural topology

The engine is delivered as a single Go codebase compiled into multiple deployable forms. All forms share the same evaluation core, the same policy/profile model, and the same attestation contract. The differences between them are in **where they run**, **what trust boundaries they assume**, and **how they expose evaluation to the caller**. This section establishes those differences and the topology that follows from them.

### 3.1 The three deployment modes

```text
                         Shared evaluation core
                ┌───────────────────────────────────────┐
                │  Resolver  │  Verifier  │  OPA  │ VSA │
                └───────────────────────────────────────┘
                            ▲       ▲      ▲
        ┌───────────────────┘       │      └───────────────────┐
        │                           │                          │
┌───────────────┐         ┌───────────────────┐      ┌─────────────────┐
│      CLI      │         │   Central server  │      │   K8s admission │
│  (dev + CI)   │         │   (REST API)      │      │     webhook     │
└───────────────┘         └───────────────────┘      └─────────────────┘
        │                           │                          │
        ▼                           ▼                          ▼
    developer                product teams,                Kubernetes
   laptop / CI               build systems,                API server
    pipelines                  platforms                 (per-cluster)
```

[Figure 1: The three deployment modes share a single evaluation core. They differ only in the surfaces they expose, the trust they assume of their callers, and how they acquire credentials for external reads.]

**The CLI** is the developer's loop and the CI/CD job's harness. It runs on a workstation or a build-runner, evaluates a single subject against a single profile, and exits with a deterministic status code. It MUST be runnable offline against a downloaded policy bundle and a filesystem attestation store (Section 5.6) holding Sigstore bundles — there is no requirement that a developer's laptop be able to reach a central server. When external data is required for a policy, the CLI delegates the evaluation to the central server (Section 6.2).

**The central server** is the engine's organization-scoped face. It exposes a REST API over HTTPS, evaluates on behalf of any authenticated caller, and is the single egress point for any external-data read that requires credentials. It is stateless: every evaluation is fresh, no per-evaluation state is persisted on the server side. Horizontal scaling is therefore trivial — replicas are interchangeable. The server holds the bundle, the verifier's trust roots, and the credentials for external-data providers.

**The K8s admission webhook** is a thin client. It receives `AdmissionReview` requests from a cluster's API server, extracts container image references from the workload spec, resolves them to digests against the cluster's image registry, reads the target namespace's profile annotation, and forwards a structured `Evaluate` request to the central server. The webhook does **not** embed an evaluation core, does **not** hold attestation-store credentials, and does **not** perform signature verification itself. It is a translator between Kubernetes' admission protocol and the engine's REST API.

> **Design rationale: a thin admission webhook.** The K8s admission webhook is a thin client. An embedded engine in every cluster is not part of the v1 design. The thin shape forwards every admission decision to a single centrally governed surface, where verifier trust roots, attestation-store credentials, and bundle distribution are managed once rather than duplicated across clusters. The trade-off is a hard runtime dependency on the central server: when it is unreachable, the webhook fails closed (Section 6.6) and admission is denied. This trade-off is the load-bearing choice because admission denial is recoverable — the team retries after the outage — whereas identity drift across hundreds of cluster-embedded engines is not.

### 3.2 Shared evaluation core

All three modes link the same `evaluation` package. The package exposes a single entry point:

```go
type Evaluator interface {
    Evaluate(ctx context.Context, req EvaluationRequest) (EvaluationResult, error)
}

type EvaluationRequest struct {
    Subjects     []SubjectKey       // artefact digest(s), source commit, etc.
    ProfileRefs  []ProfileReference // one or more top-level profiles
    Evaluation   EvaluationStrategy // collect-all | fail-fast; set by the calling mode
    Context      EvaluationContext  // caller-supplied context (cluster id, namespace, env, …);
                                    // surfaced to policies via input.context
    Parameters   ParameterSet       // optional runtime overrides (CLI/server only; never admission)
    GenerateVSA  bool               // emit a Verification Summary Attestation
}
```

The CLI populates `EvaluationRequest` from command-line flags. The server populates it from a REST request body. The webhook populates it from an `AdmissionReview` plus the namespace annotation. Past that boundary, all three modes execute the same code path. No mode places attestations on the request: the evaluator retrieves them itself through the configured storage backends (Section 5.6).

This is not a slogan. It is a normative invariant. A policy that passes in the CLI MUST produce the same `violations` set on the server and in the webhook, given the same subjects, profile set, parameters, and attestation-store contents. Mode-specific behaviour — CLI's offline mode, the server's external-data fetching, the webhook's namespace-profile lookup — is implemented strictly at the boundary, before the evaluator is called. The shared core is mode-agnostic.

`ProfileRefs` is plural because a single evaluation MAY combine multiple top-level profiles. The engine treats the list as a synthetic top-level aggregator and unions every effective policy after running each profile's authored composition through the conflict resolver. Section 4.8 specifies the runtime semantics; in short, set semantics — order doesn't matter, duplicates deduplicate, the verdict is deterministic. A request with exactly one profile is the common case; the multi-profile shape is what powers the K8s namespace annotation that lists several profiles, the CLI's repeatable `--profile` flag, and the REST API's `profileRefs[]` array.

### 3.3 Trust boundaries

Each mode establishes a different trust boundary with its caller:

- **CLI.** The caller is a human or a CI job running on a runner the caller controls. The CLI trusts no one and verifies everything: policy-bundle signatures, attestation Sigstore bundles, parameter schemas. It carries no organization-wide credentials. Anything that would require such a credential (an external-data fetch) is delegated to the central server, which has its own trust model.
- **Central server.** The caller is authenticated via a deployment-issued bearer token. The server trusts that the policy-bundle signing key is held by the platform-security team, that the attestation-store responses are authentic (verification of every Sigstore bundle is the cross-check), and that the deployment platform has scoped each external-data credential to the narrowest required reads.
- **K8s admission webhook.** The caller is the Kubernetes API server, authenticated via the `caBundle` of the `ValidatingWebhookConfiguration`. The webhook in turn authenticates to the central server with its own bearer token, and binds that authentication to the cluster's `kube-system` namespace UID. The K8s API server does not authenticate to the central server directly; the webhook is the bridge.

> **Security boundary.** The three modes never share a credential. The CLI carries no central-server credential beyond the user's own auth token (when invoking the server's REST API in delegated-evaluation mode). The webhook carries no attestation-store or external-data credential. The server is the only surface that holds production credentials, and it scopes them per provider.

### 3.4 What each mode is and is not for

| Mode | Use it for | Do NOT use it for |
|------|------------|-------------------|
| CLI | Developer-loop policy authoring. CI/CD pipeline gates. Offline batch evaluation. Signing of result VSAs in pipelines. | Long-running services. Multi-tenant evaluation with shared credentials. Operations that require a stable identity for the caller. |
| Central server | Organization-wide programmatic evaluation. Integrations with build platforms and IDE plugins. The egress point for credentialed external reads. Serving the K8s admission webhook. | Cluster-local enforcement decisions where round-trip latency to the central plane is unacceptable. Environments where the engine's availability cannot tolerate a network partition. |
| K8s admission webhook | Cluster-admission gates: blocking workloads whose image digests fail the cluster's namespace profile | Pre-build evaluation. arbitrary REST integrations. Profile authoring or testing. |

The CLI and the server overlap in capability — both can evaluate any profile against any subject set. The webhook is structurally different: it does not run user-supplied requests. It interprets admission events and forwards them to the server.

---

## 4. Policy and profile model

This section is the engine's surface contract. It specifies how policies and profiles are identified, what their metadata looks like, how they version, how they compose, and how the engine resolves conflicts when composition produces ambiguity. Every YAML and Rego artefact described here is part of the engine's stable v1 contract. Changes to its shape are MAJOR version events.

### 4.1 Identity and naming

Every policy and every profile is identified by a triple:

```text
<namespace>/<name>/<major-version>
```

where `<namespace>` reflects ownership and the file layout (Section 8), `<name>` is a stable, immutable, kebab-case identifier, and `<major-version>` is a `vN` selector. The triple is the engine's universal reference form. It is identical in YAML files, in CLI flags, and in OCI bundle manifests.

Examples:

```text
global/platform/require-signed-images/v1
global/security/sbom-validation/v2
208370/scan-container-images/v1
```

The `<major-version>` is always a major-version selector, never a full SemVer. The bundle resolves it to the latest minor/patch within the line at assembly time (Section 7.3). Profiles never pin minor or patch versions. This is intentional: minor and patch are non-breaking by SemVer contract, and pinning them defeats automated propagation of bug fixes.

### 4.2 Metadata schema

Policies and profiles share a common metadata frame. The schema is JSON-Schema-validated at authoring time, at bundle-assembly time, and at engine load time. The format is YAML.

A policy's metadata:

```yaml
version: v1                                                   # schema version
metadata:
  namespace: global/platform                                  # owner namespace
  name: require-signed-images                                 # stable identifier
  version: 1.2.0                                              # SemVer of this policy
  description: "Requires container images to be signed by an approved signer."
  deprecated: false
  labels:
    sdlc-stage: "build,deploy"                                # comma-separated when multi-valued
    attestation-type: "meta"
  owner:
    team: platform-security
    email: platform-security@example.com
predicate: "https://slsa.dev/provenance/v1"                   # exactly one predicateType this policy applies to
evidence: required                                            # required | optional when no attestation of that predicate is found
enforcement: error                                            # error | warning | info
panic: deny                                                   # deny | allow on Rego runtime panic
parameters:                                                   # map keyed by parameter name
  allowed_signers:
    type: list<string>                                        # number | string | boolean | list<string>
    # default omitted: every profile referencing this policy must supply a value
```

> **Note: one policy, one predicate.** A policy declares exactly one `predicateType`. The engine pre-filters attestations for the policy down to that type, and the policy's Rego operates on a flat array of those attestations. This is a deliberate constraint, not a syntactic oversight: it forces single-purpose policies, and it leaves the two cases that might otherwise want multiple predicates to cleaner mechanisms. **Cross-predicate freshness checks** — *"every attestation in the bundle is at most 7 days old at evaluation time"* — are expressed as two single-predicate policies plus a profile that includes both, each policy comparing its own predicate's timestamp against a shared reference (typically evaluation time, or a profile-supplied parameter) through the `policy.helpers.time` package. A genuinely pairwise relationship that cannot be decomposed against a shared reference — *"the scan was performed at most 7 days after this exact build finished"* — is modelled as a dedicated predicate type that a producer emits, with a single policy evaluating the relationship inside it. **Predicate version migrations** — moving a producer fleet from `cyclonedx/bom/v1.4` to `v1.5` — are expressed as two policy versions side by side: a v1 policy bound to the old predicate type and a v2 bound to the new one, with both included in the transition profile until the migration completes, after which v1 is deprecated and removed. Both patterns reuse the existing composition machinery instead of expanding the policy contract.

A profile's metadata:

```yaml
version: v1
metadata:
  namespace: global/security
  name: tier1-production
  version: 1.0.0
  description: "Tier-1 production gate."
  deprecated: false
  owner:
    team: platform-security
    email: platform-security@example.com

# A profile is EITHER a list of policies, OR a list of profiles. Never both.
policies:
  - policy: global/security/require-signed-images/v1
    enforcement: error
    parameters:
      allowed_signers: ["org-signer-key"]
```

Three metadata properties deserve specific treatment:

**`evidence`** decides the verdict when the resolver discovers no attestation of the policy's declared `predicate`. `required` (the default) records the policy as `FAIL` with an engine-generated `NO_MATCHING_ATTESTATION` violation, before any Rego runs. That failure carries the policy's `enforcement` like any other, so a profile that wants absent evidence reported without blocking references the policy with `enforcement: warning` rather than declaring it `optional`. `optional` records the policy as `SKIPPED` and leaves the verdict untouched. `required` is the default because an empty `input.attestations` satisfies most Rego bodies vacuously — a policy that iterates the array to flag bad entries finds nothing to flag and passes — and because suppressing one producer is cheaper than suppressing all of them. `optional` covers evidence conditional on the gate's position, such as a build-stage predicate at a source-stage gate that runs before any build exists.

**`enforcement`** is set by the policy author and by the profile that references it. It encodes how a violation is treated: `error` blocks (in the deployment mode that blocks); `warning` is reported but not blocking; `info` is informational. Enforcement is an authored property, not a runtime property — there is no `--strict` flag that promotes warnings to errors. Conflict resolution between the author's default and the profile's override is specified in Section 4.6.

**`panic`** governs what happens when a policy's Rego logic raises a runtime error (a malformed input, a divide-by-zero, a missing field where one was expected). `deny` (the default) records the policy as `ERROR` and treats the policy as failed for aggregation; `allow` records the error but treats the policy as if it had passed. The K8s admission webhook MUST treat `panic: allow` as `panic: deny` regardless of authored value, because admission cannot tolerate a non-deterministic gate.

### 4.3 Versioning and version coexistence

Policies and profiles version with SemVer. MAJOR version bumps are reserved for breaking changes — changes that could cause an existing caller to start failing in ways the caller cannot resolve without action. Adding a new optional parameter is MINOR. Tightening enforcement (e.g., raising default enforcement) is MAJOR.

The file layout (Section 8.1) places every policy under an explicit `vN/` subdirectory. There is always a `v1/`, even when no v2 exists. Major versions coexist on disk and in the bundle:

```text
policies/global/platform/require-signed-images/
  v1/
    policy.yaml      # 1.5.2
    policy.rego
    policy_test.rego
  v2/
    policy.yaml      # 2.0.1
    policy.rego
    policy_test.rego
```

A profile referencing `…/v1` resolves to the latest 1.x.x version in the bundle. A profile referencing `…/v2` resolves to the latest 2.x.x. The Rego package name encodes the major version (`policy.global.platform.require_signed_images.v1`), so OPA can hold multiple major versions of the same policy in memory without collision.

> **Note:** Profiles never reference the same policy at multiple major versions in the same composition tree. If a profile composition would result in `policy/v1` and `policy/v2` both being included, the engine rejects the bundle at validation time. Major versions are different policies for the purpose of conflict resolution. The conflict-resolver does not attempt to "merge" them.

### 4.4 Composition: profiles of profiles, profiles of policies

A profile contains **either** a list of policies **or** a list of profiles. Never both.

```yaml
# Leaf profile — a list of policies.
metadata:
  namespace: global/security
  name: sbom-validation
spec:
  policies:
    - policy: global/security/require-sbom/v2
      enforcement: error
    - policy: global/security/sbom-format-validation/v1
      enforcement: error
    - policy: global/security/sbom-completeness/v1
      enforcement: warning
      parameters:
        min_components: 10
```

```yaml
# Aggregate profile — a list of profiles.
metadata:
  namespace: global/security
  name: tier1-production
spec:
  profiles:
    - profile: global/security/sbom-validation/v1
    - profile: global/security/vulnerability-scanning/v1
    - profile: global/security/supply-chain-security/v2
```

### 4.5 Composition depth and the natural hierarchy

The composition tree is capped at **three levels**. Counting from the leaf:

```text
Level 1 (leaf)        : a profile that lists policies directly
Level 2 (aggregator)  : a profile that lists Level-1 profiles
Level 3 (roll-up)     : a profile that lists Level-2 profiles
```

The labels describe the natural hierarchy. The actual constraint the assembler enforces is on **maximum tree depth**: a profile's depth is `1 + max(depth(child))` over its children, and that value MUST NOT exceed three. A profile MAY include children at any lower level — a roll-up that combines a Level-2 aggregator with a Level-1 leaf overlay is depth 3 and valid, even though its children sit at different levels. The bundle assembler MUST reject any profile whose composition tree exceeds three levels.

### 4.6 Conflict resolution

When the composition tree is flattened, multiple profiles can reference the same policy with different settings. The engine resolves conflicts deterministically by applying the rules below in order; each rule produces a winner unless it ties, in which case the next rule applies.

1. **Most-restrictive enforcement wins.** `error > warning > info`. If one path resolves the policy with `enforcement: warning` and another with `enforcement: error`, the result is `enforcement: error`.
2. **Shallowest reference wins.** When a policy is reachable through multiple paths in the flattened composition tree, the path with the fewest profile hops from the request's top-level wins. A directly-listed policy in a top-level profile (or one hop down) outranks a policy reached through deeper aggregation. This is the rule that makes overlay-and-roll-up composition work: a downstream team that authors a leaf overlay listing a policy with adjusted parameters and combines it at the request level outranks the same policy reached through an inherited platform aggregator several hops deeper.
3. **Winning reference's parameters apply as a block.** The parameter block of the path that won under rules 1–2 applies in full. The engine does not deep-merge parameter blocks across references; this avoids partial parameter sets that pass the policy's type checks only by coincidence.

If after rules 1–2 two references remain tied at the same enforcement and depth, the engine selects deterministically by lexicographic order of the source profile reference and emits a warning at evaluation time so the author can resolve the ambiguity in the bundle.

There is **no** mechanism to remove a policy from an included profile (no `enabled: false`, no `skip`, no exclusion list). Once a profile is included, every policy it contributes is evaluated. This prevents silent gaps where a security control vanishes because a downstream profile excluded it.

Every policy in the resolved set is evaluated and reports a status. `evidence` (Section 4.2) is authored on the policy and no profile overrides it — it governs what an absent predicate means, never whether a policy runs.

### 4.7 Worked example: conflict resolution

```yaml
# Leaf profile A
spec:
  policies:
    - policy: global/security/vuln-threshold/v1
      enforcement: warning
      parameters: { max_critical: 5 }

# Leaf profile B
spec:
  policies:
    - policy: global/security/vuln-threshold/v1
      enforcement: error
      parameters: { max_critical: 0 }

# Aggregator profile
spec:
  profiles:
    - profile: global/security/profile-a/v1
    - profile: global/security/profile-b/v1
```

Resolution: `vuln-threshold/v1` is included with `enforcement: error` (rule 1), and the parameters that win are `{ max_critical: 0 }` (rule 3 — the parameters of the enforcement-winning reference). `max_critical: 5` is *not* combined with the result.

If the aggregator additionally listed the policy directly:

```yaml
# Aggregator profile mixing profiles and policies — NOT ALLOWED under homogeneous-composition rule.
spec:
  profiles:
    - profile: global/security/profile-a/v1
    - profile: global/security/profile-b/v1
  policies:
    - policy: global/security/vuln-threshold/v1
      enforcement: info
      parameters: { max_critical: 100 }
```

…this is rejected by validation. The homogeneous-composition rule disallows mixed `profiles:` and `policies:` in one profile. An author who wants this effect must split: keep the aggregator profile as profile-only, and create a separate leaf profile that explicitly sets `vuln-threshold` to `info`/`100`, then create a roll-up that combines them — at which point the most-restrictive rule (Section 4.6) produces the deterministic result.

### 4.8 Multi-profile evaluations and the synthetic aggregator

An evaluation request MAY name more than one top-level profile. The engine treats the list as a **synthetic top-level aggregator**: each named profile's authored composition tree is flattened individually, and the resulting effective-policy sets are unioned. The same conflict resolver from Section 4.6 then runs over the combined set; the rules are unchanged.

```text
Request:
  ProfileRefs = [ global/security/tier1-production/v1,
                  208370/payments/extra-checks/v1 ]

Synthetic aggregator (in memory; not persisted to the bundle):
  ┌── global/security/tier1-production/v1 ──── (authored 3-level tree)
  └── 208370/payments/extra-checks/v1     ──── (authored 1-level leaf)
                       │
                       ▼
  Union of effective policies → conflict resolver → resolved policy set
```

The synthetic aggregator is a runtime construct — it is not a profile, has no `metadata`, has no version, and is not stored anywhere. It exists only for the duration of the evaluation. Three properties hold:

- **Set semantics.** Order of `ProfileRefs` does not affect the verdict. A request with `[A, B]` and a request with `[B, A]` produce the same resolved policy set and the same result.
- **Deduplication.** Listing the same profile reference twice has no effect. The engine deduplicates by `<namespace>/<name>/<vN>`.
- **Depth cap doesn't apply at this layer.** Three-level cap governs **authored** composition in the bundle. Each profile in `ProfileRefs` MUST individually satisfy the cap. The synthetic aggregator above them is a fourth conceptual layer, but the operator who supplies the list is making the synthesis explicit at the call site — there is no hidden authoring tree to debug.

> **Note:** Multi-profile evaluation is the natural mechanism for declaring "platform-mandatory + team-specific" coverage without requiring every team to author a roll-up profile. The K8s namespace annotation lists profile references precisely because the namespace is the call site that combines them; the same applies to the CLI's repeatable `--profile` flag and the server's `profileRefs[]` array.

When `GenerateVSA: true` is set on a multi-profile request, the engine emits **one VSA per top-level profile** in the request, each with `policy.uri` pointing at that profile and each carrying the *union verdict* (the verdict computed across all profiles together). Downstream consumers who care about a specific profile verify the corresponding VSA; the verdict reflects the gate the artefact actually passed through. A consumer that wants the full picture of which profiles were evaluated together correlates the VSAs by verifier, subject, and `timeVerified`.

---

## 5. Attestation discovery and linking

This section is the engine's data-resolution heart. Before any policy can evaluate, the engine must answer the question: *"given this artefact (or this commit), which attestations apply?"* The answer determines what every downstream stage sees. This section specifies the answer normatively.

### 5.1 The foundational insight: subject digest as the universal key

Every `in-toto` attestation has a `subject` array. Each subject is a `ResourceDescriptor` whose `digest` field is a content-addressable identifier. The engine **MUST** use the subject digest as the canonical lookup key. There is no organization-specific identifier, no "context ID", no build identifier, no pipeline run identifier in the engine's contract. A storage backend that wants to expose alternative indexes for its own reasons MAY, but the engine queries it only by subject digest.

This is a deliberate and load-bearing choice. The attestation graph is a hypergraph whose nodes are immutable digests and whose hyperedges are signed statements. By identifying nodes only by their digests, the engine inherits the graph's mathematical properties: lookups are content-addressable, deduplication is automatic, and the graph is portable across organizations without any vocabulary translation.

### 5.2 Different SDLC stages, different digest types

A pre-build attestation cannot use the artefact's digest as its subject — the artefact does not yet exist. The `in-toto`/SLSA community has settled on a stage-based convention: each lifecycle stage anchors its attestations to the immutable identity of that stage's primary input or output. For software, this concretely takes the shape:

| Lifecycle stage | Subject digest type | Example predicates |
|-----------------|---------------------|--------------------|
| Source / pre-build | `gitCommit` (or `gitTree`) | Pull-request review, commit signing, source SAST/SCA, license scan on source |
| Build | `sha256` (artefact digest) | SLSA Provenance, SBOM, build logs |
| Post-build | `sha256` (artefact digest) | Container scan, image signing, VSA from a prior verifier |
| Deployment | `sha256` (artefact digest) | Deployment attestation, environment-promotion record |

Source-stage attestations are subject-bound to the commit. Build-stage and later attestations are subject-bound to the artefact. The engine uses the subject digest type to determine which storage-backend index to query (in backends that distinguish them) and which graph hop to follow.

A producer who attaches the wrong subject digest type to an attestation breaks discovery. A pull-request review attestation whose subject is the (yet-to-exist) container digest will not be found by the engine when it walks the source-stage graph. The convention above is normative for producers. The engine assumes it.

> **Note: this table is a software-domain instantiation, not a contract.** The engine's contract is the more abstract claim: *each lifecycle stage maps to an immutable identity, and that identity is the subject of stage-specific attestations.* Software happens to use `gitCommit` for source and `sha256` for everything else; other domains use whatever digest types correspond to their stages' artefacts. Section 5.8 walks through the AI-model case (model weights, training datasets, base models, training code) where the same primitives produce a richer set of source-side digests, none of which the engine privileges.

### 5.3 The bridge: SLSA Provenance and `resolvedDependencies`

[The SLSA Provenance](https://slsa.dev/provenance/v1) predicate solves the cross-stage linking problem. Its `subject` field carries the artefact's digest. Its `predicate.buildDefinition.resolvedDependencies` field records, among other things, the source commit the build consumed. A typical fragment:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "myapp", "digest": { "sha256": "a3f8…" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "resolvedDependencies": [
        { "uri": "git+https://example.com/org/myapp",
          "digest": { "gitCommit": "def012…" } }
      ]
    }
  }
}
```

This single attestation contains the bridge: its subject identifies the artefact; its `resolvedDependencies` identifies the source commit. The engine reads both and uses them as the entry points for the two halves of the graph walk.

A producer who emits no bridge attestation breaks the cross-stage walk, and every policy that needed an upstream-bound attestation receives an empty `input.attestations`. The policy's `evidence` setting decides the outcome (Section 4.2), so a missing bridge is not a distinct failure mode. A bridge attestation — SLSA Provenance v1 in the canonical case, or any predicate the deployment has registered in its resolver configuration with a `dependenciesPath` pointing at the predicate's upstream-dependency array (Section 5.4) — is a producer requirement wherever a gate declares upstream evidence `required`. A gate positioned before the bridging stage has no bridge to read and declares those policies `optional` instead.

### 5.4 The graph walk

Given a subject, the engine walks the attestation graph in three phases:

```text
INPUT:  subject = SubjectKey{ "sha256", "a3f8…" }
        (or any other (algorithm, value) — gitCommit, gitTree, …)

Phase A — Direct attestations (subject-bound).
  direct = store.Get(subject)

Phase B — Find the bridges.
  upstream = ∅
  for p in direct:
    bridge = lookup(p.predicateType, configured_bridges)
    if bridge == nil: continue
    for dep in read_path(p, bridge.dependenciesPath):
      for (algo, value) in dep.digest:
        upstream += SubjectKey{ algo, value }

Phase C — Indirect attestations (upstream-bound).
  for k in upstream:
    indirect += store.Get(k)

RESULT:  union(direct, indirect)
```

The walk is bounded and deterministic. It does not recurse beyond one bridge hop in v1: the engine resolves one level of upstream dependency from the subject's bridge attestations. Recursive supply-chain analysis (the upstream's own bridges, and so on) is post-v1.

The walker follows **every digest** present in the bridge's dependency array, not only `gitCommit`. For software builds, the upstream set typically contains a single `gitCommit` (the source repository); for other artefact types — AI models, data products, configuration bundles — the upstream set is a mix of digest types: a dataset's `sha256`, a base model's `sha256`, a training-code `gitCommit`, a config blob's `sha256`. The engine treats each uniformly: a `Get(SubjectKey)` per upstream digest.

The set of bridge predicates and the location of each predicate's dependency array are both deployment-configurable. v1 ships one entry — [`https://slsa.dev/provenance/v1`](https://slsa.dev/provenance/v1) with `dependenciesPath: predicate.buildDefinition.resolvedDependencies` — and a deployment that adopts a domain-specific bridge predicate registers it with its own `dependenciesPath`. The contract on the bridge predicate's body is narrow: the configured path resolves to an array, and each element exposes a `digest` field shaped as a DigestSet. Producers do not need to mimic SLSA Provenance v1's exact field path to be a bridge.

When the caller hands the engine a non-artefact subject directly — e.g., a `gitCommit` for a CI gate evaluating a pull request before any artefact has been built — the engine starts in Phase A on that subject, finds no bridges (source-stage attestations don't carry resolvedDependencies), and returns the direct set. There is nothing to bridge to.

When the caller hands the engine multiple subjects (Section 4.8: an artefact and the commit it was built from; or a model and its dataset), the engine walks each independently and unions the results, deduplicating by bundle digest.

> **Note:** Subject matching is exact on `(algorithm, value)`. The engine does not infer relationships between digests it has not been told about. An attestation indexed under a non-standard digest algorithm is fetched only when a caller subject or a `resolvedDependencies` entry surfaces that algorithm.

### 5.5 Verification Summary Attestations

A VSA records that a verifier (the engine) evaluated a defined policy set against a subject and produced a defined verdict. Downstream consumers can trust the VSA as a short-circuit: rather than re-walking the graph and re-evaluating every policy, they verify the VSA's signature, check that the verifier identity is trusted, and accept the verdict.

The engine produces VSAs as the optional output of an evaluation (Section 6.4). The VSA's predicate type is `https://slsa.dev/verification_summary/v1` (the SLSA-standard type). The VSA's subject is the same subject the engine evaluated. The VSA's predicate records the profile reference (with its resolved version), the resolved policy versions, the verdict, and the timestamp.

The engine also consumes VSAs from prior evaluations. A VSA emitted by an earlier gate is published to the storage backend like any other Sigstore bundle, and the resolver returns it under the same subject digest. Before evaluating a profile, the engine inspects discovered VSAs for an exact match against the current request: same `subject`, same `policy.uri` (including resolved version), same `policy.digest` (the policy bundle's resolved policy set hash), signer identity in the deployment-global allow-list for the VSA predicate, `timeVerified` within the configured freshness window, and the resolver's currently-gathered bundle-digest set is a superset of the VSA's `inputAttestations` digest set (Section 6.4) — the prior verifier MUST not have seen evidence the current resolver is missing. Subset (not equality) is intentional: new attestations appearing since the prior VSA was emitted are additive evidence the prior verifier didn't consider, but they don't invalidate what was seen. When all conditions hold, the engine accepts the VSA's `verificationResult` as the verdict for that profile and skips OPA evaluation, reporting the source verifier identity and `timeVerified` in the per-profile result. The caller does not opt in; the short-circuit applies automatically when a matching VSA exists and is silently absent otherwise — turning the engine into both a verifier and a verifier-of-verifiers without any caller-side change.

Distinct from the transparent short-circuit, a policy MAY require the *presence* of a VSA as a gating condition — for example, a production gate confirming that a prior CI gate signed off on the artefact. This is authored as a normal policy with `predicateType: https://slsa.dev/verification_summary/v1` and Rego that checks `policy.uri`, signer identity, and verdict. Where the short-circuit *replaces* evaluation when an exact match is found, the explicit reference *adds* a check that fails when the required VSA is absent or untrusted. Use it when VSA presence is itself the requirement, not merely an optimization.

The engine does not sign VSAs itself. Signing is delegated to the deployment pipeline (Sigstore/cosign, the existing organizational signer) because signing belongs to the deployment platform's identity model, not the engine's. The engine emits an unsigned in-toto Statement; the pipeline signs it and packages it as a Sigstore bundle.

### 5.6 The storage backend plugin contract

The engine's resolver consumes a storage backend through a small interface. The interface is intentionally minimal: it does point lookups by `SubjectKey` and accepts publishes of new Sigstore bundles. The graph walk is implemented in the engine, not in the backend.

```go
// AttestationStore is the engine's storage backend interface.
// All operations are scoped to a single trust domain; multi-tenancy is the
// deployment's concern.
type AttestationStore interface {
    // Get returns every Sigstore bundle whose statement.subject contains a
    // digest matching the given key. An empty result is not an error.
    Get(ctx context.Context, key SubjectKey) ([]SigstoreBundle, error)

    // Put persists a new Sigstore bundle. Implementations MUST be idempotent
    // on (bundle-digest); re-publishing the same bundle is a no-op.
    // Implementations MUST index the bundle under EVERY subject digest
    // it carries, so a single SLSA Provenance is retrievable by both the
    // artefact's sha256 and (separately) by source-bound queries that
    // start from the resolvedDependencies side.
    Put(ctx context.Context, b SigstoreBundle) error

    // HealthCheck reports the backend's current ability to serve Get/Put.
    HealthCheck(ctx context.Context) error
}

type SubjectKey struct {
    Algorithm string  // e.g. "sha256", "gitCommit", "gitTree"
    Value     string  // hex-encoded digest value
}

type SigstoreBundle struct {
    Raw          []byte    // raw Sigstore bundle bytes
    Statement    Statement // statement parsed from the bundle's DSSE envelope (cached)
    BundleDigest string    // sha256 of the canonical bundle bytes; the same value the
                           // wire JSON calls bundleDigest, and the
                           // running prose calls "bundle digest"
}
```

The reference distribution ships three implementations:

- A **filesystem** implementation (`<root>/<algorithm>/<value>/<bundle-digest>.sigstore.json`) for local development, CLI offline mode, and testing.
- An **OCI-registry** implementation, cosign-style: a Sigstore bundle is stored as an OCI artefact of artifact type `application/vnd.dev.sigstore.bundle.v0.3+json` whose manifest `subject` references the subject digest, and is discovered through the OCI v1.1 referrers API — the convention cosign follows for attestations. On registries without referrers support, the adapter uses the OCI referrers tag schema (`<repo>:sha256-a3f8…`) as the fallback index. This implementation supports `sha256` subject keys naturally; it represents `gitCommit`-keyed attestations by tagging them under a repository scoped to the source repository (configurable by deployment).
- An **HTTP** implementation that calls a remote HTTP service implementing the `Get`/`Put` contract over JSON. This is the adapter for any custom HTTP-shaped attestation store. An adapter to Archivista — whose primary query surface is GraphQL, with `POST /upload` and `GET /download/:gitoid:` for content I/O — is a separate, more specific implementation that translates between the `AttestationStore` interface and Archivista's GraphQL queries; the reference distribution does not ship that adapter in v1.

No Rekor `AttestationStore` adapter ships. Rekor v2's tile-based log does not store DSSE payloads — entries commit only to a digest of the signed content plus signature material — so it cannot serve as a content store. A v1-only adapter would lock the reference implementation to a Rekor mode that the Sigstore project is migrating away from. Deployments treat Rekor strictly as a verifier-side time-witness (Section 6.2) and use OCI, HTTP/Archivista, or a custom plugin for discovery.

The interface is deliberately small. A future backend that does graph walks natively (e.g., Archivista's GraphQL surface) MAY expose a richer interface internally, but the engine only depends on `Get`/`Put`/`HealthCheck`.

**Chaining stores.** A deployment MAY configure multiple `AttestationStore` backends as an ordered list. The engine's resolver tries each in order and unions the results (deduplicated by bundle digest). Chaining is the answer to partial coverage: an organization that has a primary central store but knows some teams publish only to a secondary store configures `[primary, secondary]` and gets both populations in one query. Chaining is a deployment composition, not a new architectural primitive; the resolver treats every entry uniformly through the `AttestationStore` interface.

### 5.7 Worked example: end-to-end discovery

A team's CI pipeline builds a container image. The pipeline produces:

- One PR-review attestation, subject `gitCommit:def012…`, predicate `https://example.org/pull-request-review/v1`.
- One source-SAST attestation, subject `gitCommit:def012…`, predicate `https://example.org/sast/v1`.
- One SLSA Provenance, subject `sha256:a3f8…`, predicate `https://slsa.dev/provenance/v1`, with `resolvedDependencies[].digest.gitCommit = def012…`.
- One SBOM, subject `sha256:a3f8…`, predicate `https://cyclonedx.org/bom/v1.4`.
- One vulnerability-scan attestation, subject `sha256:a3f8…`, predicate `https://in-toto.io/attestation/vulns/v0.2`.

At admission time, the K8s admission webhook receives a `Pod` whose container image resolves to `sha256:a3f8…`. The webhook forwards the digest to the central server. The server's resolver:

1. Calls `Get(sha256, a3f8…)` → receives Provenance, SBOM, vulnerability scan.
2. Filters the result for SLSA Provenance, extracts `resolvedDependencies[0].digest.gitCommit = def012…`.
3. Calls `Get(gitCommit, def012…)` → receives PR review and source SAST.
4. Returns the union: five Sigstore bundles.

The verifier validates the five Sigstore bundles. The preparer pre-filters by `predicateType` for each policy. A policy that declares `predicate: "https://slsa.dev/provenance/v1"` sees only the provenance; a policy that declares `predicate: "https://cyclonedx.org/bom/v1.4"` sees only the SBOM.

This example is normative for the discovery contract. Storage backends MUST return the same five Sigstore bundles given the same two `Get` calls.

### 5.8 Generalization beyond software

The engine's primitives are artefact-agnostic by construction: subject digests are `(algorithm, value)` pairs, the verifier operates on signed bytes, the storage backend is content-addressable, and the graph walker follows every digest in `resolvedDependencies` regardless of algorithm. Nothing in the contract privileges container images or git. The "software / git commit" framing in Sections 5.2 and 5.7 is the canonical example because it is the densest in the open-source ecosystem today, but the same evaluation pipeline serves any artefact whose lifecycle produces signed evidence at content-addressable identities.

This section walks through the AI-model case to make the generalization concrete.

**Subject and lifecycle.** A trained AI model is an immutable artefact: a weights blob (`.pt`, ONNX, GGUF, …) or a model container, identified by its `sha256` digest. The lifecycle stages are different from a software build but structurally analogous:

| Lifecycle stage (AI model) | Subject digest type | Example predicates |
|----------------------------|---------------------|--------------------|
| Pre-training (data prep) | `sha256` of dataset | Dataset license attestation, dataset-quality assertion, PII-scan result |
| Pre-training (base model selection) | `sha256` of base model | Base-model card, prior verifier's VSA |
| Pre-training (training code) | `gitCommit` of training repo | Pull-request review, source SAST, hyperparameter approval |
| Training | `sha256` of model weights | Training-run provenance (SLSA Provenance v1 directly, or a specialized predicate of compatible shape) |
| Post-training | `sha256` of model weights | Model card, evaluation/benchmark attestation, red-team report, safety-test result |
| Deployment | `sha256` of model weights | Deployment record, environment-promotion attestation |

Source-side digests span multiple algorithms: the dataset is a `sha256`, the base model is a `sha256`, the training config blob is a `sha256`, only the training code is a `gitCommit`. The graph walker handles this uniformly — Phase B walks every digest in `resolvedDependencies`, and Phase C issues a `Get(SubjectKey)` for each, regardless of algorithm.

**The bridge.** SLSA Provenance v1 covers the training-run case directly. Its `subject` carries the model digest; its `predicate.buildDefinition.resolvedDependencies[]` records the dataset, base model, training code, and configuration. The trainer (the build platform) issues the provenance the same way a software builder issues it for a container. A worked example statement appears in Section 5.7's spirit but extended:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "tax-classifier", "digest": { "sha256": "f1e2…" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://example.com/buildtypes/ml-training/v1",
      "resolvedDependencies": [
        { "uri": "git+https://example.com/org/training-pipeline",
          "digest": { "gitCommit": "ab12…" } },
        { "uri": "data://example.com/datasets/tax-corpus-2026q1",
          "digest": { "sha256": "c3d4…" } },
        { "uri": "model://example.com/models/llama-base-3.1",
          "digest": { "sha256": "e5f6…" } },
        { "uri": "config://hyperparams.yaml",
          "digest": { "sha256": "7890…" } }
      ]
    },
    "runDetails": {
      "builder":  { "id": "https://example.com/trainers/cluster-7" },
      "metadata": { "startedOn":  "2026-04-28T08:00:00Z",
                    "finishedOn": "2026-05-01T17:24:00Z" }
    }
  }
}
```

Given the model's `sha256:f1e2…`, the resolver:

1. Phase A — `Get(sha256, f1e2…)` → receives the training-run provenance, the model card, the safety-test attestation.
2. Phase B — finds the provenance, extracts four upstream digests: `gitCommit:ab12…` (training code), `sha256:c3d4…` (dataset), `sha256:e5f6…` (base model), `sha256:7890…` (training config).
3. Phase C — issues four `Get` calls, one per upstream digest. Each may return its own attestations: a license-cleared attestation on the dataset, a model-card attestation on the base model, a PR-review on the training code, a config-approval on the hyperparameters.

The resolver returns the union, the verifier validates every Sigstore bundle, the preparer pre-filters by `predicateType` for each policy, and policies evaluate independently. Nothing in the pipeline knows or cares that this is an ML artefact rather than a container image.

**Predicate ecosystem.** The AI/ML community is actively producing new predicate types: model cards, dataset attestations, evaluation results, red-team / safety attestations, ML-BOM (the CycloneDX-ML extension), and similar. The engine adopts each as a predicate URI; new policies declare interest in the relevant URI; helper packages (`policy.helpers.ml`, `policy.helpers.dataset`, …) provide domain-specific extraction logic. None of this requires changes to the engine's contract; it is the same shape as adding a new software predicate.

**The "is git needed?" answer.** No. `gitCommit` is one supported subject digest algorithm out of many. Pre-build artefacts that are not git-resident (datasets, configurations, base models, distilled-model parents) anchor their attestations to `sha256` (or any other content digest the producer chose). The engine has never required the source side of the graph to be git.

**The "is SLSA Provenance needed?" answer.** Yes, in spirit — *some* bridging attestation is needed for the resolver to walk from the artefact to its upstream identities. SLSA Provenance v1 fits ML directly because `buildDefinition.resolvedDependencies[]` is open-shaped. If the AI/ML community converges on a specialized "training-provenance/v1" predicate, a deployment registers it in `bridge-predicate-types` and the resolver treats it identically. The engine has no preference between a generic SLSA Provenance and a domain-specialized analogue — only the shape of `resolvedDependencies` matters.

---

## 6. Evaluation pipeline

Every evaluation, regardless of mode, executes the same six-stage pipeline. Stages run sequentially; operations within a stage run in parallel where dependencies allow. This section specifies the pipeline normatively.

### 6.1 The six stages

```text
┌──────────────────┐
│ 1. Validate      │  Schema-validate the request; resolve the profile(s);
│                  │  flatten the composition tree; check parameter types.
├──────────────────┤
│ 2. Resolve       │  Walk the subject graph; gather all relevant Sigstore bundles.
├──────────────────┤
│ 3. Verify        │  Sigstore bundle verification; signer-identity checks.
├──────────────────┤
│ 4. Prepare       │  Merge parameter precedence; pre-filter attestations
│                  │  by predicate; fetch external data (server only).
├──────────────────┤
│ 5. Evaluate      │  Run every policy in parallel; collect violations.
├──────────────────┤
│ 6. Aggregate     │  Compute overall verdict; emit VSA if requested.
└──────────────────┘
```

Stages 1, 2, 3, 5, and 6 are mandatory; stage 4's external-data sub-step is skipped when the resolved profile contains no policy that consumes external data.

### 6.2 Stage-by-stage

**Stage 1 — Validate.** The engine schema-validates the `EvaluationRequest`, resolves the profile reference against the loaded bundle, flattens the composition tree under defined rules, and checks each effective policy's resolved parameters against their declared types. A parameter that resolves to no value fails validation. Validation failures produce structured errors and abort the pipeline. The Validate stage MUST run on the engine side (CLI, server, webhook); callers cannot pre-validate and skip it.

**Stage 2 — Resolve.** The engine walks the subject graph (Section 5.4) using the configured storage backend chain (Section 5.6), which is the engine's only source of attestations. The walk is bounded: one bridge hop, exact subject matching, no implicit transitive resolution. An empty gather is a result, not an error — the pipeline continues, and each policy's `evidence` setting decides what an empty `input.attestations` means (Section 4.2). A storage backend that is unreachable or that errors is a separate condition and aborts the pipeline. Fail-closed semantics apply (Section 6.6).

**Stage 3 — Verify.** Every Sigstore bundle is verified against locally-mounted trust roots. The verifier outputs a per-bundle `verification` record (`signature: <state>`, `signer: <identity>`) that policies consume via `input.attestations[i].verification.signature` and `input.attestations[i].verification.signer`. The `signature` field is one of four categorical states:

- `valid` — all checks passed (cryptographic signature, cert chain, time-witness, identity binding).
- `invalid` — a check completed and failed: bad signature bytes, bad cert chain, time-witness rejected (e.g., signature time outside cert validity).
- `untrusted` — cryptographically valid but signer identity not on the deployment-global allow-list for this `predicateType`, or static-key hint not matching any configured key.
- `unknown` — a required check could not complete: the bundle carries no transparency-log inclusion proof or trusted timestamp, or the trust root for the log or timestamp authority it references is not configured. Distinct from `invalid` because nothing was rejected — the means to verify wasn't available.

Sigstore bundles whose verification did not produce `valid` are surfaced to policies rather than silently dropped, so policies decide whether to accept them. The verifier itself does not deny; policies do.

The verifier consumes Sigstore bundles (`application/vnd.dev.sigstore.bundle.v0.3+json` or compatible) and supports two kinds of signing material.

- **Fulcio (ephemeral) certificates.** The bundle embeds the certificate chain, the Rekor `SignedEntryTimestamp` (SET), and the Merkle inclusion proof. Verification is fully local: the verifier validates the cert chain to the configured Fulcio root, validates the SET against the configured Rekor public key, validates the inclusion proof against the proof's checkpoint, and confirms the cert was valid at the Rekor-witnessed integration time. No network call.
- **Static keys.** The bundle's verification material carries a public-key hint instead of a certificate. The verifier matches the hint against the configured static signer public keys. No time-witness is required because static keys are not ephemeral.

After signature and time-witness checks pass, the verifier performs **identity binding**. The source of the identity depends on the bundle's signing material: for Fulcio-signed bundles, the verifier reads the workflow `subject` URI from the cert's SAN extension and the OIDC issuer URL from a Sigstore-defined custom cert extension; for static-key-signed bundles, the verifier matches the bundle's public-key hint against the configured static public keys and uses the matching key's configured alias. The resulting identity is matched against the deployment-global signer-identity allow-list scoped to the statement's `predicateType`. The allow-list is part of the verifier configuration. A typical entry says *"for `https://slsa.dev/provenance/v1`, accept Fulcio certs whose issuer is `https://token.actions.githubusercontent.com` and whose subject matches `https://github.com/<org>/<repo>/.github/workflows/build.yml@refs/heads/main`."* A Sigstore bundle whose signer does not match the allow-list for its predicate type has `signature: "untrusted"`, even if the signature itself is cryptographically valid. The verifier emits `verification.signer = <matched-identity-string>` so policies that need finer constraints than the deployment baseline can narrow further (see *Policy-authored signer constraints* below).

Trust-root distribution is a deployment concern decoupled from the policy bundle and the attestation store. In **static-file** mode, trust roots refresh through whatever channel the deployment uses for verifier configuration (Helm, GitOps); in **TUF** mode, the engine refreshes them from the configured TUF-signed metadata source on a polling cadence. Trust roots are NOT shipped inside the policy bundle in either mode.

> **Note: policy-authored signer constraints (forward-looking pattern).** The deployment-global allow-list is the v1 baseline because it scopes one trust frontier per environment. Policies that require a tighter signer constraint than the deployment baseline MAY read `verification.signer` and refuse attestations whose signer is outside a policy-specific subset — this is policy logic, not verifier logic, and it composes cleanly with the deployment-global check (the verifier's allow-list is an upper bound; policies may narrow). A future version MAY formalize this as a metadata field on policies; in v1 it is a Rego pattern.

**Stage 4 — Prepare.** The engine assembles the per-policy input contract:

- `input.attestations` — a flat array of attestations whose `predicateType` matches the policy's declared `predicate`, pre-filtered by the engine.
- `input.context` — caller-supplied context: subject(s), invoking mode, environment tag, evaluation timestamp.
- `input.parameters` — the parameters resolved through precedence (Section 6.5).
- `input.verification` — the signature-verification record per Sigstore bundle.
- `input.external` — the external-data map, populated from configured providers (server only).

Pre-filtering by `predicateType` is the engine's mechanism for letting policies *easily access pre-filtered relevant attestations*. A policy that declared `predicate: "https://cyclonedx.org/bom/v1.4"` sees a flat array of CycloneDX SBOM attestations — nothing else. The policy does not have to scan a global attestation list, does not have to filter by predicate type in Rego, and does not need to know what other attestations the resolver gathered. This is an engine convenience, not a security boundary; the full set remains in the resolver's records and in the audit log.

External-data fetching (`input.external`) is server-only. The CLI delegates evaluations that require external data to the server; alternatively, the CLI runs in offline mode with `input.external = {}`.

**Stage 5 — Evaluate.** A policy whose prepared `input.attestations` is empty resolves from its `evidence` setting before any Rego runs (Section 4.2) — `required` yields `FAIL` with a `NO_MATCHING_ATTESTATION` violation, `optional` yields `SKIPPED`. Every remaining policy is evaluated in parallel (the engine uses Go's `errgroup` semantics — no DAG, no inter-policy dependencies, no orchestration engine). Each policy runs against its prepared input, produces a `violations` set, and is recorded with its execution duration and final status (`PASS`, `FAIL`, `ERROR`, `SKIPPED`, `NOT_EVALUATED`). Per-policy timeout defaults to 5 seconds; overall timeout defaults to mode-appropriate values (Section 6.9).

**Evaluation strategy.** `EvaluationRequest.Evaluation` (Section 3.2) selects how the engine schedules the resolved policy set, and the calling mode populates it — the CLI from `--collect-all`/`--fail-fast`, the server from the request body. `collect-all`, the CLI and server default, evaluates every policy and reports each one. `fail-fast` cancels in-flight evaluations on the first `enforcement: error` failure and reports the cancelled policies as `NOT_EVALUATED`, trading report completeness for latency; it never changes the verdict, because a single `enforcement: error` failure fails the evaluation under either strategy. The K8s admission webhook MUST run `fail-fast`. The strategy is a property of the evaluation rather than of any policy or profile within it: one run has one scheduler, so the request carries it alone.

**Stage 6 — Aggregate.** The engine computes the overall verdict: `PASS` if every `enforcement: error` policy passed; `FAIL` otherwise. It emits the structured result (Section 6.8). If `GenerateVSA` was requested, it emits an unsigned VSA Statement that the deployment pipeline signs (Section 6.4).

### 6.3 The Rego input contract

Every policy receives the same input shape:

```text
input.attestations  : SigstoreBundle[]                 # flat array, pre-filtered to the policy's declared predicateType
input.context       : { subjects, environment, mode, timestamp, profiles }
input.parameters    : the policy's resolved parameter block
input.verification  : map[string]VerificationRecord    # keyed by bundle digest
input.external      : map[string]ProviderResult        # keyed by provider name
```

`input.attestations` is a flat array because every policy declares exactly one `predicate` (Section 4.2); the engine pre-filters and the policy iterates without indexing by predicate type. `input.context.profiles` is the list of top-level profile references the request named — always an array, even for the common single-profile case.

Policies emit a `violations` set. An empty set is a pass; a non-empty set is a fail. An empty `input.attestations` never reaches the Rego, because Stage 5 resolves that case from `evidence` first (Section 4.2), so a policy body assumes at least one attestation and does not guard for absence. Each violation MUST contain a machine-readable `code` and a human-readable `message`; SHOULD contain a `details` object with the data that drove the decision; MAY contain a `remediation` field with an actionable suggestion.

```rego
violations contains v if {
    some att in input.attestations
    count(att.predicate.components) < input.parameters.min_components
    v := {
        "code": "SBOM_INSUFFICIENT_COMPONENTS",
        "message": sprintf("SBOM has %d components, requires %d",
                           [count(att.predicate.components), input.parameters.min_components]),
        "details": { "components": count(att.predicate.components) },
        "remediation": "Configure the SBOM generator to include transitive dependencies.",
    }
}
```

Policies do not return booleans, enforcements, or remediation actions. Enforcement is metadata; remediation is per-violation prose. There is no `allow`/`deny` decision in Rego — the engine derives the verdict from `violations` cardinality and policy enforcement at aggregation time.

### 6.4 Result attestation generation

VSA generation is opt-in in the CLI (`--generate-vsa`) and the central server's REST API (`generateVSA: true`). The K8s admission webhook does **not** generate VSAs: every admission event would emit one, the volume is wrong (an admission denial is not a downstream-consumable event), and the back-and-forth write to the attestation store creates load that admission cannot tolerate. Admission's audit trail is the server's decision log, not a VSA.

When the request names multiple top-level profiles (Section 4.8), the engine emits **one VSA per top-level profile** — each VSA's `policy.uri` points to the specific profile, and each carries the *union verdict* (the verdict computed across all profiles together by the conflict resolver). A consumer who only cares about a specific profile verifies that VSA; a consumer that wants the full evaluation provenance correlates the VSAs from one event by verifier, subject, and `timeVerified`. The single-profile case is a degenerate one — exactly one VSA emitted.

The VSA shape:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "myapp", "digest": { "sha256": "a3f8…" } } ],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": { "id": "https://policy-engine.example.com/v1" },
    "timeVerified": "2026-05-01T10:30:00Z",
    "resourceUri": "pkg:oci/example/myapp@sha256:a3f8…",
    "policy": {
      "uri": "global/security/tier1-production/v1",
      "digest": { "sha256": "<bundle-resolved-policy-set-digest>" }
    },
    "verificationResult": "PASSED",
    "verifiedLevels": [ "SLSA_BUILD_LEVEL_UNEVALUATED" ],
    "inputAttestations": [
      { "uri": "registry.example.com/myapp@sha256:<referrer-1>",   "digest": { "sha256": "<bundle-digest-of-provenance>" } },
      { "uri": "registry.example.com/myapp@sha256:<referrer-2>",   "digest": { "sha256": "<bundle-digest-of-sbom>" } },
      { "uri": "registry.example.com/myapp@sha256:<referrer-3>",   "digest": { "sha256": "<bundle-digest-of-vuln-scan>" } },
      { "uri": "https://archivista.example.com/download/<gitoid>", "digest": { "sha256": "<bundle-digest-of-pr-review>" } },
      {                                                            "digest": { "sha256": "<bundle-digest-of-source-sast>" } }
    ]
  }
}
```

The engine evaluates arbitrary policies; it does not infer SLSA build levels from policy outcomes. `verifiedLevels` is therefore emitted with one of two SLSA-spec-defined `SlsaResult` values: `SLSA_BUILD_LEVEL_UNEVALUATED` when `verificationResult` is `PASSED`, and `FAILED` when `verificationResult` is `FAILED`. A profile whose policies happen to align with a specific SLSA Build Level does not cause the engine to claim that level — making such a claim is a profile-authoring concern reserved for a future override mechanism, not a v1 engine capability.

`inputAttestations` is the SLSA-spec optional `ResourceDescriptor` array recording every Sigstore bundle that was in the resolver's gather at evaluation time (Section 5.4 phases A + C, post-dedup). Each entry MUST carry the bundle's canonical `digest`; `uri` is optional per the in-toto `ResourceDescriptor` contract (required only when neither `digest` nor `content` is set, and the engine always sets `digest`) — entries omit `uri` when the storage location is not a stable, publicly-resolvable address (e.g., an internal store reachable only from the central server, or a backend that doesn't expose stable URIs). The engine emits this field unconditionally when it has at least one Sigstore bundle to record; for a `FAILED` verdict driven by zero discovered attestations, the field is absent. Auditors and downstream consumers use the digest list to confirm exactly what evidence the verifier saw, without trusting the verifier's word for it.

In **engine-emits-unsigned** mode, the deployment pipeline (or any downstream component) signs the Statement, packages it as a Sigstore bundle, and publishes it to the attestation store (Section 5.6) under the same subject digest. In **engine-signs** mode, the engine performs the signing itself and emits a ready-to-publish Sigstore bundle. In either mode, subsequent evaluations can find the VSA under the subject digest and use a *"VSA from trusted verifier MUST be present"* policy as the only check.

> **Trust frontier.** A deployment that allows VSAs signed by the workflow being verified is doing **self-attestation**: the VSA is only as trustworthy as that workflow's integrity, because a rogue commit in the same workflow can skip the engine entirely, hand-craft a `verificationResult: "PASSED"` Statement, and sign it with the same Fulcio identity any legitimate run would carry. Engine-signs does not by itself defend against this — when the CLI runs in the build workflow's OIDC context, the Fulcio cert it acquires is still that workflow's identity. The defence is the verifier-side allow-list for the VSA predicate. For a compliance-grade gate, configure that allow-list to require a signer identity the verified workflow cannot mint a Fulcio cert for: typically the central server's stable identity (a static key or a deployment-specific workload identity), or a dedicated verifier workflow whose Fulcio subject is distinct from build-workflow subjects.

### 6.5 Parameter precedence

Parameters resolve through three levels, evaluated **per parameter key** (not by wholesale block replacement):

```text
Runtime override   (CLI --param flags / server API request body)   ← highest
Profile-direct     (profile spec.policies[].parameters)
Policy defaults    (policy spec.parameters with default values)    ← lowest
```

A parameter set at a higher level wins. A parameter not set at a higher level falls through.

Each parameter declares a `type` and an optional `default` (Section 4.2). A parameter without a default must be supplied by every profile that references the policy, and bundle assembly rejects a profile that does not. A runtime override can replace a value but cannot be its only source. Parameter customization beyond what a profile declares is achieved by authoring a downstream profile. There is no separate application-level configuration object.

Runtime overrides are supported in the CLI and the server REST API. The K8s admission webhook MUST NOT accept runtime overrides — admission requests originate from Kubernetes and carry no operator intent — and MUST run with profile-direct + policy-defaults only.

### 6.6 Fail-closed default and error handling

The engine defaults to fail-closed at every stage:

- A bundle that fails to load: serve the last successfully loaded bundle until a valid one is available; if no bundle has ever loaded, refuse to serve.
- A policy with no attestation of its declared predicate: `FAIL` under `evidence: required` (the default), `SKIPPED` under `evidence: optional`. A subject with no attestations at all is the degenerate case of this rule — every `required` policy fails.
- A Sigstore bundle whose verification does not produce `signature: "valid"` (i.e., `invalid`, `untrusted`, or `unknown`) is recorded but not silently dropped; policies decide. Default-shipped policies treat any non-`valid` state as a violation.
- An external-data provider that times out or errors: deny (per-provider configurable, default `deny`).
- A Rego runtime panic: per-policy `panic: deny` (default) or `panic: allow`. The K8s admission webhook MUST treat all panics as deny regardless of authored value.
- The engine itself unreachable from the K8s admission webhook: `failurePolicy: Fail` on the `ValidatingWebhookConfiguration` causes the API server to deny the request.

Fail-closed is a design invariant, not a configuration. The engine ships with no flag to disable it.

### 6.7 Local attestation sources

A real CI workflow needs to evaluate an artefact whose attestations have been generated locally but not yet published to the central store. A real developer-loop needs to test policy logic against handcrafted Sigstore bundles without round-tripping through central storage. Neither case places attestations on the request: `EvaluationRequest` carries no attestations in any mode, and Stage 2 (Resolve) is the only path by which attestations enter an evaluation. Local attestations enter through the storage backend chain instead (Section 5.6). The CLI's `--attestation-dir <directory>` flag configures a filesystem `AttestationStore` rooted at that directory and places it in the CLI's store chain, so the graph walk discovers locally written Sigstore bundles exactly as it discovers published ones, deduplicated by bundle digest.

The central server and the K8s admission webhook resolve exclusively from the server's configured store chain. A pipeline that wants a server-side evaluation of freshly generated attestations publishes them (`Put`) before calling the server.

### 6.8 Result schema

The engine emits a structured result regardless of output format. The canonical JSON shape:

```json
{
  "status": "FAIL",
  "completeness": "complete",
  "timestamp": "2026-05-01T10:30:00Z",
  "subjects": [ { "name": "myapp", "digest": { "sha256": "a3f8…" } } ],
  "summary": { "total": 5, "passed": 3, "failed": 1, "errored": 1, "skipped": 0 },
  "policies": [
    {
      "ref": "global/platform/require-signed-images/v1",
      "version": "1.5.2",
      "status": "FAIL",
      "enforcement": "error",
      "duration_ms": 38,
      "violations": [ { "code": "UNSIGNED_OR_UNTRUSTED_IMAGE", "message": "Image nginx:1.25 not signed by an approved signer", "details": { "image": "nginx:1.25" }, "remediation": "Sign the image with an approved signer and re-publish the provenance." } ]
    },
    { "ref": "…", "status": "PASS", "violations": [] }
  ],
  "metadata": {
    "profiles": [
      { "ref": "global/security/tier1-production/v1", "version": "1.0.0" }
    ],
    "engine_version": "1.0.0",
    "duration_ms": 5214,
    "strategy": "collect-all"
  },
  "vsaStatements": []
}
```

`metadata.profiles` is always an array, even when the request named only one profile, so downstream consumers do not branch on the cardinality. For a multi-profile request, every top-level profile reference appears here with its bundle-resolved version.

`vsaStatements` is always an array — empty `[]` when `generateVSA: true` was not set on the request, otherwise containing one unsigned VSA Statement (Section 6.4) per top-level profile in the request. The single-profile case is a degenerate one (`vsaStatements.length == 1`); consumers iterate uniformly regardless of cardinality. The field is populated only on the server REST API response; the CLI writes one Statement file per top-level profile into the directory passed to `--vsa-output` (file naming: `<profile-namespace>--<profile-name>--<profile-version>.intoto.json`, with `/` in the profile reference replaced by `--` for filesystem safety) and leaves the field `[]` in the JSON output.

Output formats: `text` (TTY default; coloured symbols for pass/fail), `json` (non-TTY default; the canonical shape above), `sarif` (for source-control integration).

Per-policy status uses five values: `PASS` (no violations), `FAIL` (violations of any enforcement, or no attestation of the declared predicate under `evidence: required`), `ERROR` (panic or timeout — enforcement from metadata determines effect on overall verdict), `SKIPPED` (no attestation of the declared predicate under `evidence: optional`, counted in `summary.skipped`), `NOT_EVALUATED` (cancelled by `fail-fast`).

Overall verdict computation: `FAIL` if any `enforcement: error` policy is `FAIL` or `ERROR`; `PASS` otherwise. Warnings and infos are reported but do not flip the verdict. The CLI's `--fail-on-warning` flag changes the **process exit code** for CI gate purposes, not the violation enforcements or the overall verdict in the JSON shape.

### 6.9 Timeouts and resource limits

| Mode | Per-policy timeout | Overall timeout | Memory budget |
|------|---------------------|-----------------|---------------|
| CLI | 5 s | 30 s | 256 MB |
| Server | 5 s | 30 s | 1 GB |
| K8s webhook | 5 s | 10 s | 512 MB |

Per-policy timeout treats the policy as `ERROR` on expiry; enforcement from metadata determines effect. Overall timeout cancels in-flight policies and marks them `NOT_EVALUATED`; aggregation runs on what completed and the verdict is `FAIL` (fail-closed). Operators MAY tune these via configuration; environments SHOULD NOT.

---

## 7. Distribution and versioning

### 7.1 OCI as the substrate

Policies are distributed exclusively as OCI artefacts. The OCI registry is the source of truth for published versions; Git is the source of truth for authoring. There is no second distribution channel — no static HTTP bundle URL, no in-cluster ConfigMap-mounted bundle. OCI is the substrate because it provides content-addressable storage, mature signing via Sigstore cosign, and consistent auth (registry credentials are well-understood operationally).

```text
Git monorepo (authoring)
   │
   │  PR → review → merge to main
   ▼
CI: per-policy publish
   │
   │  one OCI artefact per (policy, semver)
   ▼
OCI registry: <registry>/policies/<namespace>/<name>:<semver>
   │
   │  bundle assembler pulls latest minor/patch per major-version line
   ▼
OCI registry: <registry>/bundles/<bundle-name>:<commit-sha>
   │
   │  pulled by engine on a polling cadence
   ▼
Engine: in-memory compiled policy set
```

[Figure 2: Authoring flows from Git to per-policy OCI artefacts to a single bundle artefact. The engine consumes only the bundle.]

### 7.2 Per-policy publishing

Each policy is published as its own OCI artefact when its `metadata.version` changes on merge to main. The artefact contains the policy directory: YAML, Rego, tests, README. Tags are SemVer (`1.5.2`, `2.0.0`); tags are immutable — re-publishing the same SemVer is rejected by the registry. The artefact's manifest records the policy reference and the SemVer.

Profiles are published the same way, under `<registry>/profiles/<namespace>/<name>:<semver>`.

### 7.3 Bundle assembly

The bundle is an OPA-compatible tar archive containing every effective `policy.rego`, the helper packages, and a manifest enumerating the included policies and their resolved versions. Assembly proceeds:

1. The CI assembler reads the bundle's source list (Section 7.5) — for v1, a single Git monorepo.
2. For every policy directory in the source, the assembler picks the highest minor/patch SemVer per major-version line and pulls the corresponding OCI artefact.
3. For every profile, the assembler pulls the highest minor/patch per major-version line and validates that every referenced policy exists in the assembled set.
4. The assembler writes the OPA bundle (a `.tar.gz` containing the compiled policies, helpers, reference data, and OPA's own `.manifest` file with `revision` and `roots`) and additionally embeds an engine-specific `bundle-manifest.json` inside the same archive. The engine-specific manifest is distinct from OPA's `.manifest` — OPA's records the bundle's internal structure for the OPA runtime; the engine's records the policy-and-profile composition for human/auditor consumption and for the engine's own catalogue queries:

   ```json
   {
     "bundle_revision": "build-456",
     "git_commit": "abc123def456",
     "build_timestamp": "2026-05-01T10:30:00Z",
     "policies_included": {
       "global/platform/require-signed-images/v1": "1.5.2",
       "global/platform/require-signed-images/v2": "2.0.0",
       "global/security/sbom-validation/v1": "1.0.0"
     },
     "profiles_included": {
       "global/security/tier1-production/v1": "1.0.0"
     }
   }
   ```

5. The assembler signs the OCI artefact with Sigstore cosign and pushes it to the registry tagged with the assembling commit SHA. **Bundle signing is mandatory**: production modes (server, admission webhook, CLI in `OCI` and `--bundle-file` modes) refuse to load an unsigned bundle and verify the cosign signature against the deployment-configured trust root on every pull (Section 7.4). Two signing paths are supported — **Sigstore keyless** (Fulcio + Rekor, natural for OSS deployments and CI workflows that already mint OIDC tokens) and **static keys** (a deployment-owned long-lived signing key, natural for air-gapped or regulated environments running their own PKI). Source-tree mode is the only path that operates without bundle-signature verification — restricted to the developer authoring loop, logs the unsigned-source warning, and refuses to emit VSAs.

The bundle's internal layout — the directory structure inside the `.tar.gz` — is:

```text
.manifest                                # OPA bundle manifest (revision, roots, …)
bundle-manifest.json                     # engine's composition catalogue (Section 7.3 above)
policies/<namespace>/<name>/<vN>/        # one directory per (policy, major version)
  policy.yaml
  policy.rego
  policy_test.rego                       # tests are bundled but not loaded by the engine at evaluation time
profiles/<namespace>/<name>/<vN>/        # one directory per (profile, major version)
  profile.yaml
helpers/<domain>/                        # helper Rego packages
  *.rego
data/                                    # organization-wide reference data
  *.json
```

The on-disk structure mirrors the source-tree layout (Section 8.1), with the addition of OPA's two manifest files and the engine's `bundle-manifest.json` at the root.

### 7.4 Bundle granularity: one global bundle for v1

A single global bundle ships every policy, every profile, every helper, and every shared reference data file the engine needs. The single-bundle shape is the engine's v1 contract; per-tenant, per-scope, and per-owner bundles are not supported. Four properties motivate the choice: (1) a single bundle is the simplest distribution surface — one OCI tag, one verifier trust root, one polling cadence; (2) bundle size at the v1 policy count (estimated at low hundreds of policies) is well below the 100 MB threshold where OPA's bundle-load cost becomes a practical concern; (3) bundle splitting is a configuration change (additional bundle entries in the OPA config), not an architectural one — an adopter that outgrows the single-bundle shape adds bundles without modifying engine code; (4) the multi-bundle case introduces an aggregator-resolution question — which bundle owns resolution when an aggregator profile references policies from several bundles — that the single-bundle design avoids by construction. The shape evolves to multi-bundle when bundle size, per-scope update cadence, or trust-domain isolation justify the configuration change described in (3).

### 7.5 Sources as a pluggable concept

The bundle assembler reads from one or more **sources**. v1 ships one source implementation: a Git monorepo whose layout follows Section 8.1. The source interface is intentionally narrow:

```go
type Source interface {
    // List returns the set of policy and profile directories the source
    // can produce, keyed by reference triple.
    List(ctx context.Context) ([]Manifest, error)

    // Fetch returns the contents of a directory (policy.yaml, policy.rego,
    // tests, README) at the requested SemVer.
    Fetch(ctx context.Context, ref Reference, semver string) (DirContents, error)
}
```

Future source implementations might include: a non-Git artefact registry, a vendor-supplied policy catalogue, or an in-memory source for testing. Sources are configured at the assembler level, not the engine level — the engine only consumes the assembled bundle. The assembler's full configuration shape (sources list, OPA-config-equivalent, signing settings, OCI push target) is part of the assembler tool's deliverable and is intentionally out of scope for this paper; the engine sees only the resulting bundle artefact.

> **Note:** When a source is a Git monorepo, fully deprecated and removed policies are deleted from the working tree but recoverable from Git history. The bundle assembler reads only the working tree, so removal from the tree removes from the bundle. This matches the operational expectation that removing a policy from `main` removes it from production. Bundle history (older bundle tags) provides rollback — a previous bundle that contained the deleted policy is still pullable from the registry.

### 7.6 Retention, rollback, and deprecation

**Retention.** Per-policy OCI artefacts and bundle artefacts are retained on the registry indefinitely by default. Operators MAY apply a registry retention policy (e.g., delete bundle tags older than 90 days that no current deployment references). Retention is a registry concern, not an engine concern.

**Rollback.** A bundle that turns out to break things is rolled back by re-pointing the engine's bundle URL to a previous bundle tag. The engine's polling cycle picks up the new tag on the next interval (configurable; default 30 seconds). Rollback is therefore O(seconds), not O(deployments).

**Deprecation.** `metadata.deprecated: true` on a policy or profile signals that the version line is in retirement. The bundle assembler emits a warning when including a deprecated artefact; the CLI emits a warning when evaluating against one. Deprecation does not block — it is a signal to consumers to migrate. Removal is a separate, explicit step: deleting the directory from the source. After removal, profiles that still reference the removed artefact fail validation at the next bundle assembly, surfacing the orphan reference loudly.

Deprecation applies at the major-version line. v1 of a policy can be marked deprecated when v2 is published and stable; minor/patch deprecation is not supported and not meaningful — minor/patch are non-breaking by SemVer contract, and the bundle always carries the latest minor/patch.

### 7.7 What the engine pulls and how

The engine reads a single OCI bundle reference from its configuration. It pulls the bundle, verifies the signature against its configured trust roots, compiles the policies into prepared OPA queries (the long-running modes — server and webhook — pre-compile at startup; the CLI compiles per invocation), and serves evaluations against the compiled set. A polling cycle (default 30 s, conditional pulls via OCI's manifest-digest comparison) re-pulls when the bundle's digest changes. The CLI pulls per invocation, but OCI client caching makes an unchanged bundle a manifest-digest check rather than a re-download — steady-state CI runs do not pay the bundle-download cost on every invocation.

The engine does **not** pull individual policy artefacts at evaluation time. Per-policy artefacts exist for the assembler's benefit; the engine sees only the assembled bundle.

---

## 8. Governance and ownership

### 8.1 File layout

The monorepo enforces ownership through directory structure:

```text
policies/
  global/
    platform/                                # platform engineering ownership
      require-signed-images/
        v1/
          policy.yaml
          policy.rego
          policy_test.rego
          README.md
        v2/
          policy.yaml
          policy.rego
          policy_test.rego
      …
    security/                                # security ownership
      sbom-validation/v1/…
      vulnerability-scanning/v1/…
    …
  <owner-id>/                                # business-unit / team ownership
    <policy-name>/v1/…
profiles/
  global/
    platform/…
    security/…
  <owner-id>/…
helpers/
  <domain>/                                  # ships in the bundle
    <package-name>/…
data/                                        # org-wide reference data
  <reference-set>.json
CODEOWNERS
```

> **Example (TR-specific).** In Thomson Reuters' deployment, `<owner-id>` is the AIID, and the global namespaces are `platform`, `isrm`, and similar. A team's policies live at `policies/<AIID>/<policy-name>/v1/…`, owned via CODEOWNERS by the team's GitHub group. Global namespaces are owned by GitHub teams: `@tr/platform-engineering` and `@tr/isrm-product-security` (examples).

The layout is not ornamental. Each first-level directory under `policies/global/` and each `<owner-id>/` directory is a **governance boundary**: the CODEOWNERS file maps each directory to the group authorized to approve changes within it. PRs that touch multiple boundaries require approvals from each. The bundle assembler validates that no policy's `metadata.namespace` field disagrees with its on-disk path — a policy at `policies/global/platform/require-signed-images/v1/policy.yaml` MUST declare `namespace: global/platform`. Disagreement aborts assembly.

### 8.2 Approval model

The default approval rules:

| Scope | Approval requirement |
|-------|----------------------|
| `policies/global/platform/*` | Two platform engineering approvers |
| `policies/global/<other-domain>/*` | One domain-team approver + one security approver |
| `policies/<owner-id>/*` | One team approver + one peer reviewer |
| `helpers/*` | Two platform-security approvers (helpers are dependencies of many policies) |
| `data/*` | Two platform-security approvers |

These are CODEOWNERS rules, enforced at PR review by the source repository's branch protection. The engine does not evaluate or verify them; that is the SCM's job. The engine inherits whatever the SCM enforced at merge time.

### 8.3 Sensitive data and the monorepo

The monorepo MAY contain organizationally sensitive policy logic (which signers are trusted; which packages are allow-listed; which production environments have stricter gates). For organizations that want to keep the monorepo private but expose policies for read by automated tools, two operational patterns are available:

- **Direct repository access with CODEOWNERS gating.** The monorepo is private; PRs flow through the CODEOWNERS-controlled review path; published bundles are public.
- **Proxy access through an identity portal.** The monorepo is private and not directly readable; an internal identity/access portal proxies read-only access for tools that need to render policies without checkout. The portal applies the org's RBAC; the engine sees only the assembled bundle.

The engine takes no position on which pattern an organization chooses. Both produce the same bundle-shaped artefact.

> **Note (TR-specific).** TR's deployment uses the proxy pattern — the policy monorepo is not directly exposed; PS360 (TR's identity portal) renders policies for tools that need read access. The engine does not depend on PS360.

### 8.4 RBAC at the registry and storage layer

- **OCI registry RBAC.** Pull access on the bundle is required by every engine instance. Push access on per-policy artefacts is required only by the CI assembler. Push access on bundle artefacts is required only by the assembler. Operators SHOULD scope the assembler's push token to write-only on the bundle path.
- **Attestation store RBAC.** The central server holds read access on the attestation store. The K8s admission webhook, the CLI, and any other caller MUST NOT hold attestation-store credentials directly — they evaluate via the central server, which reads on their behalf.

### 8.5 Decorrelation between policies and application SDLCs

Policies live in their own monorepo, on their own release cadence, owned by security and platform teams. Application SDLCs proceed independently: a team that wants a new policy filed against their pipeline raises a PR against the policy monorepo, which is reviewed by the policy's domain owners, merged, assembled into the next bundle, and propagated to engines on their polling cadence. The team's application SDLC is unchanged.

This decorrelation is intentional. Coupling policy changes to application releases (where each app declares which policy version it gates on) reverses the security model: instead of platform-security setting a baseline that every consumer inherits, every consumer chooses its own baseline. The current model — bundle-distributed, polled, profile-selected — keeps platform-security in control of the baseline while giving consumers the ability to layer additional checks via downstream profiles in their own namespace.

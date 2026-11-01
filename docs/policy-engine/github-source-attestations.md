# GitHub Source Attestations: Verified Review and Promotion Chains

**Version:** 1.0\
**Date:** October 2026\
**Authors:** ISRM Product Security\
**Companion to:** *Policy Engine: Architecture, governance, and integration* (v1.0)

**Scope.** This companion specifies how four-eye (pull-request) reviews, branch promotions (`feat/* → dev → prod`), and release deployments are attested and verified with the policy engine. It defines the source-side predicates, producers, profiles, resolver/verifier configuration, the fleet bootstrap for ~60,000 repositories, and — normatively — the exception model (force pushes, break-glass changes, expedited hotfixes, control drift).

**The policy engine is unchanged by this document.** Everything here is producer, profile, and configuration work layered on the engine's existing contract: one bridge hop (§5.4), exact digest matching (§5.1), fail-closed evaluation (§6.6), per-policy evidence expectation (§4.2), VSA emission and consumption (§5.5, §6.4), bridge registration, and the signer-identity allow-list. Section references of the form §N.N point at the main design document.

**A schematic overview accompanies this document.** *Source Attestations — The Whole Story on One Map* (`github-source-attestations-overview.md`) maps the attestation types, the happy path, the exception paths, and the detect/block/recover flow onto one page, with `→ §N` pointers back to the sections here. Read it for the shape, this document for the normative detail.

---

## 1. Problem statement

**The question reviewed:** *can the policy engine, at deploy time, automatically fetch and verify the upstream four-eye-review attestations for every change that reached production — e.g., the review of `feat/feature1 → dev` — starting from the container image digest?*

**Verdict: the goal is sound. The deploy-time mechanism is not.** Having the engine walk git ancestry by chasing subject digests is an anti-pattern, for three structural reasons:

1. **Commit identity does not survive merges.** A review binds to the pre-merge source tip. The landed commit is a *new* identity. Under squash or rebase merges, the reviewed digest never appears anywhere in the landed history — exact-digest discovery is structurally impossible, not merely hard.
2. **No attested bridge exists between a commit and its parents.** SLSA Provenance records *build inputs*, not git lineage. Parent relationships live in the git DAG, which the engine deliberately does not touch.
3. **Completeness is undecidable by traversal.** A history walk cannot distinguish "no review required here" from "review missing here", which is fatal for a fail-closed gate. Fan-out is also unbounded.

**The sound shape** keeps the engine exactly as designed and moves history reasoning to where the knowledge lives:

- **Checkpoint gates at every merge transition**, each evaluating the *landed* commit and emitting a VSA (the verifier-of-verifiers pattern, §5.5, applied to the source side).
- **A source-side bridge predicate** (`source-provenance`) that records the reviewed parent revision as an explicit digest edge, registered with the resolver exactly like SLSA Provenance.
- **Induction instead of traversal**: each gate does at most one bridge hop and requires the *predecessor's* VSA. A PASS at the deploy gate therefore proves every transition back to the chain root was individually reviewed — without git access, recursion, or ancestry reconstruction.

---

## 2. Decision record

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | The engine is not modified. No git access, no recursion, no relaxation of one-hop/exact-match/fail-closed. | The identifiers a history walk needs are unstable across merges. Completeness is undecidable by traversal (§1). |
| D2 | A checkpoint gate runs at **every** merge to a protected branch and emits a VSA. | Enforces the review property continuously where commit identity is fresh. Collapses history into link-by-link induction. |
| D3 | All source attestations bind to the **landed (post-merge) commit**, never the PR head. | The landed commit is the only identity that survives squash and rebase. Single most important producer rule. |
| D4 | `source-provenance/v1` is a distinct predicate acting as the source-side bridge. `reviewedParentRevisions` is populated from the merge **webhook** (`head.sha`), never by walking the DAG. | The forge is the only authority that knows `c1` came from `D` under squash/rebase. The DAG never witnesses it. One code path for all merge strategies. |
| D5 | `pr-review` and `source-provenance` remain **separate predicates** (same producer, same event handler). | Scoped bridging: hops happen only where a `source-provenance` exists. And separation of fact types (human approval vs. structural merge fact), which may later come from different authorities. |
| D6 | The integration-branch gate is a **continuity gate**: every landing requires the *prior tip's* VSA, not just the current merge's review. | Closes the multi-feature hole: otherwise `VSA(D2)` proves feature 2's review and says nothing about feature 1. Fan-in becomes chain *length*, never gate *width*. |
| D7 | The checkpoint VSA is a **correctness control**, not an optimization. Deeper resolver traversal can never substitute for it. | Identity discontinuity, completeness, and verdict-freezing across a trust boundary are unreachable by traversal at any depth. |
| D8 | Completeness is defined by the **profile's policy set**, fail-closed per policy through `evidence: required` (§4.2). Boundedness by explicit digest edges only. | The engine never counts or infers an expected set. Prior releases are unreachable because nothing references them by digest. |
| D9 | Fleet bootstrap is a **baseline, not a history audit**: a `source-onboarding` genesis attestation at each protected branch's current tip, forward-only continuity from there. | SLSA Source Track continuity semantics. Makes 50k repos a finite, automatable, idempotent job. |
| D10 | Signer trust is **per-predicate, deployment-global**: one org-wide GitHub App identity per source predicate. The VSA signer is an identity no build/dev workflow can mint. Build-provenance trust rides on a standardized reusable build workflow (one `subjectPattern` regex). | Kills "50k repos = 50k signers". Four separated identities prevent self-attestation (§6.4 trust frontier). |
| D11 | Rollout is phased: producers-everywhere → onboard + audit (`warning`) → enforce pilot cohort → enforce fleet. | Audit mode surfaces coverage gaps without blocking. High-value repos may take a one-time backward audit. |
| D12 | Exceptions (force push, break-glass, expedited hotfix) are handled by **explicitly invoked emergency profiles + re-genesis**, never by weakening standard profiles. Section 7 is normative. | The exception must be attested, distinguishable (`policy.uri`), time-bound, and signed outside the developer/build trust boundary. Fail-closed remains the default for anything unattested. |

---

## 3. Predicates and producers

### 3.1 `https://attestations.thomsonreuters.com/pr-review/v1`

Emitted by the org-wide GitHub App on `pull_request` (`action: closed`, `merged: true`). Subject: the **landed** commit (`merge_commit_sha`). Predicate: approver logins, approval count, required-approver set, CODEOWNERS satisfaction, PR URL, author (so policies can enforce approvers ≠ author), timestamps. Consumed by `four-eye-review/v1`.

The approval must cover the tree that actually landed. Enabling **dismiss stale approvals on new commits** makes any push after approval re-open review, so the reviewed SHA cannot diverge from the promoted SHA behind a stale approval. (`dismissStaleApprovals` is one of the tier inputs, §3.3.)

### 3.2 `https://attestations.thomsonreuters.com/source-provenance/v1`

Emitted by the same GitHub App from the same event. Subject: the landed commit. Load-bearing field: `reviewedParentRevisions[]` — for a promotion merge, exactly one entry: the PR's `head.sha` (the reviewed source tip). For an integration-branch landing it also carries the **continuity parent** (the prior branch tip) so the continuity gate can hop to it. Additional audit fields: `mergedRevision`, `mergeStrategy`, `pullRequest`, `mergedBy`, `mergedAt`, and (recommended, per §7.6) the branch's current protection controls.

Alongside those observed controls it carries the branch's genesis-anchored **claimed tier**, copied forward link-to-link (reset only at re-genesis). A downgrade of live config changes the observed field but not the claimed one, which traces to the signed genesis. Both fields ride this one attestation, so `control-tier-current` (§7.6) compares observed against claimed as a single-predicate policy.

The same pattern anchors the **review-count bar**. `claimedRequiredApprovals` is the required-approvals count fixed at genesis (§3.3), copied forward link-to-link and reset only at re-genesis. `actualApprovals` is the count this PR actually received. `observedRequiredApprovals` is the live branch setting at merge, carried for audit and drift only. Because `actualApprovals` and `claimedRequiredApprovals` ride this one attestation, `required-count-current` (§4.1) compares them as a single-predicate policy — the real review count against the genesis bar, not against a live setting an admin can lower and restore.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "gitCommit": "c1c1…" } }],
  "predicateType": "https://attestations.thomsonreuters.com/source-provenance/v1",
  "predicate": {
    "mergedRevision": { "ref": "refs/heads/prod", "digest": { "gitCommit": "c1c1…" } },
    "mergeStrategy": "squash",
    "reviewedParentRevisions": [
      { "uri": "git+https://github.com/acme/widget-svc@refs/heads/dev",
        "digest": { "gitCommit": "d2d2…" } }
    ],
    "pullRequest": "https://github.com/acme/widget-svc/pull/512",
    "mergedBy": "carol",
    "mergedAt": "2026-05-01T09:14:00Z",
    "actualApprovals": 2,
    "claimedRequiredApprovals": 2,
    "observedRequiredApprovals": 2
  }
}
```

**Producer rule (normative):** `reviewedParentRevisions` is derived from the authenticated webhook payload (`head.sha`) or a direct API read — never from the git DAG, and never from anything a PR author can influence. `actualApprovals` and `observedRequiredApprovals` are captured from one merge-pinned snapshot of the same authenticated event, never from two reads at different instants — a split read is what a soften-merge-restore window exploits (§7.6.2). `claimedRequiredApprovals` is copied from the predecessor link, which traces to the genesis onboarding record (§3.3), and is never read from live branch settings.

### 3.3 `https://attestations.thomsonreuters.com/source-onboarding/v1`

The genesis attestation, one per protected branch, bound to the branch tip at onboarding time. Carries the repository, branch, onboarding timestamp, the **control tier** derived from actual branch-protection settings (`requiredApprovals`, `requiresCodeownerReview`, `linearHistory`, `dismissStaleApprovals`, `restrictsForcePush`), and `continuity: from-this-revision-forward`. The exact `requiredApprovals` value is also anchored here as the branch's claimed review-count bar, carried forward by `source-provenance` as `claimedRequiredApprovals` (§3.2). It is kept separate from the coarse tier so an above-floor requirement (for example three approvals) is enforced precisely rather than bucketed. Emitted by the fleet onboarding tool with its own dedicated signer. Re-emitted on re-genesis (§7.4) with `reonboarding: true` and an incident reference.

The tier derivation must also read the branch's **bypass-actor allow-list**, not only the boolean controls above. `restrictsForcePush: true` with a broad bypass set is not tier-1 in practice, because listed actors can force-push without review and the config never changes when they do (§7.1.5, bypass shape). A protected branch with a wide bypass set is classified down or flagged — never accepted as fully protected on the strength of `restrictsForcePush` alone.

### 3.4 Verification Summary Attestations

The engine emits these (§6.4). The pipeline signs them with the source-gate signer — a stable identity that no build or dev workflow can mint. The VSA's `policy.uri` records which source profile blessed the commit. Downstream consumers discriminate on it (this is what makes exceptions visible forever, §7.3).

*Note: The tier is not carried here. It rides the `source-provenance` (§3.2), which every gate already resolves.*

### 3.5 The GitHub App

One org-wide installation:

1. On merge events: emit `pr-review` + `source-provenance` (two Sigstore bundles, one handler) bound to the landed commit.
2. On `branch_protection` events and on a periodic sweep: re-emit the control assertion (drift detection, §7.6).
3. Fleet onboarding runs: enumerate repos/protected branches, read protection config, classify tier, emit `source-onboarding`, trigger the base gate for the genesis VSA. Idempotent. Re-runs onboard new repos and re-baseline drifted ones.

The GitHub App's integrity is something the source guarantee depends on: for squash/rebase merges, `c1 ← D` is not re-derivable from the DAG after the fact — the assertion rests on trusting the GitHub App at emission time (for merge commits it is independently checkable via `c1^2`).

---

## 4. Profiles, bridge and signer configuration

### 4.1 Source profiles

```yaml
# Base gate — chain genesis (first gate after onboarding)
metadata: { namespace: global/security, name: source-review-base, version: 1.0.0 }
policies:
  - policy: global/security/require-onboarding/v1       # predicate: source-onboarding/v1
    enforcement: error
```

```yaml
# Continuity gate — every landing on an integration branch (dev)
metadata: { namespace: global/security, name: source-review-continuity, version: 1.0.0 }
policies:
  - policy: global/security/four-eye-review/v1
    enforcement: error
  - policy: global/security/require-source-vsa/v1        # predicate: …/verification_summary/v1
    enforcement: error
    parameters:
      accepted_source_profiles:                          # prior tip must be blessed by one of these
        - "global/security/source-review-base/v1"
        - "global/security/source-review-continuity/v1"
        - "global/security/source-review-promotion/v1"
        - "global/security/source-review-emergency/v1"   # see §7.3
  - policy: global/security/control-tier-current/v1      # predicate: source-provenance/v1
    enforcement: error                                   # observed controls vs claimed tier, both carried in source-provenance
  - policy: global/security/required-count-current/v1    # predicate: source-provenance/v1
    enforcement: error                                   # actualApprovals vs claimedRequiredApprovals, both carried in source-provenance
```

```yaml
# Promotion gate — dev → prod
metadata: { namespace: global/security, name: source-review-promotion, version: 1.0.0 }
policies:
  - policy: global/security/four-eye-review/v1
    enforcement: error
  - policy: global/security/require-source-vsa/v1
    enforcement: error
    parameters:
      accepted_source_profiles:
        - "global/security/source-review-continuity/v1"
        - "global/security/source-review-base/v1"
  - policy: global/security/control-tier-current/v1     # predicate: source-provenance/v1
    enforcement: error                                  # observed controls vs claimed tier, both carried in source-provenance
  - policy: global/security/required-count-current/v1   # predicate: source-provenance/v1
    enforcement: error                                  # actualApprovals vs claimedRequiredApprovals, both carried in source-provenance
```

The **base gate** carries only `require-onboarding`. Genesis is a baseline assertion, not a review proof (D9, §6 caveat a). It anchors the branch's identity, tier, and claimed review-count bar, and makes no claim about whether the genesis tip itself was reviewed. Review enforcement begins at the first continuity landing. The base profile reads no `source-provenance` and requires no predecessor VSA, because the chain root has nothing upstream to hop to. It therefore omits the VSA hop and the drift policies the other gates carry.

`require-source-vsa` is the **explicit VSA-presence policy** of §5.5 (not the transparent short-circuit): it checks `policy.uri` membership, `verificationResult == "PASSED"`, and relies on the verifier for signer trust. Each dev landing requires the prior dev tip's VSA (D6). Each promotion requires the promoted tip's VSA.

`control-tier-current` compares the observed controls against the genesis-anchored claimed tier — both carried in this landing's own `source-provenance`. A branch whose protection drifted below its genesis claim fails here (§7.6), so a downgrade cannot be laundered by a later well-reviewed landing. The base gate omits the policy — genesis mints the tier from the observed config, so there is nothing yet to drift from.

`required-count-current` closes the case the review floor cannot see. `four-eye-review` reads the required count from `pr-review`, which records the *live* branch setting at merge — an admin can lower it (three approvals to two), merge, and restore it, and the landing honestly records the softened bar. `required-count-current` instead compares this landing's `actualApprovals` against the genesis-anchored `claimedRequiredApprovals`, both carried in the same `source-provenance` (§3.2). The claimed bar traces to the onboarding record (§3.3) and moves only at re-genesis, so a soften-merge-restore window fails here even when it clears the org floor and stays within a single coarse tier (§7.6.2). Like `control-tier-current`, the base gate omits it — genesis mints the bar, so there is nothing yet to drift from.

`four-eye-review` enforces an org floor of two approvals with approver ≠ author. The floor is a minimum, not a fixed count. A team needing three or four approvals raises `requiredApprovals` in branch protection. The policy reads both the required set and the actual approvers from `pr-review` (§3.1) and enforces actual ≥ required, with the org floor as the lowest any tier accepts. A team can set the bar above the floor, never below it. A team's *above-floor* bar is anchored at genesis and enforced by `required-count-current`, not by this live read, which a transient downgrade can soften (§3.2, §3.3, §7.6.2).

`control-tier-current`, `required-count-current`, and the review floor are load-bearing only at `enforcement: error`. In a `warning` rollout the policies record the violation but still admit, so a drifted or under-reviewed landing passes. The gate becomes real when the profile is promoted to `error`.

### 4.2 Resolver bridges

```yaml
resolver:
  bridges:
    - predicateType: https://slsa.dev/provenance/v1                                   # image → landed commit
      dependenciesPath: predicate.buildDefinition.resolvedDependencies
    - predicateType: https://attestations.thomsonreuters.com/source-provenance/v1     # landed commit → reviewed/continuity parent
      dependenciesPath: predicate.reviewedParentRevisions
```

Bridging happens only where a `source-provenance` exists — exactly the transitions we care about (D5).

### 4.3 Signer allow-list

```yaml
signers:
  # Authority signers are dedicated, ISRM-owned workflows that sign keyless via Fulcio.
  # Each entry pins one exact workflow subject. None is mintable by a product build or dev workflow.
  # The routine source-side signers share one repo (distinct workflow files). Break-glass and the
  # gate get their own repos, so their control planes are governed and audited independently.
  - predicateType: https://attestations.thomsonreuters.com/pr-review/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/source-attestations/\\.github/workflows/sign-source\\.yml@refs/heads/main$"        # source-app signer, whole fleet
  - predicateType: https://attestations.thomsonreuters.com/source-provenance/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/source-attestations/\\.github/workflows/sign-source\\.yml@refs/heads/main$"        # same source-app signer as pr-review
  - predicateType: https://attestations.thomsonreuters.com/source-onboarding/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/source-attestations/\\.github/workflows/sign-onboarding\\.yml@refs/heads/main$"   # same repo as source-app, distinct workflow
  - predicateType: https://attestations.thomsonreuters.com/emergency-change/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/break-glass/\\.github/workflows/sign\\.yml@refs/heads/main$"                      # §7.3 — own repo, most restricted identity
  - predicateType: https://slsa.dev/verification_summary/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/source-gate/\\.github/workflows/sign\\.yml@refs/heads/main$"                      # own repo — NOT mintable by any build/dev workflow
  - predicateType: https://slsa.dev/provenance/v1
    accept:
      - type: fulcio
        issuer: https://token.actions.githubusercontent.com
        subjectPattern: "^https://github\\.com/tr/[^/]+/\\.github/workflows/build\\.yml@refs/heads/(dev|prod)$"
```

Distinct identities, distinct blast radii: the review producer, the onboarding tool, the break-glass authority, and the gate VSA signer are four separate signing identities. If any one of them were mintable from a build or dev workflow, the guarantee collapses to self-attestation (§6.4 trust frontier). Break-glass and the gate get their own repos for independent governance. The routine source-side signers share a repo, kept apart by exact per-workflow subjects and per-workflow reviewer controls. The provenance regex presumes the **standardized reusable build workflow** — the highest-leverage fleet move. Hand-rolled build workflows degrade it into per-repo entries.

---

## 5. Verified flow

Identifiers: `F` = feature tip, `D1`/`D2` = successive dev landed commits, `c1` = prod landed commit, `img` = image digest.

```
Checkpoint A  (feat → dev, landing D1):
  GitHub App emits pr-review@D1, source-provenance@D1 (continuity parent = D0)
  Gate: Evaluate gitCommit:D1 under source-review-continuity.
        Phase A → pr-review@D1 · Phase B → hop to D0 · Phase C → VSA@D0
  ⇒ VSA_D1

Checkpoint A' (feat/feature2 → dev, landing D2): same shape, hop to D1  ⇒ VSA_D2

Checkpoint B  (dev → prod, landing c1):
  GitHub App emits pr-review@c1, source-provenance@c1 (reviewedParentRevisions = [D2] = head.sha)
  Gate: Evaluate gitCommit:c1 under source-review-promotion.
        Phase A → pr-review@c1 · Phase B → hop to D2 · Phase C → VSA_D2
  ⇒ VSA_c1

Build: standardized workflow builds img from c1, emits SLSA Provenance
       (resolvedDependencies[].gitCommit = c1), SBOM, vuln scan, signature.

Deploy gate (admission webhook → central server):
  Phase A → provenance/SBOM/vuln@img · Phase B → hop to c1
  Phase C → pr-review@c1, source-provenance@c1, VSA_c1
  tier-1 profile: image policies + require-source-vsa (finds VSA_c1) ⇒ ADMIT
```

**Every evaluation is ≤ 1 bridge hop.** The chain `img → c1 → D2 → D1 → … → genesis` is never walked in one evaluation. It is verified link-by-link, each link freezing its verdict in a VSA the next gate trusts. By induction, a deploy-gate PASS means every transition back to genesis was individually four-eye-reviewed and continuous — merge-strategy-proof because every attestation binds to landed commits, and reachability-proof because the store is content-addressed (a rebase orphaning `D` from prod's history changes nothing: `Get(gitCommit:D)` is a digest lookup).

**Multi-feature fan-in** (D6) is absorbed as dev-chain *length*: whether 2 or 200 features land before promotion, the promotion gate still does one hop to one tip whose VSA inductively covers the whole chain. Boundedness holds because previous releases are never referenced by any digest edge. Completeness holds because the profile's policy conjunction — not a count — defines "enough" (D8).

---

## 6. Fleet bootstrap

**Bootstrap a baseline, not history.** Continuity claims run forward from an onboarding revision. Nothing is asserted about prior history. Onboarding is therefore finite and automatable:

1. Enumerate repos and protected branches.
2. Read each branch's actual protection config.
3. Derive a **control tier** from real settings (for example: 2 reviewers + CODEOWNERS + linear history → `tier1-protected`; 1 reviewer → `tier2`; unprotected → `untiered`, flagged).
4. Emit `source-onboarding` bound to the current tip.
5. Run the base gate → **genesis VSA**.
6. No branch→tier registry is kept. The deploy side reads the claimed tier from the chain's `source-provenance` (carried forward from genesis, §3.2) and admits only where it meets the service's required tier.

**Where attestations and VSAs are expected.** Expectation is per-digest, never per-branch enumeration. Each evaluation resolves `Get(digest)`, hops once via `source-provenance`/provenance, and fails closed when the profile's required evidence is absent at that digest (§4.2, D8). No global registry of covered branches exists or is needed:

- **Scope is data-derived, per repo.** The protected-branch set comes from each repo's branch-protection config — read at onboarding, refreshed on `branch_protection` events (§3.5). It differs per repo. Drift re-baselines idempotently. The GitHub App emits and gates on merges into protected branches only.
- **Steady-state invariant.** Every protected-branch tip carries the evidence bound to its landed commit — `pr-review` + `source-provenance` and a passing VSA — plus `source-onboarding` at genesis. That landed-commit digest is the sole location any consumer resolves. Nothing is expected on PR heads or unprotected branches.
- **Unprotected branches are out of scope by construction.** They carry no attestations and no VSA, so a build from an unreviewed tip cannot pass a deploy gate (fail-closed), rather than being unknown. A feature tip enters the chain once — as the `reviewedParentRevisions` edge recorded when it lands — never as its own gated chain, so there is no branch recursion to bound.
- **Fleet trigger.** The central GitHub App drives the gate on the merge webhook for every landing. The resulting VSA is published under the landed-commit digest (gate signer, §3.4). The next gate therefore always resolves a fresh predecessor VSA.

**Rollout phases:**

- **Phase 0 — Producers everywhere.**\
  Install the GitHub App org-wide. Emit `pr-review` + `source-provenance` on every merge. No gates. The trail accumulates.
- **Phase 1 — Onboard + audit.**\
  Genesis everywhere. Source gates in `warning` mode. Surfaces weak protection, non-standard workflows, squash-orphaned reviews without blocking. Chained stores (§5.6) cover partial-coverage populations.
- **Phase 2 — Enforce pilot cohort.**\
  `require-source-vsa` → `error` for high-value repos.
- **Phase 3 — Enforce fleet-wide.**

**Standing caveats:**
- (a) Genesis is a trust assertion, not a proof: "onboarded" must never be read as "all history reviewed".
- (b) Control drift must be actively managed (§7.6).
- (c) The maturation path is to move the highest tiers from GitHub App-read forge state to repo-embedded policy: for example, [SLSA Source Track](https://slsa.dev/spec/v1.2/source-requirements) or [gittuf](https://gittuf.dev/). Engine, bridges, and policies unchanged.

---

## 7. Exception handling

### 7.1 Default semantics: what happens with no exception machinery

A force push to `main`/`prod` is already a privileged, out-of-band act (branch protection with `restrictsForcePush` must be bypassed by an admin). If it happens, the new tip `X` arrives without a PR merge event, so the GitHub App emits **no** `pr-review` and **no** `source-provenance` for `X`. Consequences, all automatic:

1. **The source gate fails at `X`**.\
  `four-eye-review` finds no review. `require-source-vsa` finds no bridge and therefore no prior-tip VSA. Fail-closed: no VSA is emitted for `X`.
2. **Everything downstream inherits the denial.**\
  A build from `X` yields an image whose deploy-gate `require-source-vsa` fails.\
  A later promotion whose chain passes through `X` fails. Unreviewed, history-rewritten code cannot reach production silently.\
  This is the engine working as designed, not an error case.
3. **The continuity chain is severed permanently.**\
  Even a subsequent, properly reviewed merge `Y` on top of `X` cannot heal it: `Y`'s continuity hop lands on `X`, which has no VSA, so `Y` fails, and so on forever forward.\
  Without an explicit repair primitive the branch is dead to the engine, which in practice pressures teams to bypass the deploy gate entirely.\
  An unmanaged exception is therefore worse than a designed one.
4. **Orphaned attestations are harmless.**\
  Commits discarded by the rewrite keep their attestations and VSAs in the content-addressed store.\
  Nothing bridges to them anymore, so they are unreachable by any evaluation. No revocation is needed.
5. **The genesis claim is falsified, via one of two event shapes.**\
  Either an allowed bypass actor force-pushes while the ruleset stays enabled, so the config never changes and the only signal is the `push` event with `forced: true`.\
  Or the ruleset is disabled → pushed → re-enabled, so the config flips and `repository_ruleset` webhooks fire on both edges.\
  On the chain axis both are identical — `X` has no review and no VSA — so both route to control-drift handling (§7.6) and mandatory re-baseline (§7.4).\
  They differ only in detection surface (§7.6).

### 7.2 Design principles for exceptions

1. **Never weaken a standard profile.**\
  No `enforcement` downgrades, no policy removal (the engine forbids exclusion anyway, §4.6).\
  The standard chain stays intact for everyone else.
2. **An exception is evidence, not configuration.**\
  It exists only as a signed attestation bound to the specific commit, produced by an identity outside the developer/build trust boundary.\
  Absence of evidence = denial, always.
3. **Exceptions are explicitly invoked and forever distinguishable.**\
  The emergency gate is a separate profile. Its VSA carries a distinct `policy.uri`.\
  Nothing downstream can confuse an emergency blessing with a standard one.
4. **Exceptions are time-bound and carry post-hoc obligations**.\
  They are enforced mechanically via VSA freshness windows, not via process documents.
5. **The engine records and enforces, it does not prevent.**\
  Preventing the force push is the SCM's job (the engine inherits what the SCM enforced).\
  The engine's job is to make the bypass consequential, visible, and repairable.
6. **Protection status is enforced transitively, never by a live read.**\
  The deploy gate does not query "is this branch protected right now?".\
  A live config read is TOCTOU-vulnerable: a disable → push → re-enable would pass it.\
  Instead the gate requires a fresh, passing VSA bound to the artifact digest.\
  That VSA exists only if the landed tip was reviewed and continuous.\
  Config is read solely at onboarding, re-genesis, and drift detection, then frozen into the attestations the chain carries forward.\
  When the producer freezes that config, it captures the control snapshot — `actualApprovals`, `observedRequiredApprovals`, and the tier inputs — from one merge-pinned read of a single authenticated event, never two reads at different instants. A split read is what a soften-merge-restore window (§7.6.2) exploits.

### 7.3 Break-glass: the emergency change path

**Producer.** A dedicated break-glass workflow emits:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "gitCommit": "x9x9…" } }],
  "predicateType": "https://attestations.thomsonreuters.com/emergency-change/v1",
  "predicate": {
    "incident": "https://trentreprise.service-now.com/INC0451234",
    "justification": "prod outage — hotfix bypassed review under incident commander authority",
    "authorizedBy": ["alice", "bob"],
    "changeType": "force-push",
    "branch": "refs/heads/prod",
    "expiresAt": "2026-07-09T12:00:00Z",
    "postHocReviewDue": "2026-07-11T12:00:00Z"
  }
}
```
*NOTE: This attestation is provided as an example only. Exact fields are yet to be determined. Similarly, who can execute the workflow, and who can approve a request must be documented.*

**Profile.** The emergency gate is a separate profile — profiles are conjunctive and policies are single-predicate (§4.2), so "review OR break-glass" is deliberately *not* expressible inside one profile. The disjunction lives at the (human, audited) decision to authorize break-glass. Recording the `emergency-change` attestation is what selects this profile:

```yaml
metadata: { namespace: global/security, name: source-review-emergency, version: 1.0.0 }
policies:
  - policy: global/security/break-glass-attested/v1     # predicate: emergency-change/v1
    enforcement: error                                  # valid, unexpired, trusted-signer, subject matches
  - policy: global/security/break-glass-flag/v1         # predicate: emergency-change/v1
    enforcement: warning                                # always emits a violation → permanent audit flag
```

**Invocation is central and automatic.** A force push emits no `pull_request` event, so the standard merge-webhook gate (§6) never fires for the emergency tip. Instead, once `emergency-change@X` is recorded to the store, the GitHub App invokes the `source-review-emergency` profile against `X` on the central engine and publishes the result — no per-repo pipeline, no operator console. The break-glass workflow produces the `emergency-change` attestation under the break-glass signer. The GitHub App produces the VSA under the gate signer. The two identities stay separate across an automatic handoff.

Running the gate produces `VSA_X` with `policy.uri = …/source-review-emergency/v1`. Downstream `require-source-vsa` policies accept it only where the deployment says so — the continuity gate accepts it (so the chain can continue, §4.1). The *deploy-side* acceptance is a per-tier decision with a short freshness window (e.g., 72 h):

```yaml
  - policy: global/security/require-source-vsa/v1
    enforcement: error
    parameters:
      accepted_source_profiles:
        - "global/security/source-review-promotion/v1"
        - "global/security/source-review-emergency/v1"
      time_limited_profiles:
        - "global/security/source-review-emergency/v1"
      max_age_hours: 72              # after this, deploys from the emergency lineage stop
```

**Post-hoc obligations, mechanically enforced.** The 72-hour window is the enforcement of the retroactive process: before it expires, the team must (a) land the retroactive review — a normal PR reviewing the emergency diff, producing a standard `pr-review` — and (b) complete re-genesis (§7.4), after which the branch tip carries a *standard* VSA again and the emergency VSA is no longer load-bearing. If they don't, deployments from that lineage fail when the window closes.

### 7.4 Chain repair: re-genesis

A force push severs continuity (§7.1.3). By design, nothing can retroactively assert continuity claims over rewritten history. The repair primitive is the same one used for bootstrap, run by the central onboarding tool:

1. **Land the retroactive review first.** A normal PR reviews the emergency diff and produces a standard `pr-review`. The PR must be based so its diff includes the force-pushed change `X`. Open it against a pre-incident blessed tip so `X`'s content actually appears in the reviewed diff. A PR whose merge base already contains `X` reviews an empty or unrelated diff and launders the bypass — the reviewer never sees the emergency change. (Alternatively, roll the branch back to a previously blessed tip per §7.7 and skip re-genesis entirely.)
2. **Re-read protection and re-onboard.** The onboarding tool re-reads the branch's *current* protection config and emits a new `source-onboarding` bound to the post-incident tip with `reonboarding: true` and the incident reference. The tier recorded is the observed tier. If protection is still absent or degraded, genesis is honestly low-tier (`untiered`) and the branch fails tier-gated deploys. Re-genesis never fabricates a protected claim to paper over missing controls. Restoring `restrictsForcePush` is therefore a precondition for a tier-1 re-genesis, not a side effect of it.
3. **Run the base gate → new genesis VSA** (gate signer). Continuity resumes forward from this revision. The two identities stay separate across the handoff: the onboarding signer asserts the baseline, the gate signer freezes the verdict.

**Re-genesis of an *already-onboarded* branch is privileged.** The onboarding signer is the control point. The tool requires either a referenced `emergency-change` attestation on the same tip **or** an explicit two-person administrative approval. That approval sits outside the repo's own dev/build trust boundary, so no one who can push to the repo can also re-baseline it. Otherwise re-genesis would itself be a laundering primitive — an attacker who can re-baseline at will can erase any severed chain. Whether a branch counts as *already-onboarded* is read from the platform's own onboarding record, never from a live check of its ref or protection state. Stripping protection, or deleting and recreating the branch, does not make it read as un-onboarded, so neither opens a cheaper un-privileged path to re-baseline.

**`emergency-change` authorizes re-genesis. It does not trigger it.** The two are distinct events on different clocks. The emergency gate (§7.3) fires *immediately* when `emergency-change@X` is recorded, blessing `X` for a bounded window. Re-genesis happens *later* — after the retroactive review lands and protection is restored. The referenced `emergency-change` pre-satisfies the two-person control only while it is valid (unexpired), so no *fresh* co-approval is needed in that window. Once it expires, the shortcut lapses, and re-genesis falls back to an explicit fresh two-person administrative approval. Expiry never blocks re-genesis — it only removes the automatic waiver of a live approval. Even with a valid `emergency-change`, re-genesis is never fully hands-off: because "the retro-review covered `X`" (step 1) is not machine-checkable, a human still triggers the re-baseline and vouches for the clean state. Nothing auto-runs re-genesis off the emergency attestation.

The seam remains permanently auditable. The branch's attestation history shows genesis → continuous chain → emergency-change + re-genesis → continuous chain. Nothing is hidden. The induction is honest about where it restarts.

### 7.5 Expedited hotfix

The 02:00 hotfix merged with a single approver is the same machinery with a milder profile: `source-review-hotfix/v1` (one approval + valid `emergency-change` reference), explicitly invoked, VSA distinguishable by `policy.uri`, deploy-side acceptance time-bound exactly as in §7.3. No re-genesis is needed — history was not rewritten and the continuity hop still lands on a blessed tip, so the chain continues through the hotfix VSA. The retroactive second review clears the flag within the window.

### 7.6 Control drift

Branch protection can be weakened after onboarding (the genesis then over-claims). Handling:

- The GitHub App re-emits the control assertion on `branch_protection` / `repository_ruleset` webhooks and a periodic sweep. Each `source-provenance` also carries the current control state, so the chain self-attests its controls at every link.
- A `control-tier-current/v1` policy in the source profiles compares the freshest control assertion against the tier the branch claims — both carried in the `source-provenance`. A downgraded branch fails its own gates (or flags in `warning` during rollout) rather than coasting on stale genesis claims.
- A `required-count-current/v1` policy does the same for the review-count bar, comparing `actualApprovals` against the genesis-anchored `claimedRequiredApprovals` so an above-floor requirement (for example three approvals) is enforced precisely rather than bucketed into a coarse tier (§7.6.2).
- Deliberate tier changes are re-onboarding events (new `source-onboarding` with the new tier), not silent drift.

**Detection surfaces differ by exception shape (§7.1.5).** A bypass-actor force push with the ruleset left enabled emits only a `push` event (`forced: true`). There is no config change to observe, so the push event and the missing VSA are the signals. A disable → push → re-enable emits two `repository_ruleset` edges plus the push. The periodic sweep sees only the current state, so a transient disable that opens and closes between sweeps is invisible to it. The forge audit log is the durable record and the source of truth for reconciliation.

**Re-enabling a ruleset is forward-only.** It restores the configuration posture. It does **not** re-validate, quarantine, or clear commits pushed while the rule was off. The force-pushed tip `X` keeps its unreviewed, VSA-less status — GitHub rulesets are not retroactive. A ruleset disable on an onboarded branch is therefore a **sticky controls-dropped incident**. Re-enabling heals the config but leaves the chain severed. The flag clears only by re-genesis (§7.4), for which restored protection is a precondition, not a substitute.

#### 7.6.1 Worked example: tier downgrade → review laundering → deny

A `dev` branch onboarded at tier 1 (claimed tier 1). The attack lowers protection, lands weakly-reviewed changes, restores protection, then lands one correctly-reviewed PR — aiming to have that final passing VSA vouch for the whole run.

| # | Actor / where | Event | Chain effect |
|---|---------------|-------|--------------|
| T0 | steady state | `dev` tip carries a passing tier-1 VSA | Landings admit. |
| T1 | **[human]** admin lowers `requiredApprovals` 2→1, allows self-approval | `branch_protection` edge. Live controls now below tier 1. | Claimed tier stays 1. The GitHub App copies it forward in `source-provenance` from signed genesis, outside the pusher's reach. |
| T2 | **[human]** self-approved PRs land | Each emits `pr-review` + `source-provenance` whose observed controls sit below the claimed tier. | `control-tier-current` fails each landing → **no passing VSA** for these tips. The chain severs at the first one. |
| T3 | **[human]** admin restores tier-1 protection | `branch_protection` edge. Live controls back to tier 1. | Observed meets claimed again, but only from this tip forward. |
| T4 | **[human]** one correctly-reviewed PR lands | `pr-review` (two approvals, approver ≠ author) + `source-provenance` (observed = tier 1) | `control-tier-current` passes for this landing, but the continuity hop (phase C) needs the prior tip's passing VSA — the T2 tip has none → **gate fails, no VSA**. |
| T5 | **[auto][central]** deploy gate | Build + deploy from the T4 tip | `require-source-vsa` finds no passing VSA at that tip → **DENY**. The clean PR cannot launder the severed run. |

The attack fails on two independent controls. `control-tier-current` denies each downgraded landing a passing VSA (§4.1). Induction then blocks the clean PR from chaining over a severed predecessor — a later passing VSA never reconstitutes a broken link. Re-baselining the claim downward instead of the live config would require re-genesis, which is privileged (§7.4). Recovery is re-genesis at the restored tier, which restarts continuity forward. The downgrade window stays visible in the attestation and forge-audit history.

#### 7.6.2 Worked example: above-floor bar → soften-merge-restore → deny

A `dev` branch onboarded when the team required **three** approvals (the org floor is two). The attack lowers the requirement to two, lands a two-approval PR, then restores three — aiming to have the landing honestly record "two required, two given" and pass. Two approvals clear both the org floor and a coarse tier, so neither the review floor nor `control-tier-current` sees the shortfall.

| # | Actor / where | Event | Chain effect |
|---|---------------|-------|--------------|
| T0 | steady state | `dev` tip carries a passing VSA. `claimedRequiredApprovals` = 3, anchored at genesis (§3.3). | Landings admit. |
| T1 | **[human]** admin lowers `requiredApprovals` 3→2 | `branch_protection` edge. Live setting now two. | Claimed bar stays 3 — copied forward in `source-provenance` from signed genesis, outside the pusher's reach. |
| T2 | **[human]** two-approval PR lands | `pr-review` (actual = 2) + `source-provenance` (`actualApprovals` = 2, `observedRequiredApprovals` = 2, `claimedRequiredApprovals` = 3), all from one merge-pinned snapshot (§3.2). | `four-eye-review` passes (2 ≥ org floor 2). `required-count-current` fails: `actualApprovals` 2 < `claimedRequiredApprovals` 3 → **no passing VSA**. The chain severs here. |
| T3 | **[human]** admin restores `requiredApprovals` 2→3 | `branch_protection` edge. Live setting back to three. | The restore never touches the frozen `actualApprovals` = 2 on the T2 tip. Nothing heals. |
| T4 | **[auto][central]** deploy gate | Build + deploy from the T2 tip | `require-source-vsa` finds no passing VSA → **DENY**. |

The attack fails on `required-count-current` alone. The org floor is met and the coarse tier is unchanged, so the two controls that would catch a drop below the floor or a tier change both pass — the count control is the one that sees two-versus-three. It works because `claimedRequiredApprovals` is anchored at genesis and moves only by re-genesis (§7.4), and because `actualApprovals` and the claimed bar ride the same `source-provenance`, so one single-predicate policy compares them (§4.1). Capturing both from one merge-pinned snapshot (§3.2, §7.2) is what denies the attacker a split read where `actualApprovals` reflects the softened window but the compared bar reflects the restored setting. The soften window stays visible in the forge-audit history as two `branch_protection` edges bracketing the merge (§7.6).

### 7.7 Non-exceptions

- **Reverts** are ordinary PRs: reviewed, merged, attested, chained. Nothing special.
- **Force-push rollback to a previously blessed tip**: the restored tip already carries a valid VSA, and the next merge's continuity hop lands on it, so the chain survives. The event is still a protection bypass. It triggers the §7.6 sweep and an audit record, but requires no break-glass VSA if the tip's standard VSA is within freshness. If it has aged out, treat as §7.3.
- **Branch deletions / re-creations** of a branch the platform records as onboarded are re-genesis events (§7.4) – not a fresh, un-privileged onboarding. Recreating the branch neither sheds its onboarded status nor resets its chain outside that control. A branch with no onboarding record is an ordinary first onboarding.

### 7.8 What the engine can and cannot do

**Can the engine handle a force push to main without reviews? Yes, in the sense that matters:** it deterministically denies promotion and deployment of the unreviewed tip (fail-closed, no configuration needed), it can accept an explicit, signed, time-bound break-glass attestation through a separate emergency profile, it makes the exception permanently visible in the VSA chain, and it mechanically enforces the post-hoc review deadline via freshness windows.

**What it cannot do:** prevent the force push (SCM control), assess whether the emergency change was *wise* (human control), or restore continuity claims over rewritten history (nothing can — re-genesis restarts the induction honestly). Two residual risks remain. First, the break-glass signer's holders, bounded by the manual trigger and audit. Second, deploy-side acceptance of emergency VSAs during the window, bounded by `max_age_hours` and tier policy.

### 7.9 Worked example: force push → deny → break-glass → recovery

A concrete `prod` force-push timeline. Markers: **[human]** an explicit human act. **[auto]** central tooling with no human in the loop. **[central]** runs on the security platform, not repo CI.

| # | When | Actor / where | Event | Chain effect |
|---|------|---------------|-------|--------------|
| T0 | — | steady state | `prod` tip `w8` carries `pr-review@w8`, `source-provenance@w8`, `VSA_w8` | Deploys from `w8` admit. |
| T1 | incident | **[human]** on-call, via admin bypass or ruleset disable | Force push `x9` to `prod`, no PR | `push{forced:true}` fires (plus `repository_ruleset` edges if disabled). No `pr-review` / `source-provenance` for `x9`. |
| T2 | +seconds | **[auto][central]** App | No merge event exists to gate `x9` | `x9` has no VSA. Fail-closed. |
| T3 | build | **[auto]** build workflow | Builds `img` from `x9` | Deploy gate resolves `img → x9`, finds no VSA → **DENY**. Unreviewed code cannot ship. |
| T4 | incident | **[human]** IC + second approver, break-glass workflow | Two-person break-glass emits `emergency-change@x9` (break-glass signer) | Authorizes the emergency profile for `x9`. |
| T5 | +seconds | **[auto][central]** App | Invokes `source-review-emergency` against `x9`, publishes `VSA_x9` (`policy.uri = …/source-review-emergency/v1`, gate signer) | `x9` blessed **for ≤72 h** where a tier accepts the emergency profile. |
| T6 | ≤72 h | **[human]** deploy | Emergency deploy of `img` | Deploy-side `require-source-vsa` accepts the emergency VSA within `max_age_hours: 72` → ADMIT. Permanent audit flag set (§7.3 `break-glass-flag`). |
| T7 | ≤72 h | **[human]** team | Retroactive-review PR whose diff **includes** `x9` (§7.4.1) lands → standard `pr-review` | The emergency change is now genuinely reviewed. |
| T8 | ≤72 h | **[human]** admin restores `restrictsForcePush`, then **[auto][central]** onboarding tool re-genesis (§7.4) | New `source-onboarding` (observed tier) + base gate → new genesis VSA, `reonboarding: true` | Standard chain restarts at the post-incident tip. Emergency VSA no longer load-bearing. |

**The >72 h branch.** If T7–T8 do not complete before the window closes, the emergency VSA ages past `max_age_hours` and **every deploy from that lineage fails**. No human need remember to follow up — the freshness window enforces the deadline. The branch is not bricked. Completing the retroactive review and re-genesis at any later time restarts continuity forward from the new genesis. Until then, `prod` cannot ship. If protection was never restored, re-genesis records `untiered` and tier-1 deploys keep failing (§7.4.2) — the honest low tier, not a fabricated pass.

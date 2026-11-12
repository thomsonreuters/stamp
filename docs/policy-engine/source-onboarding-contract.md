# Source-onboarding contract

This checklist makes the source-onboarding requirements in work item 101999
and `github-source-attestations.md` §§3.3, 3.5, 6, and 7.4 actionable for
implementation. It defines the predicate and producer boundary; it does not
implement fleet orchestration.

## Predicate and statement checklist

Every `source-onboarding/v1` statement must:

- Use the fixed predicate URI
  `https://attestations.thomsonreuters.com/source-onboarding/v1`.
- Have a subject for the exact current tip of the protected branch, represented
  as a `gitCommit` digest. Do not substitute a default-branch name, PR head, or
  earlier revision.
- Include these required predicate fields:

  | Field                     | Contract                                                                       |
  | ------------------------- | ------------------------------------------------------------------------------ |
  | `repository`              | `owner/name`; retain immutable platform ID for record lookup.                  |
  | `branch`                  | Full branch ref, such as `refs/heads/main`, not a short name.                  |
  | `onboardingTime`          | Producer-supplied UTC RFC 3339 timestamp; no predicate default.                |
  | `requiredApprovals`       | Exact non-negative observed count and claimed review bar.                      |
  | `requiresCodeownerReview` | Boolean from the same protection snapshot.                                     |
  | `linearHistory`           | Boolean from the same protection snapshot.                                     |
  | `dismissStaleApprovals`   | Boolean from the same protection snapshot.                                     |
  | `restrictsForcePush`      | Boolean from the same protection snapshot.                                     |
  | `bypassActors`            | Complete allow-list; entries identify actor kind/ID and bypass mode/scope.     |
  | `tier`                    | Derived from controls and bypass list: `tier1-protected`, `tier2`, `untiered`. |
  | `continuity`              | Constant `from-this-revision-forward`; no pre-onboarding history claim.        |

`requiredApprovals` is anchored independently of the coarse tier, so above-floor
requirements remain exact. `bypassActors` must include an empty list when no
actors are allowed. Each bypass entry must preserve enough detail to identify
who can bypass which controls; unresolved or unsupported entries must not be
silently omitted.

- Include optional re-genesis fields only as a consistent pair: both absent on
  first onboarding, or `reonboarding: true` with a non-empty incident reference
  on re-genesis. Reject `reonboarding: false` paired with an incident reference,
  a true marker without an incident reference, and an incident reference
  without the true marker.
- Keep predicate construction deterministic. In particular, timestamps and
  actor ordering/representation come from the producer's observation and are
  not generated or normalized nondeterministically by the predicate.

## Tier and evidence behavior

- Derive the tier from one observation of all listed settings and the complete
  bypass-actor list. `restrictsForcePush: true` alone is never sufficient for
  `tier1-protected`.
- A bypass entry that grants access to a broad or unbounded population (for
  example, an organization/repository role or a team rather than an explicitly
  identified principal) is broad. A broad entry, or an entry whose effective
  scope cannot be resolved, must downgrade or flag the tier and cannot qualify
  as `tier1-protected`. Record all entries even when they cause a downgrade.
- Do not emit a strong-tier assertion when any required setting or bypass
  evidence is missing, unsupported, or inconsistent. Surface the
  repository/branch failure so the central producer can retry safely.
- Emit only for protected branches. Record the observed configuration and bind
  the statement to the branch's current tip at the onboarding observation.
- Treat onboarding as a forward-only baseline, not a retroactive audit or
  proof that the baseline revision was reviewed.
- For an already-onboarded branch, complete the retroactive review before
  re-genesis, re-read protection, and bind to the post-review current tip.
  Authorize re-genesis only through a valid same-tip emergency-change
  attestation or explicit two-person administrative approval outside the
  repository build/development trust boundary. Expired emergency authorization
  requires fresh administrative approval. Record observed controls and tier
  honestly; a tier-1 claim requires restored force-push protection.
- Publish the onboarding attestation before triggering the base gate. The
  base gate produces the genesis VSA and does not require a predecessor VSA.

## Ownership and idempotency

- `stamp` owns the reusable typed predicate, schema, validation, and statement
  construction. Those components do not enumerate a fleet, authorize
  re-genesis, choose signing credentials, publish attestations, or trigger
  gates.
- The centrally controlled onboarding service/workflow owns repository and
  branch enumeration, observation, tier derivation, onboarding-state lookup,
  re-genesis authorization, signing, publication, retry/failure reporting, and
  base-gate orchestration.
- No repository build or development workflow may obtain the onboarding
  signer or authorize a re-baseline.
- Process each repository/protected-branch pair independently. A normal rerun
  must not publish a second genesis for a pair already recorded as onboarded;
  a newly protected branch/repository may receive its first genesis. Do not
  add a branch-to-tier registry.
- Branch deletion, recreation, or protection changes do not erase onboarded
  status. The lookup must use a durable platform onboarding record independent
  of the live branch ref and protection configuration.

## Onboarding record of truth

The centrally retained, signed `source-onboarding` attestation is the durable
platform onboarding record. The control plane looks it up by immutable
platform repository ID plus full branch ref, independently of the branch's
current existence or protection settings. A matching attestation means the
pair is already onboarded and any new genesis requires re-genesis
authorization. Do not create a separate branch-to-tier registry.

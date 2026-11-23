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
- `tier1-protected` requires at least two approvals, CODEOWNERS review, linear
  history, stale-approval dismissal, force-push restriction, and no broad
  bypass actor. At least one approval without every tier-1 control is `tier2`;
  zero approvals is `untiered`.
- A bypass entry that grants access to a broad or unbounded population (for
  example, an organization/repository role or a team rather than an explicitly
  identified principal) is broad. A broad entry, or an entry whose effective
  scope cannot be resolved, must downgrade or flag the tier and cannot qualify
  as `tier1-protected`. Record all entries even when they cause a downgrade.
  Only explicitly identified individual user actors are considered narrow;
  group, role, organization, and unknown actor kinds are broad.
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

## Re-genesis authorization boundary

`BuildStatement` validates statement content, not permission to re-baseline.
Setting `reonboarding: true` and an incident reference is not authorization.
**Open design decision:** the emergency-change attestation may bind to the
force-pushed incident tip, while re-genesis follows a retroactive PR and binds
to the post-review tip. The relationship between those two tips is not defined
here. The producer must not treat a same-tip check as sufficient for this
flow until the `X`/`Y` authorization semantics are agreed and tested.

Before calling it for re-genesis, the centrally controlled producer must:

1. Establish that the retroactive review has landed, then re-read the branch's
   current tip and protection settings.
2. Verify either a trusted, valid emergency-change attestation bound to that
   same tip or explicit two-person administrative approval outside repository
   build/development workflows. Reject wrong-tip emergency evidence; expired
   emergency evidence requires fresh administrative approval.
3. Supply the newly observed controls, honestly derived tier, incident
   reference, and post-review current tip to the statement builder.

The producer must test same-tip and wrong-tip emergency evidence, expiry, and
missing or insufficient administrative approvals. These checks are not
implemented by the predicate package. Its statement tests cover serialized
re-genesis fields, exact supplied-tip binding, degraded and restored controls,
and rejection of a tier-1 claim without force-push protection. They do not
prove that a supplied tip is current or that authorization was verified.

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

## Signer, publication, and base-gate requirements

`stamp` builds unsigned statements only. The central producer and trust
configuration must satisfy these requirements; they are not implemented or
enforced here.

- Use a dedicated onboarding signer with its own trust rule. It must be
  distinct from the GitHub App source signer and the gate/VSA signer, and its
  credentials and workflow permissions must be unavailable to repository build
  or development workflows.
- Publish the signed `source-onboarding` attestation before triggering the base
  gate. A gate run with no published onboarding evidence must fail.
- The base gate must verify trusted signer identity and require a matching
  `source-onboarding/v1` statement for the evaluated repository, full branch
  ref, and exact `gitCommit` tip. Reject absent, stale, duplicate, or
  mismatched evidence; mere presence of an onboarding attestation is not
  sufficient.
- The base gate produces the genesis VSA with the gate signer. It must not
  require a predecessor VSA and must not claim the genesis revision was
  reviewed; the VSA is a forward-only baseline.
- Integration tests in the producer/infrastructure project should cover signer
  identity separation, publish-then-gate ordering, missing onboarding evidence,
  and the genesis VSA's forward-only semantics.

## Operations

These are producer-side responsibilities; `stamp` supplies the predicate,
statement builder, and lookup key only.

- **Fleet trigger:** the centrally controlled producer processes each
  repository/protected-branch pair independently. Trigger cadence and exact
  event/on-demand entry points are producer decisions and are not specified by
  this contract.
- **Retry and failure reporting:** a failed pair is retried on the next run
  without affecting other pairs. Because a normal rerun must not publish a
  second genesis for an onboarded pair, publication must be idempotent per
  `RecordLookupKey`. Persistent failures are reported to the owning team.
- **Re-genesis:** requires the external authorization described in
  "Re-genesis authorization boundary".
- **Signer ownership:** the source design requires dedicated ISRM-owned
  signer workflows. The specific operational team and escalation owner must be
  confirmed by the producer project; they are not assigned here.
- **Base gate:** invoked by the producer after the attestation is published.
- **Baseline, not audit:** onboarding records the observed controls from the
  recorded tip forward. It makes no claim about earlier history
  (`continuity: from-this-revision-forward`).

### Event response and idempotent publication

The producer must implement these behaviors; they are not provided by
`RecordLookupKey`:

1. **Unseen identity:** for a protected repository/branch pair with no verified
   onboarding record, publish one signed attestation for the observation's tip.
2. **Published, gate incomplete:** verify and reuse the already-published
   signed attestation, then retry the base gate for that attestation's exact
   subject digest. Do not republish a genesis just because gate triggering
   failed or the live branch tip has since advanced.
3. **Gate complete:** treat an unchanged rerun as a no-op. Concurrent runs
   must use conditional creation or equivalent deduplication so only one
   genesis is published.
4. **Uncertain publication result:** query the durable record and verify its
   signed attestation before retrying publication. Never interpret a timeout
   as proof that publication failed.
5. **Protection drift:** record/report the observed change and let source
   policies fail closed when their claimed controls no longer hold. Do not
   replace an existing genesis automatically.
6. **Forced push or transient ruleset disable:** retain the event/audit evidence
   and the missing-VSA failure. Recovery uses the authorized
   "Re-genesis authorization boundary" path; restoring protection alone does
   not heal continuity.
7. **Sweep reconciliation:** compare periodic observations with durable
   platform audit events so a disable/restore between sweeps is not treated as
   an unchanged healthy state. Report discrepancies and preserve fail-closed
   behavior.

The source design does not set detection-latency or alerting deadlines. The
producer owner must set those operational objectives; this contract does not
assume a cadence.

## Acceptance criteria coverage

Tests are in `pkg/predicates/source-onboarding/v1`. Criteria marked
"producer" are not testable in `stamp` and need producer or integration checks.

| 101999 completion check                        | Coverage                                                                                                                    |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Attestation tied to exact tip and controls     | `TestBuildStatement_UsesCurrentBranchTip`, `TestBuildStatement_UsesObservedControlsAndTier`, `TestPredicate_RoundTrip`      |
| Broad bypass is never tier 1                   | `TestDeriveTier_AllControlCombinations`, `TestBuildStatement_RejectsTier1WithBroadBypass`                                   |
| Rerun does not duplicate genesis               | `RecordLookupKey` tests cover the stable key; idempotent publication is producer-owned                                      |
| Re-genesis records controls and incident       | `TestBuildStatement_RegenesisPreservesObservedBaseline`, `TestBuildStatement_RejectsInvalidRegenesis`                       |
| Signer separation and gate-created genesis VSA | Producer and infrastructure integration tests; requirements are documented above                                            |
| No claim about pre-onboarding history          | `TestSchema_Contract`, `TestSchema_ValidatesPredicates`, `TestPredicate_ValidateRejectsInvalidValues` (continuity constant) |

## Onboarding record of truth

The centrally retained, signed `source-onboarding` attestation is the durable
platform onboarding record. The control plane looks it up by immutable
platform repository ID plus full branch ref, independently of the branch's
current existence or protection settings. A matching attestation means the
pair is already onboarded and any new genesis requires re-genesis
authorization. Do not create a separate branch-to-tier registry.

`pkg/predicates/source-onboarding/v1.RecordLookupKey` can derive a stable index
key from that identity. The key is only a lookup aid: the producer must still
validate the matching signed attestation, which remains the source of truth.
Because the predicate records `owner/name` rather than the immutable platform
ID, the producer's durable record must authenticate and preserve the mapping
from `(platform repository ID, full branch ref)` to the signed statement
digest. It must verify that mapping when looking up an existing record; a
recreated repository with the same name but a different platform ID must not
inherit the old repository's onboarding state.

# Build environment detection

SLSA provenance asks a simple question: *which builder produced this
artifact, and under what conditions*? The framework answers that question
by detecting the build environment at run time and naming the builder
explicitly in the resulting predicate. This document discusses how
detection works, what each environment contributes, and where the
trustworthiness of the resulting claim begins and ends.

## The detection sequence

Detection is a deterministic, first-match-wins probe across a fixed
ordering of known environments.

```
GitHub Actions   --(if not present)-->   EC2 IMDS   --(if not present)-->   Generic
```

The order is chosen by specificity. GitHub Actions is the most
information-rich environment: a successful detection gives you repository,
ref, workflow file path, run identifiers, actor, and OIDC token access.
EC2 sits below it because IMDS-derived metadata is meaningful only when
running on EC2, which the framework can reliably probe. Generic is the
fallback when nothing else matches.

First-match-wins matters because environments can overlap. A self-hosted
GitHub Actions runner on an EC2 instance will match GitHub *and* EC2; the
ordering says we treat it as a GitHub build, because that is the
environment that actually governs the work being attested. EC2 metadata
about the host can still be collected by other attestors if relevant; the
build environment detector is asking a narrower question.

## What each environment contributes

### GitHub Actions

When the detector confirms it is running inside a GitHub Actions job, it
collects:

- Workflow ref (the path to the workflow file at the commit being built).
- Run identifier and attempt number.
- Repository identity and the actor that triggered the run.
- The event payload, when `$GITHUB_EVENT_PATH` points to a readable file.
- Availability of an OIDC token (the token itself is not embedded; only
  the fact that it can be obtained).

The event payload is the most variable piece. For a push, it includes
commit metadata that is independently verifiable against the git
attestor. For a pull_request, it includes the head/base refs and the PR
metadata. For workflow_dispatch, it includes the inputs provided to the
manual run. The framework records the payload as-collected and lets
downstream verifiers parse what they need.

### EC2

When IMDS responds, the detector collects:

- Instance ID, region, availability zone.
- AMI ID.
- Other identity-document fields the instance exposes.

The honest framing of EC2 metadata is "this is what the instance says
about itself, via a service Amazon hosts on the instance". The data is
trustworthy to the extent that you trust the instance and the metadata
service running on it. The metadata service itself is hardened against
in-instance tampering (IMDSv2 token-binding), but the framework cannot
distinguish a real EC2 instance from one constructed to mimic one if the
attacker controls the host.

### Generic

When no specific environment matches, the detector falls back to a
generic identifier composed of hostname, working directory, and other
neutral signals. This is the appropriate choice for unknown environments
because it produces a stable but unambiguously fallback identifier — a
verifier looking at the resulting builder URI knows immediately that the
provenance does not pin to a specific platform.

## The Builder URI convention

The detected environment is published in the SLSA provenance predicate as
a builder URI of the form:

```
https://github.com/thomsonreuters/stamp/builders/<env>/v1
```

The URI is a claim, not a proof. It asserts that the build ran in `<env>`
according to the framework's detection logic. Verifiers can use it to
route to the right policy: "trust GitHub-built provenance only when the
ref is `main` and the workflow file is the release workflow", and so on.

The version suffix exists for the same reason every other URI in the
framework carries one: a future change in what we mean by `github/v1`
becomes `github/v2`, and verifiers can upgrade on their own schedule.

## Why detection matters

SLSA provenance is meaningless without a trustworthy builder identity.
"This artifact was built somewhere, by something" is not a useful
statement. Identifying the builder is what lets a verifier reason about
the build's properties: did it run on hardware we trust, in a workflow we
control, from source we reviewed?

The detection logic is also what lets us downstream-attest things like
"this build did not run on a self-hosted runner" or "this build's OIDC
token claimed the right repository". Those policies depend on having a
stable, machine-readable name for the environment, which is what the
detector produces.

## The limits of detection

It is important to be honest about what environment detection can and
cannot prove.

Most environment signals are read from environment variables or files
written by the build system. Those signals can be spoofed by anything
running inside the build, including the build itself. A malicious build
script can set `$GITHUB_ACTIONS=true` and populate the other variables
with whatever it likes; the framework will detect "GitHub Actions" and
produce a provenance claiming so, and the signature will be entirely
valid. The signature attests that the framework saw those variables, not
that the variables were truthful.

The one signal that resists this kind of spoofing is the OIDC token —
because the token is issued by an external authority and binds the build
context cryptographically. A GitHub-issued OIDC token contains an
attested claim about the repository, ref, and workflow that triggered the
job, and that claim is signed by GitHub. A verifier who pulls the OIDC
identity out of a Fulcio cert sees what GitHub said, not what the build
said about itself.

The practical guidance is: use environment detection to populate the
provenance for diagnostic and routing purposes, but ground the
*verifiable* trust in the OIDC identity bound into the signing cert. The
two work together. Detection gives you a rich, machine-readable
environment record; the OIDC identity tells you which parts of that
record an external authority is willing to vouch for.

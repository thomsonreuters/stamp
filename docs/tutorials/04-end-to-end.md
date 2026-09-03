# Demonstrate end-to-end scenario with STAMP

The policy engine not being available yet, this short tutorial is a proof of
concept that demonstrates a complete simplified end-to-end scenario.

## What you will need

- The `stamp` binary on your `PATH`.
- The `jq` command on your `PATH`.
- The `opa` command on your `PATH`. This [Open Policy Agent](https://www.openpolicyagent.org/docs#complete-example) can easily be installed with homebrew on a Mac.

## What this will not demonstrate

This little demo will not show how policy engine would unwrap payloads, verify with Rekor, check validity with Fulcio,
verify signatures. The goal is not to implement all the checks that the policy engine would perform, but rather to demonstrate
the feasibility of the end-to-end scenario.

## What the steps will be

- run `stamp` to generate a command attestation for a shell command (we will use `exit 0`, a successful command that does nothing, but the
same scenario can be repeated with any command, including one that fails, to check that the expected result is correct)
- look at the generated attestation and unwrap it to get at the embedded payload (policy engine would additionnally perform signature
verification at this stage)
- how to look at fields in the attestation from a rego policy
- how to run `opa` with a rego policy and get a result that implements the chosen policy (in this case the policy is to only allow a command
whose execution was successful, i.e. had an exit code of 0)

## Step 0: Generate a signing key

This tutorial will use a generated key, not quite what would happen in production, but sufficient for this POC, as this only uses
local files (both for the key and attestation) and does not actually need to communicate with Fulcio or Rekor.

```
stamp generate-key --type ecdsa --output ./demo-key
```

## Step 1: Generate a command attestation

Make stamp run your shell command, and record an attestation for this execution.

```
stamp --log-level info run   --signer key   --private-key ./demo-key.key    --persist   --template './attestations/${attestor}-${timestamp}.json'  --attestor command --set command='exit 0'
```

Abbreviated output:

```
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="execution mode determined" mode=single-attestor
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="executing single attestor" attestor_type=command
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="starting attestor pipeline" attestor_id=command
→ Generating attestation for command...
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="initializing command run attestor" attestor_id=command
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="pre-attestation completed" attestor_id=command duration_ms=0
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="starting command execution attestation" attestor_id=command
time=2026-08-27T16:59:35.699+02:00 level=INFO msg="executing command" attestor_id=command command="exit 0" working_dir="" timeout_seconds=600
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="command execution completed" attestor_id=command exit_code=0 duration_ms=5 status=success
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="attestation completed" attestor_id=command duration_ms=18 status=success
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="cleaning up after attestation" attestor_id=command
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="post-attestation cleanup completed" attestor_id=command duration_ms=0
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="generating predicate" predicate_type=https://github.com/thomsonreuters/stamp/command/v1
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="predicate generated successfully"
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="creating in-toto statement" subject_count=1
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="creating DSSE envelope"
time=2026-08-27T16:59:35.718+02:00 level=INFO msg="signing attestation envelope"
{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicGtnOmdlbmVyaWMvY29tbWFuZC1leGVjdXRpb25AY29tbWFuZCIsImRpZ2VzdCI6eyJzaGEyNTYiOiJjMjI5OTVhZGMyOTc1N2E5OWJjOTI0MjkyNmE1ZDViNWE4MDA3ZWNjNzhmMzA5NDMxNjFjZjA3MmFmNDJkOWQyIn19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vZ2l0aHViLmNvbS90aG9tc29ucmV1dGVycy9zdGFtcC9jb21tYW5kL3YxIiwicHJlZGljYXRlIjp7ImNvbW1hbmQiOnsiY29tbWFuZF9saW5lIjoiZXhpdCAwIiwic2hlbGwiOiIvYmluL2Jhc2gifSwiZXhlY3V0aW9uIjp7InN0YXJ0X3RpbWUiOiIyMDI2LTA4LTI3VDE2OjU5OjM1LjY5OTg5OSswMjowMCIsImVuZF90aW1lIjoiMjAyNi0wOC0yN1QxNjo1OTozNS43MDQ5MjErMDI6MDAiLCJkdXJhdGlvbiI6NSwiZXhpdF9jb2RlIjowLCJzdGF0dXMiOiJzdWNjZXNzIn0sImVudmlyb25tZW50Ijp7IndvcmtpbmdfZGlyZWN0b3J5IjoiL1VzZXJzL2plYW5iYXB0aXN0ZW5pdm9pdC93b3Jrc3BhY2Uvc3RhbXAvY21kIiwidXNlciI6ImplYW5iYXB0aXN0ZW5pdm9pdCIsImhvc3RuYW1lIjoiVFItSzZHMDlOS0gwMiIsInBsYXRmb3JtIjp7Im9zIjoiZGFyd2luIiwiYXJjaCI6ImFybTY0IiwidmVyc2lvbiI6IjI2LjUuMiJ9fSwib3V0cHV0Ijp7InNpemUiOnsic3Rkb3V0IjowLCJzdGRlcnIiOjB9LCJkaWdlc3QiOnt9fSwicmVzb3VyY2VzIjp7ImNwdSI6eyJ1c2VyIjowLjAwMDY1Niwic3lzdGVtIjowLjAwMTI0N30sIm1lbW9yeSI6eyJwZWFrIjoyMDk3MTUyfSwiaW8iOnt9fX19","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"84e5c4658639ec833a028f983e6bcf926d2523c2754b1777fd15909d3d792365","sig":"MEYCIQDUHUoV9ajpyxGb0z3wGXP0/A6yLBvfSUwLsoKhR/YoQAIhAIYjOH0mbSjwuufKd54QtT0OTJPj7CouMfi4ufR3G/2s"}]}
time=2026-08-27T16:59:35.726+02:00 level=INFO msg="write completed" attestation_id=594129ac-9c10-44f2-a4c0-f2f770fb6e51 predicate_type=https://github.com/thomsonreuters/stamp/command/v1 successful_destinations=1 failed_destinations=0 total_destinations=1 duration_ms=4 parallel=false failure_policy=fail-fast
time=2026-08-27T16:59:35.726+02:00 level=INFO msg="attestation persisted" destination=persist-file location=./attestations/command-1787842775.json size=1402
✓ Attestation saved to: ./attestations/command-1787842775.json
time=2026-08-27T16:59:35.726+02:00 level=INFO msg="pipeline completed successfully" attestor_id=command duration_ms=26
✓ Attestation for command completed successfully
✓ Attestor command executed successfully
```

## Step 2: look at the command attestation

The generated file on disk contains only the base64-encoded payload and a signature.

```
jq keys attestations/command-1787842775.json
```

This prints out:

```
[
  "payload",
  "payloadType",
  "signatures"
]
```

Note how the interesting bit is encoded in the nested payload.

## Step 3: Unwrap the payload

Let us unwrap the base64-encoded payload:

```
jq -r '.payload' attestations/command-1787842775.json | base64 -d | jq '.'
```

This prints out the following:

```
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:generic/command-execution@command",
      "digest": {
        "sha256": "c22995adc29757a99bc9242926a5d5b5a8007ecc78f30943161cf072af42d9d2"
      }
    }
  ],
  "predicateType": "https://github.com/thomsonreuters/stamp/command/v1",
  "predicate": {
    "command": {
      "command_line": "exit 0",
      "shell": "/bin/bash"
    },
    "execution": {
      "start_time": "2026-08-27T16:59:35.699899+02:00",
      "end_time": "2026-08-27T16:59:35.704921+02:00",
      "duration": 5,
      "exit_code": 0,
      "status": "success"
    },
    "environment": {
      "working_directory": "/Users/jeanbaptistenivoit/workspace/stamp/cmd",
      "user": "jeanbaptistenivoit",
      "hostname": "TR-K6G09NKH02",
      "platform": {
        "os": "darwin",
        "arch": "arm64",
        "version": "26.5.2"
      }
    },
    "output": {
      "size": {
        "stdout": 0,
        "stderr": 0
      },
      "digest": {}
    },
    "resources": {
      "cpu": {
        "user": 0.000656,
        "system": 0.001247
      },
      "memory": {
        "peak": 2097152
      },
      "io": {}
    }
  }
}
```

Note how the nested `exit_code` field is what a policy would like to look at and compare,
and see how this generalizes to arbitrary fields, like a pass rate in a unit test run report, or a
coverage rate, or a score in a security scan.

Store the unwrapped command attestation in a temp file:

```
jq -r '.payload' attestations/command-1787842775.json | base64 -d > attestations/command-1787842775.payload.json
```

## Step 4: See how jq can get at a field in the JSON body of the attestation

Run

```
jq -r '.payload' attestations/command-1787842775.json | base64 -d | jq '.predicate.execution.exit_code'
```

or

```
cat attestations/command-1787842775.payload.json | jq '.predicate.execution.exit_code'
```

and this shows:

```
0
```

## Step 5: Write a policy in rego

Based on the [OPA tutorial] (https://www.openpolicyagent.org/docs#complete-example),
let us now write a policy in rego, named `command.rego` with the following contents:

```
package example

default allow := false                              # unless otherwise defined, allow is false

allow if {                                          # allow is true if...
    input.predicate.execution.exit_code == 0
}
```

Now run the following opa command with our command attestation as input, and our command.rego file as policy,
getting at the `allow` variable set when that policy gets executed:

```
opa eval -i attestations/command-1787842775.payload.json -d command.rego data.example.allow
```

This will print out:

```
{
  "result": [
    {
      "expressions": [
        {
          "value": true,
          "text": "data.example.allow",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

## Step 5: Extract the truth value of the execution of the policy

Now we can use `jq` to navigate this JSON output and get at the value of interest:

```
opa eval -i attestations/command-1787842775.payload.json -d command.rego data.example.allow | jq '.result[0].expressions[0].value'
```

This will print out the truth value:

```
true
```

Assuming this runs in the k8s admission check, this would accept this attestation and thus leave the gate open for deployment.
Conversely, if the truth value is failed (i.e. the command failed), then the admission check refuses this attestation and blocks deployment.

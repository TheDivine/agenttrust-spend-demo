# Artifact inspection and policy gate — experimental

This module demonstrates a small local lifecycle: inspect files, review findings, approve exact bytes, check for changes, and evaluate a hypothetical tool request. It does not execute tools, proxy traffic, resolve npm dependencies or enforce OS/network isolation.

## Try it

From repository root with Node.js 24+:

```bash
node tools/trust.mjs inspect examples/skills/hello
node tools/trust.mjs approve examples/skills/hello ./demo-approval.json local-reviewer
node tools/trust.mjs verify examples/skills/hello ./demo-approval.json
node tools/trust.mjs gate examples/skills/hello ./demo-approval.json examples/tool-request.json examples/gate-policy.json
```

The approval record must be outside the inspected artifact and must not already exist. `local-reviewer` is a descriptive label, not an authenticated identity. Protect the approval file and policy with your operating system's permissions.

Modify SKILL.md after approval and rerun verify: valid becomes false. The policy gate then denies. Restore the demo using Git and delete demo-approval.json when finished. Inspection never invokes the inspected files or package scripts.

## Decisions and exit codes

- inspect: NO_FINDINGS (0), REVIEW (3), BLOCK (2).
- approve: creates a local record (0); a REVIEW result requires explicit --ack-review after actual review; a BLOCK cannot be approved by this command.
- verify: matching bytes and no blocking finding (0), otherwise mismatch (2).
- gate: ALLOW (0), DENY (2).
- unsupported input or operational failure: ERROR (1).

Treat every nonzero status as no permission to proceed. NO_FINDINGS means only that these few rules found nothing. Rule severity is a local demonstration convention, not a measured malware probability.

## What it checks

The manifest contains normalized relative paths and SHA-256 hashes of file contents. A directory digest covers the sorted manifest. Added, renamed, removed or modified files change it. The root .git directory is excluded. Symlinks and special files are rejected; file count, per-file size and total-byte limits bound ordinary inputs. Binary content is marked for review, not certified.

Heuristics flag simple fetch-and-shell pipelines, dynamic evaluation, instruction-override phrases, sensitive-path references, encoded-content indicators and npm lifecycle hooks. They do not cover all shell syntax, obfuscation or natural-language attacks. A lifecycle hook may be legitimate; a flagged path may be documentation.

The gate compares caller-supplied principal/tool labels, HTTPS hostname and maximum declared amount to a trusted local policy. It rejects userinfo, non-default ports and suffix lookalike domains. It does not resolve DNS, follow redirects, validate TLS, meter real costs, check request bodies or connect to the destination.

## Trust boundaries and limitations

- Approval files are unsigned local records. Anyone who can modify one can replace its digest or reviewer label. This module is not the spending simulator's signed receipt system.
- Policy and approval files must be trusted inputs controlled outside the inspected directory.
- Identity and amount are assertions in the input JSON; real identity verification and billing evidence are not implemented.
- An ALLOW is a decision simulation, not enforcement. An agent can bypass the CLI. No subprocess runs as a consequence of ALLOW.
- Use a quiescent, locally controlled directory. The inspection is not a filesystem snapshot and does not prevent concurrent file replacement or other time-of-check/time-of-use attacks. Do not inspect hostile live mounts as a security boundary.
- File permissions, empty directories, extended attributes and external dependencies are not included in the content digest. It is byte/path integrity, not a full execution environment attestation.
- No Sigstore/provenance verification, malware intelligence feed, sandbox execution, npm registry integration, key revocation or blockchain anchoring is implemented.

Next integration experiment: consume an established scanner's result, bind review to artifact digest plus scanner/policy version, then enforce through a separate authenticated runtime boundary. This requires additional design and tests before production use.

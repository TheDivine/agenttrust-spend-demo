# AgentTrust concepts and next steps

AgentTrust explores a specific boundary: an untrusted worker can propose an action, but a trusted broker decides whether the supported simulated action occurs. The goal is enforceable permissions with inspectable evidence. A clean inspection or valid signature is not proof that a package is safe.

This roadmap distinguishes code present in the development branch from proposed integrations. It does not claim production readiness, successful deployment or independently audited isolation.

## Immediate: establish the supported boundary

The enforced prototype now has captured bundles bound to an immutable runtime image ID, static review signals, Ed25519 approvals, a separate Docker worker, and a host-side broker. Approvals bind the bundle digest, principal, policy version and exact simulated purchase. The broker checks authority before running the worker and again before the simulated effect, persists local revocations, and applies transactional budget checks and replay handling.

The worker receives proposed action data; its output remains untrusted. Signing keys, policy and ledger stay outside its container. See [worker runtime](worker-runtime.md) for resource, filesystem and network restrictions.

**Acceptance:** changed artifact bytes, untrusted signers, expired or revoked approvals, altered action output and exhausted budgets must prevent the simulated effect. Runtime failure must never trigger an unrestricted fallback. Replaying a completed action must not debit the budget twice. Verification must exercise actual container restrictions as well as broker logic with test doubles.

**Further work:** document supported deployment assumptions and reproduce the boundary on another controlled host. The host, Docker daemon, kernel, runtime image and broker remain trusted. Container restrictions do not establish resistance to kernel exploits. Real payments and arbitrary tool execution remain outside this prototype.

## Next: make trust decisions portable and maintainable

### Provenance verification

Add one adapter for an established artifact ecosystem. Reuse maintained Sigstore verification tooling and SLSA provenance rather than inventing signing algorithms or a new certification scheme. Verify the artifact digest, trusted signer or builder, expected source and relevant build parameters. Build provenance and operator permission to execute are separate decisions.

**Acceptance:** reject valid signatures from unexpected identities, provenance for different bytes, and unexpected build inputs. Missing evidence must be explicit. [SLSA verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts) defines checks against consumer expectations; it does not certify runtime behavior.

### Capability-diff review

Show changed code/dependencies alongside changes to broker-enforced tools, destinations, limits and write scopes. Any changed bundle still requires new approval, even if its declared capabilities look identical.

**Acceptance:** a new destination or increased limit is visible before approval; unknown capability fields cannot disappear from the review. Static declarations are not a complete description of possible behavior.

### Policy freshness and offline evidence

Local expiry, policy-version checks and persistent revocation already exist. Next, define key rotation, distributed policy freshness and portable verification bundles with independently configured trust roots. [Sigstore bundles](https://docs.sigstore.dev/about/bundle/) provide a useful existing format for signature verification material.

**Acceptance:** an exported fixture verifies without network access, but cannot make its own embedded key trusted. Stale revocation information may support a labeled historical signature check; it must not silently authorize new execution.

### Controlled MCP integration

Inventory one integration's owner, transport, endpoint identity, tool schemas and granted scopes before adding its adapter. For supported HTTP authorization, validate issuer, audience, expiry and scope; keep downstream credentials at the broker. Follow [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), including resource binding and separate downstream tokens.

**Acceptance:** reject wrong-audience tokens, unapproved tools, changed endpoint identity and expanded scopes. Discovery descriptions remain untrusted. One adapter does not establish support for all MCP servers.

## Later: installations, external outcomes and public evidence

**VSIX admission:** start with one managed editor profile and installation/update path. Verify bounded archive extraction, exact bytes and dependencies. Alternative UI/CLI installs or writable extension directories must not bypass the claimed gate. [VS Code documents multiple installation and update routes](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace); wrapping one command is insufficient. Admission does not sandbox extension execution.

**Trusted outcomes:** current signed receipts describe simulated success. Real providers require reservations, reconciliation and explicit uncertain states. Acceptance must include timeout-after-acceptance recovery without blind duplicate execution. Signature integrity alone cannot establish settlement or complete logging.

**Transparency and blockchain:** evaluate existing transparency infrastructure first. If independent observers need public commitments, verify inclusion and consistency while protecting private content. A later blockchain adapter would need explicit finality, reorganization and fee assumptions. Acceptance must detect substituted evidence and keep unconfirmed anchors pending. Neither mechanism makes false events true, proves that omitted events never occurred, or replaces the broker's enforcement boundary.

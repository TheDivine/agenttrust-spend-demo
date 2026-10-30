# AgentTrust — local spending authorization prototype

Experimental open-source prototype. Working name only. This demonstrates policy-controlled AI-agent spending with simulated payments. It is not a production financial service, comprehensive malware detector, or general agent firewall. A local heuristic artifact inspector and policy-gate demonstration are also included.

## Enforced executor experiment

The new CLI/library path connects a captured tool bundle, an Ed25519-signed approval, a restricted Docker worker and an external simulated-spending broker. The worker requests an action through stdout; only the broker can debit its SQLite ledger. Modified bundles, forged or revoked approvals, changed worker requests and conflicting replay are rejected. A valid replay returns the stored receipt without another debit.

This is a bounded local experiment for one `simulate_purchase` capability. It is not a production sandbox, malware-free certificate, provenance service or real payment integration. `npm start` still runs the original HTTP/UI demo below; those endpoints are **not** wrapped by the new executor.

With Node.js 24+, Python 3.8+, Linux x64 and a trusted local Docker daemon:

```sh
# Build from the current trusted Node and host libraries; this mode downloads nothing.
IMAGE=$(python3 tools/build-worker-runtime.py --node-binary "$(command -v node)" --cache-dir data/worker-runtime)
AGENTTRUST_TEST_DOCKER_IMAGE="$IMAGE" npm test
npm run enforced:demo -- --image "$IMAGE"
```

The demo generates in-memory signing keys and automated sample approvals. It runs a real restricted worker, verifies a signed simulated receipt, checks replay/tampering/forgery/revocation, and saves a report under ignored `data/enforced-demo/`. This is not independent human approval. Ordinary tests explicitly skip the Docker cases unless `AGENTTRUST_TEST_DOCKER_IMAGE` is set.

See [the executor design and limits](docs/enforced-executor.md), [runtime build and containment tests](docs/worker-runtime.md), and [concepts backlog](docs/concepts.md).

## Run on Ubuntu, Windows or macOS

Requires Node.js 24 or later. No package installation, third-party dependencies or cloud account required.

1. Extract this ZIP and open a terminal in `agenttrust-spend-demo`.
2. Run `npm test`.
3. Run `npm start`.
4. Open http://127.0.0.1:8080.
5. Open the locally generated `data/access.json`. Paste the `agent` token into the UI.
6. Request $12: AUTHORIZED. Click Simulate payment. Inspect the receipt and verify it.
7. Request $120: DENIED.
8. Request $30: WAITING_APPROVAL. Replace the token with `reviewer`, refresh, approve. Switch back to `agent`, refresh, simulate payment.
9. Edit any character of a receipt's body and verify again: INVALID.

Tokens and signing keys are generated locally at first start. Never send these files to anyone or commit `data/`. Keep the service on loopback; no tunnels, shared hosting or production deployment. To reset the demo, stop the server and remove `data/` (this discards the local demo records and key).

## Implemented

- Two separate demo roles, enforced by HTTP handlers.
- Deterministic vendor, currency, per-payment and remaining-budget checks.
- Human review for purchases above $20; maximum payment $50.
- Separate authorization and execution, with ten-minute expiry and revalidation.
- Durable SQLite ledger and serialized transactional budget decrement.
- Idempotent request keys with payload-conflict detection; successful execution retries return the stored result.
- Local simulator, Ed25519 signed receipts, public key endpoint, signature verifier.
- Minimal responsive admin UI and event history.

Amounts are integer USD cents; initial budget is $100 per demo tenant. Authorization does not reserve budget. At execution the transaction atomically checks and debits it; this intentionally allows authorization to later fail if another request spent the budget. Simulator execution has no external side effect and therefore runs within the database transaction; real providers need a separate reservation/outbox/reconciliation design.

## Security and implementation limits

This first slice uses native JavaScript modules on Node 24 rather than the proposed TypeScript/PostgreSQL stack, to keep it dependency-free and runnable. SQLite support in Node may emit an experimental warning.

Only the demo tenant is exposed over HTTP. Core tests cover tenant scoping, but this is not production multi-tenant authentication. Tokens are local shared demo secrets, not user accounts, SSO, MFA or signed machine delegations. No revocation service, credential rotation workflow, policy editor or rate limiter is implemented. Private key lives outside the database but on the same host. SQLite events are application-appended and are not tamper-proof against a database administrator. Receipts prove signature integrity only, not independent settlement, authorization validity at verification time or audit-log completeness. The UI has not had browser visual QA.

No reimbursement app, real payments, provider credentials, receipt uploads or workplace infrastructure are included. Reimbursement remains a separate proposed product using shared approval concepts, pending buyer validation.

## Verified tests

`npm test` exercises positive and negative decisions, approval requirements, expiry, cross-tenant probing, idempotency conflicts, replayed execution, signature tampering, parallel processes competing for a shared budget, and HTTP role separation plus the full approval-to-simulation flow.

## Next milestone

1. Choose pilot workflow and buyer with actual observed spending/approval pain.
2. Move core contracts to TypeScript and production database migrations.
3. Add organization identity, real reviewer accounts, scoped expiring machine mandates and revocation.
4. Implement reservations, outbox, provider status reconciliation and uncertain outcomes.
5. Add a provider sandbox adapter after its capabilities and access are verified.
6. Independently verify exported signatures; add key identification and portable evidence bundles.
7. Only then consider pilot deployment and a separate reimbursement interface.

## Rechecked sources, 29 October 2026

- https://developer.bill.com/docs/bill-mcp-server — official MCP is beta/read-only; it does not create, approve or pay. A custom MCP wrapper is not a sufficient differentiation hypothesis.
- https://usa.visa.com/about-visa/newsroom/press-releases.releaseId.22856.html — October 20 pilot executes already-approved invoice payments; limited participating buyers/suppliers, not general availability.

These sources support building a provider-independent authorization/evidence prototype. They do not establish demand or willingness to pay. No buyer commitments have been inferred.


## Related projects and positioning

- [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner): multi-engine inspection of agent skills.
- [Pipelock](https://github.com/pipelab-org/pipelock): agent egress/MCP security and mediator-signed receipts.
- [Sigstore](https://docs.sigstore.dev/): software signatures and transparency infrastructure.

These projects overlap with future ideas. This repository currently implements a much narrower spending simulation, not those projects' protections. No integration, endorsement or uniqueness claim is implied.

## Feedback wanted

What paid tools do your agents use today? Where do approvals block your workflow? Which exact action would you need to stop, allow or audit? Open an issue with a synthetic example; never upload customer information or credentials.

## Roadmap

- Implemented: local spend simulator, deterministic decisions, manual approvals, signed receipts and tests.
- Implemented: local artifact manifest/digest inspection, explicit review records, change detection and hypothetical tool-request policy decisions.
- Next: independent signed-receipt verifier and authenticated scoped machine authorizations.
- Research: approvals bound to exact skill/artifact digests, integrating existing scanners, runtime enforcement.
- Not implemented: comprehensive skill/malware detection, registry/dependency analysis, runtime firewall enforcement, provider settlement or blockchain anchoring.

## License

MIT. See LICENSE. Hosted services and additional commercial features may be developed separately. The published code remains governed by its license.


## Inspect a skill and evaluate a tool request

See [artifact-gate.md](docs/artifact-gate.md) for commands, expected outcomes and important trust limitations. The inspector checks local content with a small heuristic rule set and hashes. It does not execute the inspected skill. The policy gate returns a decision only; it is not a network firewall or sandbox.

```bash
node tools/trust.mjs inspect examples/skills/hello
node tools/trust.mjs approve examples/skills/hello ./demo-approval.json local-reviewer
node tools/trust.mjs verify examples/skills/hello ./demo-approval.json
node tools/trust.mjs gate examples/skills/hello ./demo-approval.json examples/tool-request.json examples/gate-policy.json
```

All 13 automated tests passed locally at this milestone. See GitHub Actions for hosted results; no security audit or production-readiness claim is implied.

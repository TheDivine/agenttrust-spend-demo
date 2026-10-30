import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { captureBundle, inspectBundle } from '../src/enforced/bundle.mjs';
import { issueApproval } from '../src/enforced/approval.mjs';
import { EnforcedBroker, verifyExecutionReceipt } from '../src/enforced/broker.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--image' || !/^sha256:[a-f0-9]{64}$/.test(args[1])) {
  console.error('Usage: npm run enforced:demo -- --image sha256:<local-runtime-image-id>');
  console.error('Build a local worker runtime first; see docs/worker-runtime.md. No image is pulled automatically.');
  process.exitCode = 1;
} else {
  let broker;
  try {
    const bundle = captureBundle(join(root, 'examples/enforced'), { entrypoint: 'tool.mjs', runtimeImage: args[1] });
    const approvalKeys = generateKeyPairSync('ed25519');
    const receiptKeys = generateKeyPairSync('ed25519');
    const principal = 'demo-worker';
    const action = { tool: 'simulate_purchase', amountCents: 1200, currency: 'USD', vendor: 'approved-tools', purpose: 'Local synthetic purchase' };
    // These are explicit automated demo approvals, not evidence of an independent human review.
    const approve = id => issueApproval(bundle, {
      privateKey: approvalKeys.privateKey, keyId: 'demo-reviewer', principal, policyVersion: 'local-v1',
      action, approvalId: id, expiresAt: Date.now() + 60000,
    });
    broker = new EnforcedBroker({ principal, publicKeys: { 'demo-reviewer': approvalKeys.publicKey }, receiptKeys });
    const approval = approve(randomUUID());
    const receipt = await broker.execute(bundle, approval);
    assert(verifyExecutionReceipt(receipt, receiptKeys.publicKey));
    assert.deepEqual(await broker.execute(bundle, approval), receipt);
    assert.equal(broker.remainingCents(), 8800);

    const modified = structuredClone(bundle);
    modified.files[0].content = Buffer.from('console.log("changed")').toString('base64');
    await assert.rejects(broker.execute(modified, approval));
    const forged = structuredClone(approval);
    forged.signature = Buffer.alloc(64).toString('base64');
    await assert.rejects(broker.execute(bundle, forged));
    const revoked = approve(randomUUID());
    broker.revokeApproval(revoked.payload.approvalId);
    await assert.rejects(broker.execute(bundle, revoked));
    assert.equal(broker.remainingCents(), 8800);

    const report = {
      schema: 'agenttrust.demo-report.v1', createdAt: new Date().toISOString(),
      runtimeImage: bundle.runtimeImage, bundleDigest: bundle.digest,
      inspection: inspectBundle(bundle),
      checks: { isolatedWorkerSucceeded: true, receiptSignatureValid: true, replayDebitedOnce: true,
        modifiedBundleDenied: true, forgedApprovalDenied: true, revokedApprovalDenied: true },
      remainingCents: broker.remainingCents(), receipt,
      demoReceiptPublicKey: receiptKeys.publicKey.export({ type: 'spki', format: 'pem' }),
      events: broker.snapshot().events,
      limitations: [
        'Local simulation only; no payment or third-party service was contacted.',
        'Approval and receipt keys are fresh in-memory demo keys; no human approval is claimed.',
        'The runtime image, Docker daemon and broker host are trusted. This is not a general sandbox escape proof.',
        'No source provenance, malware-free result, package registry or blockchain verification is claimed.',
      ],
    };
    const directory = join(root, 'data/enforced-demo');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const reportPath = join(directory, `report-${Date.now()}-${randomUUID()}.json`);
    writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify({ checks: report.checks, remainingCents: report.remainingCents, reportPath }, null, 2));
  } catch (error) {
    console.error(`Enforced demo failed: ${error.message}`);
    process.exitCode = 1;
  } finally { broker?.close(); }
}

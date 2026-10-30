import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureBundle } from '../src/enforced/bundle.mjs';
import { issueApproval } from '../src/enforced/approval.mjs';
import { EnforcedBroker, verifyExecutionReceipt } from '../src/enforced/broker.mjs';

const TEST_IMAGE = 'sha256:' + 'a'.repeat(64);
const action = (amountCents = 1200) => ({ tool: 'simulate_purchase', amountCents, currency: 'USD', vendor: 'approved-tools', purpose: 'Synthetic purchase' });

function setup(t, { runtimeImage = TEST_IMAGE, ...options } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-broker-test-'));
  writeFileSync(join(dir, 'tool.mjs'), "let data=''; for await (const chunk of process.stdin) data+=chunk; console.log(JSON.stringify(JSON.parse(data).action));\n");
  const bundle = captureBundle(dir, { runtimeImage });
  const keys = generateKeyPairSync('ed25519');
  const receipts = generateKeyPairSync('ed25519');
  let calls = 0;
  const broker = new EnforcedBroker({ principal: 'worker-1', policyVersion: 'local-v1', publicKeys: { reviewer: keys.publicKey },
    receiptKeys: receipts, runner: async (_, { input }) => { calls++; return { stdout: JSON.stringify(input.action), exitCode: 0 }; }, ...options });
  const approve = (id, amount = 1200, overrides = {}) => issueApproval(bundle, {
    privateKey: keys.privateKey, keyId: 'reviewer', principal: 'worker-1', policyVersion: 'local-v1',
    action: action(amount), approvalId: id, expiresAt: Date.now() + 60000, ...overrides,
  });
  t.after(() => { broker.close(); rmSync(dir, { recursive: true, force: true }); });
  return { broker, bundle, approve, keys, receipts, dir, calls: () => calls };
}

test('approved request produces one simulated receipt; repeated and concurrent replay debit once', async t => {
  const { broker, bundle, approve, receipts, calls } = setup(t);
  const approval = approve('once');
  const [a, b] = await Promise.all([broker.execute(bundle, approval), broker.execute(bundle, approval)]);
  const c = await broker.execute(bundle, approval);
  assert.deepEqual(a, b); assert.deepEqual(a, c);
  assert.equal(calls(), 1);
  assert.equal(broker.remainingCents(), 8800);
  assert.equal(broker.snapshot().executions.length, 1);
  assert(verifyExecutionReceipt(a, receipts.publicKey));
  const changed = structuredClone(a); changed.payload.action.amountCents++;
  assert(!verifyExecutionReceipt(changed, receipts.publicKey));
  assert(!verifyExecutionReceipt(a, generateKeyPairSync('ed25519').publicKey));
});

test('forged approval, claimed identity, artifact flag and bundle tampering never start a worker', async t => {
  const { broker, bundle, approve, calls } = setup(t);
  const original = approve('forged');
  const signature = structuredClone(original); signature.signature = Buffer.alloc(64).toString('base64');
  await assert.rejects(broker.execute(bundle, signature));
  const principal = structuredClone(original); principal.payload.principal = 'other';
  await assert.rejects(broker.execute(bundle, principal));
  await assert.rejects(broker.execute(bundle, { ...original, artifactValid: true }));
  const changed = structuredClone(bundle); changed.files[0].content = Buffer.from('different').toString('base64');
  await assert.rejects(broker.execute(changed, original));
  assert.equal(calls(), 0); assert.equal(broker.remainingCents(), 10000);
});

test('a signed request exceeding the broker cap is denied before launch', async t => {
  const { broker, bundle, approve, calls } = setup(t, { maxAmountCents: 1000 });
  await assert.rejects(broker.execute(bundle, approve('over-cap')), /policy limit/);
  assert.equal(calls(), 0);
});

test('worker output is data: changed action, extra authority and malformed output cause no effect', async t => {
  for (const stdout of [JSON.stringify({ ...action(), amountCents: 1 }), JSON.stringify({ ...action(), artifactValid: true }), 'not JSON', JSON.stringify(action()) + '\n' + JSON.stringify(action())]) {
    const { broker, bundle, approve } = setup(t, { runner: async () => ({ stdout, exitCode: 0 }) });
    await assert.rejects(broker.execute(bundle, approve('bad-output')));
    assert.equal(broker.remainingCents(), 10000); assert.equal(broker.snapshot().executions.length, 0);
  }
});

test('expiry and persistent revocation are rechecked after a worker finishes', async t => {
  for (const mode of ['expiry', 'approval', 'key']) {
    let release, started;
    const running = new Promise(resolve => { started = resolve; });
    const now = Date.now(); let time = now;
    const { broker, bundle, approve } = setup(t, {
      clock: () => time,
      runner: async (_, { input }) => { started(); await new Promise(resolve => { release = resolve; }); return { stdout: JSON.stringify(input.action), exitCode: 0 }; },
    });
    const pending = broker.execute(bundle, approve(mode, 1200, { now, expiresAt: now + 10000 }));
    await running;
    if (mode === 'expiry') time += 10001;
    else if (mode === 'approval') broker.revokeApproval(mode);
    else broker.revokeKey('reviewer');
    release();
    await assert.rejects(pending, /expired|revoked/);
    assert.equal(broker.remainingCents(), 10000);
  }
});

test('host-side revocation denies before starting a worker', async t => {
  const { broker, bundle, approve, calls } = setup(t);
  broker.revokeApproval('revoked');
  await assert.rejects(broker.execute(bundle, approve('revoked')), /revoked/);
  assert.equal(calls(), 0);
});

test('same approval ID with a separately signed changed action conflicts', async t => {
  const { broker, bundle, approve, calls } = setup(t);
  await broker.execute(bundle, approve('same-id'));
  await assert.rejects(broker.execute(bundle, approve('same-id', 1300)), /conflict/);
  assert.equal(calls(), 1); assert.equal(broker.remainingCents(), 8800);
});

test('invalid revocation IDs cannot poison later verification', async t => {
  const { broker, bundle, approve } = setup(t);
  for (const id of ['x'.repeat(129), ' padded ', 'line\nbreak', '', null]) {
    assert.throws(() => broker.revokeApproval(id), /Invalid revocation/);
    assert.throws(() => broker.revokeKey(id), /Invalid revocation/);
  }
  const receipt = await broker.execute(bundle, approve('still-valid'));
  assert.equal(receipt.payload.outcome, 'SIMULATED_SUCCESS');
});

test('parallel broker instances share a transactional budget and persistent replay ledger', async t => {
  const storage = mkdtempSync(join(tmpdir(), 'agenttrust-ledger-test-'));
  t.after(() => rmSync(storage, { recursive: true, force: true }));
  const first = setup(t, { databasePath: join(storage, 'ledger.sqlite'), initialBudgetCents: 1000 });
  const second = new EnforcedBroker({ databasePath: join(storage, 'ledger.sqlite'), principal: 'worker-1',
    publicKeys: { reviewer: first.keys.publicKey }, initialBudgetCents: 99999,
    runner: async (_, { input }) => ({ stdout: JSON.stringify(input.action), exitCode: 0 }) });
  t.after(() => second.close());
  assert.equal(second.remainingCents(), 1000); // Restart/config cannot silently refill an existing ledger.
  const results = await Promise.allSettled([
    first.broker.execute(first.bundle, first.approve('a', 800)),
    second.execute(first.bundle, first.approve('b', 800)),
  ]);
  assert.deepEqual(results.map(r => r.status).sort(), ['fulfilled', 'rejected']);
  assert.equal(first.broker.remainingCents(), 200); assert.equal(second.snapshot().executions.length, 1);
  second.revokeKey('reviewer');
  await assert.rejects(first.broker.execute(first.bundle, first.approve('c', 100)), /revoked/);
});

test('worker failure never falls back to unsandboxed execution or a simulated success', async t => {
  const { broker, bundle, approve } = setup(t, { runner: async () => { throw Error('Docker unavailable'); } });
  await assert.rejects(broker.execute(bundle, approve('unavailable')), /unavailable/);
  assert.equal(broker.remainingCents(), 10000); assert.equal(broker.snapshot().executions.length, 0);
});

test('real Docker worker plus signed approval plus broker execution', { skip: !process.env.AGENTTRUST_TEST_DOCKER_IMAGE }, async t => {
  const { runIsolated } = await import('../src/enforced/docker-runner.mjs');
  const { broker, bundle, approve, receipts } = setup(t, {
    runtimeImage: process.env.AGENTTRUST_TEST_DOCKER_IMAGE, runner: runIsolated,
  });
  const approval = approve('docker-e2e');
  const receipt = await broker.execute(bundle, approval);
  assert.equal(receipt.payload.outcome, 'SIMULATED_SUCCESS');
  assert(verifyExecutionReceipt(receipt, receipts.publicKey));
  assert.equal(broker.remainingCents(), 8800);
  assert.deepEqual(await broker.execute(bundle, approval), receipt);
});

import { DatabaseSync } from 'node:sqlite';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { canonicalJSON, validateBundle } from './bundle.mjs';
import { verifyApproval } from './approval.mjs';
import { runIsolated } from './docker-runner.mjs';

const digest = value => createHash('sha256').update(canonicalJSON(value)).digest('hex');
const label = value => typeof value === 'string' && value.length > 0 && value.length <= 128
  && value === value.trim() && !/[\x00-\x1f\x7f]/.test(value);

// Signature integrity under an independently trusted key, not proof of a payment.
export function verifyExecutionReceipt(receipt, trustedPublicKey) {
  try {
    if (Object.keys(receipt).sort().join(',') !== 'payload,signature') return false;
    if (receipt.payload.schema !== 'agenttrust.execution.v1' || receipt.payload.outcome !== 'SIMULATED_SUCCESS') return false;
    const signature = Buffer.from(receipt.signature, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== receipt.signature) return false;
    return verify(null, Buffer.from(canonicalJSON(receipt.payload)), trustedPublicKey, signature);
  } catch { return false; }
}

/** Trusted host component. Workers never receive this object, database or keys. */
export class EnforcedBroker {
  #db;
  #principal;
  #policyVersion;
  #publicKeys;
  #maxAmount;
  #receiptKeys;
  #runner;
  #clock;
  #inflight = new Map();

  constructor({ databasePath = ':memory:', principal, policyVersion = 'local-v1', publicKeys,
    maxAmountCents = 5000, initialBudgetCents = 10000,
    receiptKeys = generateKeyPairSync('ed25519'), runner = runIsolated, clock = Date.now } = {}) {
    if (!label(principal) || !(label(policyVersion) || Number.isSafeInteger(policyVersion) && policyVersion > 0)) throw Error('Invalid broker identity or policy version');
    if (!publicKeys || typeof publicKeys !== 'object' || !Object.keys(publicKeys).length) throw Error('Trusted approval keys required');
    if (!Number.isSafeInteger(maxAmountCents) || maxAmountCents < 1 || !Number.isSafeInteger(initialBudgetCents) || initialBudgetCents < 0) throw Error('Invalid budget limits');
    if (typeof runner !== 'function' || typeof clock !== 'function') throw Error('Invalid trusted host configuration');
    if (receiptKeys.privateKey?.asymmetricKeyType !== 'ed25519' || receiptKeys.publicKey?.asymmetricKeyType !== 'ed25519') throw Error('Ed25519 receipt keys required');
    if (!createPublicKey(receiptKeys.privateKey).export({ type: 'spki', format: 'der' })
      .equals(receiptKeys.publicKey.export({ type: 'spki', format: 'der' }))) throw Error('Receipt keys do not match');
    this.#publicKeys = Object.create(null);
    for (const [id, key] of Object.entries(publicKeys)) {
      if (!label(id)) throw Error('Invalid approval key ID');
      const parsed = key?.type === 'public' ? key : createPublicKey(key);
      if (parsed.asymmetricKeyType !== 'ed25519') throw Error('Ed25519 approval keys required');
      this.#publicKeys[id] = parsed;
    }
    this.#principal = principal;
    this.#policyVersion = policyVersion;
    this.#maxAmount = maxAmountCents;
    this.#receiptKeys = receiptKeys;
    this.#runner = runner;
    this.#clock = clock;
    this.#db = new DatabaseSync(databasePath);
    this.#db.exec(`
      PRAGMA busy_timeout=5000;
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS enforced_budgets(principal TEXT PRIMARY KEY, remaining INTEGER NOT NULL CHECK(remaining >= 0));
      CREATE TABLE IF NOT EXISTS enforced_executions(approval_id TEXT PRIMARY KEY, principal TEXT NOT NULL, approval_digest TEXT NOT NULL, bundle_digest TEXT NOT NULL, receipt TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS enforced_revocations(kind TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(kind,id));
      CREATE TABLE IF NOT EXISTS enforced_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, principal TEXT NOT NULL, approval_id TEXT, event TEXT NOT NULL, time INTEGER NOT NULL);
    `);
    this.#db.prepare('INSERT OR IGNORE INTO enforced_budgets VALUES(?,?)').run(principal, initialBudgetCents);
  }

  #event(id, event) {
    this.#db.prepare('INSERT INTO enforced_events(principal,approval_id,event,time) VALUES(?,?,?,?)')
      .run(this.#principal, label(id) ? id : null, event, this.#clock());
  }

  #check(bundle, approval) {
    const revoked = this.#db.prepare('SELECT kind,id FROM enforced_revocations').all();
    const payload = verifyApproval(approval, {
      bundle, publicKeys: this.#publicKeys, principal: this.#principal, policyVersion: this.#policyVersion,
      revokedApprovalIds: revoked.filter(x => x.kind === 'approval').map(x => x.id),
      revokedKeyIds: revoked.filter(x => x.kind === 'key').map(x => x.id), now: this.#clock(),
    });
    if (payload.action.amountCents > this.#maxAmount) throw Error('Action exceeds broker policy limit');
    return payload;
  }

  #existing(id, fingerprint) {
    const row = this.#db.prepare('SELECT * FROM enforced_executions WHERE approval_id=?').get(id);
    if (!row) return null;
    if (row.principal !== this.#principal || row.approval_digest !== fingerprint) throw Error('Approval ID conflict');
    return JSON.parse(row.receipt);
  }

  remainingCents() {
    return this.#db.prepare('SELECT remaining FROM enforced_budgets WHERE principal=?').get(this.#principal).remaining;
  }

  execute(bundle, approval) {
    // Snapshot caller-owned objects before asynchronous work; never reread a source path.
    let captured, envelope, payload, fingerprint;
    try {
      captured = structuredClone(bundle);
      envelope = structuredClone(approval);
      validateBundle(captured);
      payload = this.#check(captured, envelope);
      fingerprint = digest(envelope.payload);
      const previous = this.#existing(payload.approvalId, fingerprint);
      if (previous) return Promise.resolve(previous);
      const inflight = this.#inflight.get(payload.approvalId);
      if (inflight) {
        if (inflight.fingerprint !== fingerprint) throw Error('Approval ID conflict');
        return inflight.promise;
      }
      if (payload.action.amountCents > this.remainingCents()) throw Error('Budget unavailable');
    } catch (error) {
      this.#event(envelope?.payload?.approvalId, 'DENIED_BEFORE_WORKER');
      return Promise.reject(error);
    }
    const promise = this.#run(captured, envelope, payload, fingerprint)
      .finally(() => this.#inflight.delete(payload.approvalId));
    this.#inflight.set(payload.approvalId, { fingerprint, promise });
    return promise;
  }

  async #run(bundle, approval, payload, fingerprint) {
    const id = payload.approvalId;
    this.#event(id, 'WORKER_STARTED');
    try {
      // The worker only gets the proposed action, never approval keys, identity tokens or the ledger.
      const result = await this.#runner(bundle, { input: { action: structuredClone(payload.action) } });
      if (result?.exitCode !== 0 || typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > 65536) throw Error('Invalid worker result');
      let requested;
      try { requested = JSON.parse(result.stdout); } catch { throw Error('Worker must emit exactly one JSON action'); }
      if (canonicalJSON(requested) !== canonicalJSON(payload.action)) throw Error('Worker action does not match signed approval');

      // This transaction only models a local effect. Do not put a real payment/API call inside it.
      this.#db.exec('BEGIN IMMEDIATE');
      try {
        this.#check(bundle, approval); // Recheck expiry/revocation after execution and under the write lock.
        const previous = this.#existing(id, fingerprint);
        if (previous) {
          this.#db.exec('COMMIT');
          return previous;
        }
        const update = this.#db.prepare('UPDATE enforced_budgets SET remaining=remaining-? WHERE principal=? AND remaining>=?')
          .run(payload.action.amountCents, this.#principal, payload.action.amountCents);
        if (update.changes !== 1) throw Error('Budget no longer available');
        const receiptPayload = {
          schema: 'agenttrust.execution.v1', approvalId: id, principal: this.#principal,
          bundleDigest: bundle.digest, policyVersion: this.#policyVersion, action: payload.action,
          outcome: 'SIMULATED_SUCCESS', executedAt: this.#clock(), receiptId: randomUUID(),
        };
        const receipt = { payload: receiptPayload, signature: sign(null, Buffer.from(canonicalJSON(receiptPayload)), this.#receiptKeys.privateKey).toString('base64') };
        this.#db.prepare('INSERT INTO enforced_executions VALUES(?,?,?,?,?)')
          .run(id, this.#principal, fingerprint, bundle.digest, JSON.stringify(receipt));
        this.#event(id, 'SIMULATED_SUCCESS');
        this.#db.exec('COMMIT');
        return receipt;
      } catch (error) {
        this.#db.exec('ROLLBACK');
        throw error;
      }
    } catch (error) {
      this.#event(id, 'NO_SIMULATED_EFFECT');
      throw error;
    }
  }

  revokeApproval(id) { this.#revoke('approval', id); }
  revokeKey(id) { this.#revoke('key', id); }
  #revoke(kind, id) {
    if (!label(id)) throw Error('Invalid revocation ID');
    this.#db.prepare('INSERT OR IGNORE INTO enforced_revocations VALUES(?,?)').run(kind, id);
    this.#event(kind === 'approval' ? id : null, kind === 'approval' ? 'APPROVAL_REVOKED' : 'KEY_REVOKED');
  }

  snapshot() {
    return {
      principal: this.#principal, remainingCents: this.remainingCents(),
      executions: this.#db.prepare('SELECT receipt FROM enforced_executions WHERE principal=? ORDER BY rowid').all(this.#principal).map(x => JSON.parse(x.receipt)),
      events: this.#db.prepare('SELECT seq,approval_id,event,time FROM enforced_events WHERE principal=? ORDER BY seq').all(this.#principal),
    };
  }

  close() {
    if (this.#inflight.size) throw Error('Cannot close broker while a worker is running');
    this.#db.close();
  }
}

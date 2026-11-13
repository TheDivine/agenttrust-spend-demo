import { createPrivateKey, createPublicKey, KeyObject, sign, verify } from 'node:crypto';
import { canonicalJSON, inspectBundle, validateBundle } from './bundle.mjs';

const SCHEMA = 'agenttrust.approval.v1';
const MAX_LIFETIME_MS = 60 * 60 * 1000;
const PAYLOAD_FIELDS = ['schema', 'approvalId', 'keyId', 'bundleDigest', 'principal',
  'policyVersion', 'action', 'issuedAt', 'expiresAt'];

function fields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== expected.length
    || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`Invalid ${label} fields`);
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw new Error(`Invalid ${label} property`);
  }
}

function identifier(value, label) {
  if (typeof value !== 'string' || !value.length || value.length > 128
    || value !== value.trim() || /[\x00-\x1f\x7f]/.test(value)) {
    throw new Error(`Invalid ${label}`);
  }
}

function version(value) {
  if (Number.isSafeInteger(value) && value > 0) return;
  identifier(value, 'policy version');
}

function timestamp(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid approval timestamp');
}

function validateAction(action) {
  fields(action, ['tool', 'amountCents', 'currency', 'vendor', 'purpose'], 'action');
  if (action.tool !== 'simulate_purchase' || action.currency !== 'USD' || action.vendor !== 'approved-tools'
    || !Number.isSafeInteger(action.amountCents) || action.amountCents <= 0
    || typeof action.purpose !== 'string' || !action.purpose.trim() || action.purpose.length > 200
    || /[\x00-\x1f\x7f]/.test(action.purpose)) {
    throw new Error('Invalid approval action');
  }
}

function validatePayload(payload, now) {
  fields(payload, PAYLOAD_FIELDS, 'approval payload');
  if (payload.schema !== SCHEMA || typeof payload.bundleDigest !== 'string'
    || !/^[a-f0-9]{64}$/.test(payload.bundleDigest)) throw new Error('Invalid approval schema or digest');
  for (const name of ['approvalId', 'keyId', 'principal']) identifier(payload[name], name);
  version(payload.policyVersion);
  validateAction(payload.action);
  timestamp(now);
  timestamp(payload.issuedAt);
  timestamp(payload.expiresAt);
  if (payload.issuedAt > now || payload.expiresAt <= now || payload.expiresAt <= payload.issuedAt
    || payload.expiresAt - payload.issuedAt > MAX_LIFETIME_MS) {
    throw new Error('Approval expired, future-dated or exceeds maximum lifetime');
  }
}

function signingKey(value) {
  const key = value instanceof KeyObject ? value : createPrivateKey(value);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 private key required');
  return key;
}

function verificationKey(value) {
  const key = value instanceof KeyObject ? value : createPublicKey(value);
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 public key required');
  return key;
}

export function issueApproval(bundle, {
  privateKey, keyId, principal, policyVersion, action, expiresAt, approvalId,
  ackReview = false, now = Date.now(),
} = {}) {
  validateBundle(bundle);
  if (typeof ackReview !== 'boolean') throw new Error('Review acknowledgement must be boolean');
  const inspection = inspectBundle(bundle);
  if (inspection.decision === 'BLOCK') throw new Error('Blocked bundle cannot be approved');
  if (inspection.decision === 'REVIEW' && !ackReview) throw new Error('Human review acknowledgement required');
  const payload = { schema: SCHEMA, approvalId, keyId, bundleDigest: bundle.digest,
    principal, policyVersion, action, issuedAt: now, expiresAt };
  validatePayload(payload, now);
  // Copy signed data so later mutation of the caller's action cannot change this envelope.
  const snapshot = JSON.parse(canonicalJSON(payload));
  const signature = sign(null, Buffer.from(canonicalJSON(snapshot)), signingKey(privateKey)).toString('base64');
  return { payload: snapshot, signature };
}

export function verifyApproval(envelope, {
  bundle, publicKeys, principal, policyVersion,
  revokedApprovalIds = [], revokedKeyIds = [], now = Date.now(),
} = {}) {
  fields(envelope, ['payload', 'signature'], 'approval envelope');
  validatePayload(envelope.payload, now);
  validateBundle(bundle);
  identifier(principal, 'expected principal');
  version(policyVersion);
  for (const list of [revokedApprovalIds, revokedKeyIds]) {
    if (!Array.isArray(list)) throw new Error('Revocation state must be an array');
    for (const value of list) identifier(value, 'revocation ID');
  }
  const payload = envelope.payload;
  if (payload.principal !== principal || payload.policyVersion !== policyVersion
    || payload.bundleDigest !== bundle.digest) throw new Error('Approval scope mismatch');
  if (revokedApprovalIds.includes(payload.approvalId) || revokedKeyIds.includes(payload.keyId)) {
    throw new Error('Approval or signer revoked');
  }
  if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)
    || !Object.hasOwn(publicKeys, payload.keyId)) throw new Error('Untrusted approval signer');
  const descriptor = Object.getOwnPropertyDescriptor(publicKeys, payload.keyId);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new Error('Invalid trusted key configuration');
  if (typeof envelope.signature !== 'string' || envelope.signature.length !== 88) throw new Error('Invalid approval signature');
  const signature = Buffer.from(envelope.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== envelope.signature
    || !verify(null, Buffer.from(canonicalJSON(payload)), verificationKey(descriptor.value), signature)) {
    throw new Error('Invalid approval signature');
  }
  if (inspectBundle(bundle).decision === 'BLOCK') throw new Error('Blocked bundle cannot execute');
  return JSON.parse(canonicalJSON(payload));
}

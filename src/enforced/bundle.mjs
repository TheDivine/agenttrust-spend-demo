import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';

const SCHEMA = 'agenttrust.bundle.v1';
const MAX_FILES = 1000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_TOTAL_BYTES = 8 * MAX_FILE_BYTES;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function plainObject(value) {
  return value !== null && typeof value === 'object'
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function fields(value, expected, label) {
  if (!plainObject(value) || Reflect.ownKeys(value).length !== expected.length
    || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`Invalid ${label} fields`);
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new Error(`Invalid ${label} property`);
    }
  }
}

// Deliberately rejects non-JSON values instead of silently dropping signed fields.
export function canonicalJSON(value) {
  const seen = new Set();
  function encode(item, depth) {
    if (depth > 64) throw new Error('JSON nesting limit exceeded');
    if (item === null || typeof item === 'boolean' || typeof item === 'string') {
      return JSON.stringify(item);
    }
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item);
    if (typeof item !== 'object' || seen.has(item)) throw new Error('Invalid JSON value');
    seen.add(item);
    let result;
    if (Array.isArray(item)) {
      if (Reflect.ownKeys(item).length !== item.length + 1) throw new Error('Invalid JSON array');
      const values = [];
      for (let index = 0; index < item.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
          throw new Error('Invalid JSON array entry');
        }
        values.push(encode(descriptor.value, depth + 1));
      }
      result = `[${values.join(',')}]`;
    } else {
      if (!plainObject(item) || Reflect.ownKeys(item).some((key) => typeof key !== 'string')) {
        throw new Error('Invalid JSON object');
      }
      const descriptors = Object.getOwnPropertyDescriptors(item);
      result = `{${Object.keys(descriptors).sort().map((key) => {
        const descriptor = descriptors[key];
        if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
          throw new Error('Invalid JSON property');
        }
        return `${JSON.stringify(key)}:${encode(descriptor.value, depth + 1)}`;
      }).join(',')}}`;
    }
    seen.delete(item);
    return result;
  }
  return encode(value, 0);
}

function safePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) {
    throw new Error('Invalid bundle path');
  }
  const segments = value.split('/');
  if (segments.length > 32 || segments[0] === '.git' || segments.some((segment) =>
    segment.length > 128 || !/^[A-Za-z0-9_.-]+$/.test(segment)
    || segment === '.' || segment === '..' || segment.endsWith('.')
    || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment))) {
    throw new Error(`Unsafe bundle path: ${value}`);
  }
  return value;
}

function validateImage(value) {
  if (typeof value !== 'string' || !IMAGE_ID.test(value)) {
    throw new Error('runtimeImage must be an immutable sha256 Docker image ID');
  }
}

function decodeContent(content) {
  if (typeof content !== 'string' || content.length > 4 * Math.ceil(MAX_FILE_BYTES / 3)) {
    throw new Error('Invalid or oversized file content');
  }
  const bytes = Buffer.from(content, 'base64');
  if (bytes.length > MAX_FILE_BYTES || bytes.toString('base64') !== content) {
    throw new Error('File content must be bounded canonical base64');
  }
  return bytes;
}

function bundleBody(bundle) {
  return { schema: bundle.schema, entrypoint: bundle.entrypoint,
    runtimeImage: bundle.runtimeImage, files: bundle.files };
}

export function validateBundle(bundle) {
  fields(bundle, ['schema', 'entrypoint', 'runtimeImage', 'files', 'digest'], 'bundle');
  if (bundle.schema !== SCHEMA) throw new Error('Invalid bundle schema');
  safePath(bundle.entrypoint);
  validateImage(bundle.runtimeImage);
  if (!Array.isArray(bundle.files) || bundle.files.length < 1 || bundle.files.length > MAX_FILES) {
    throw new Error('Invalid bundle file count');
  }
  let total = 0;
  let previous;
  const portableNames = new Set();
  const fileNames = new Set();
  for (const file of bundle.files) {
    fields(file, ['path', 'content', 'sha256'], 'file');
    safePath(file.path);
    if (previous !== undefined && previous >= file.path) throw new Error('Files must be sorted and unique');
    previous = file.path;
    const portableName = file.path.toLowerCase();
    if (portableNames.has(portableName)) throw new Error('Case-colliding bundle paths');
    portableNames.add(portableName);
    fileNames.add(portableName);
    const bytes = decodeContent(file.content);
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) throw new Error('Bundle byte limit exceeded');
    if (typeof file.sha256 !== 'string' || !DIGEST.test(file.sha256) || sha256(bytes) !== file.sha256) {
      throw new Error('File digest mismatch');
    }
  }
  for (const name of fileNames) {
    const segments = name.split('/');
    for (let index = 1; index < segments.length; index++) {
      if (fileNames.has(segments.slice(0, index).join('/'))) throw new Error('File/directory path collision');
    }
  }
  if (!bundle.files.some((file) => file.path === bundle.entrypoint)) throw new Error('Entrypoint missing from bundle');
  if (typeof bundle.digest !== 'string' || !DIGEST.test(bundle.digest)
    || sha256(canonicalJSON(bundleBody(bundle))) !== bundle.digest) {
    throw new Error('Bundle digest mismatch');
  }
  return bundle;
}

function sameFile(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size
    && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}

export function captureBundle(root, { entrypoint = 'tool.mjs', runtimeImage } = {}) {
  safePath(entrypoint);
  validateImage(runtimeImage);
  const base = path.resolve(root);
  const files = [];
  let total = 0;
  let entries = 0;
  function walk(directory, prefix = '') {
    const before = fs.lstatSync(directory);
    if (before.isSymbolicLink() || !before.isDirectory()) throw new Error('Bundle root and directories must be real directories');
    for (const name of fs.readdirSync(directory).sort()) {
      if (!prefix && name === '.git') continue;
      if (++entries > 4000) throw new Error('Bundle entry limit exceeded');
      const relative = safePath(prefix ? `${prefix}/${name}` : name);
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error('Bundle symlinks are unsupported');
      if (stat.isDirectory()) { walk(absolute, relative); continue; }
      if (!stat.isFile()) throw new Error('Bundle special files are unsupported');
      if (files.length >= MAX_FILES || stat.size > MAX_FILE_BYTES || total + stat.size > MAX_TOTAL_BYTES) {
        throw new Error('Bundle size limit exceeded');
      }
      const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      try {
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || !sameFile(stat, opened)) throw new Error('File changed during capture');
        const storage = Buffer.alloc(MAX_FILE_BYTES + 1);
        let length = 0;
        while (length < storage.length) {
          const count = fs.readSync(fd, storage, length, storage.length - length, null);
          if (!count) break;
          length += count;
        }
        if (length > MAX_FILE_BYTES || total + length > MAX_TOTAL_BYTES
          || !sameFile(opened, fs.fstatSync(fd)) || length !== opened.size) {
          throw new Error('File changed or exceeded limits during capture');
        }
        const bytes = storage.subarray(0, length);
        total += length;
        files.push({ path: relative, content: bytes.toString('base64'), sha256: sha256(bytes) });
      } finally { fs.closeSync(fd); }
    }
    if (!sameFile(before, fs.lstatSync(directory))) throw new Error('Directory changed during capture');
  }
  walk(base);
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const body = { schema: SCHEMA, entrypoint, runtimeImage, files };
  return validateBundle({ ...body, digest: sha256(canonicalJSON(body)) });
}

const RULES = [
  ['FETCH_EXECUTE', 'HIGH', /\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sh|bash|zsh)\b/],
  ['DYNAMIC_EVAL', 'REVIEW', /\b(?:eval|exec)\s*\(/],
  ['INSTRUCTION_OVERRIDE', 'REVIEW', /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i],
  ['SENSITIVE_PATH', 'REVIEW', /(?:\.ssh\b|\.aws\b|\.env\b)/],
  ['ENCODED_EXECUTION', 'REVIEW', /(?:base64\s+(?:-d|--decode)|fromCharCode\s*\()/],
];

// These deliberately small heuristics are review signals, not a safety verdict.
export function inspectBundle(bundle) {
  validateBundle(bundle);
  const findings = [];
  for (const file of bundle.files) {
    const bytes = decodeContent(file.content);
    if (bytes.includes(0) || !isUtf8(bytes)) {
      findings.push({ file: file.path, rule: 'BINARY_CONTENT', severity: 'REVIEW' });
      continue;
    }
    const text = bytes.toString('utf8');
    for (const [rule, severity, regex] of RULES) {
      if (regex.test(text)) findings.push({ file: file.path, rule, severity });
    }
    if (file.path.split('/').at(-1) === 'package.json') {
      try {
        const manifest = JSON.parse(text);
        if (!plainObject(manifest)) throw new Error('Invalid package manifest');
        for (const hook of ['preinstall', 'install', 'postinstall']) {
          if (plainObject(manifest.scripts) && Object.hasOwn(manifest.scripts, hook)) {
            findings.push({ file: file.path, rule: 'INSTALL_HOOK', severity: 'REVIEW', hook });
          }
        }
      } catch {
        findings.push({ file: file.path, rule: 'INVALID_MANIFEST', severity: 'HIGH' });
      }
    }
  }
  const decision = findings.some((finding) => finding.severity === 'HIGH') ? 'BLOCK'
    : findings.length ? 'REVIEW' : 'NO_FINDINGS';
  return { decision, findings };
}

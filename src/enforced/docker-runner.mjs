import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { canonicalJSON, validateBundle } from './bundle.mjs';

const MAX_INPUT_BYTES = 65536;
const SAFE_ENV = {
  PATH: '/usr/local/bin', HOME: '/tmp', LANG: 'C',
  NODE_OPTIONS: '', NODE_PATH: '', NODE_EXTRA_CA_CERTS: '', NODE_USE_ENV_PROXY: '',
  OPENSSL_CONF: '', OPENSSL_MODULES: '', LD_PRELOAD: '', LD_LIBRARY_PATH: '',
  SSLKEYLOGFILE: '', HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '', NO_PROXY: '',
};

function command(binary, args, { input = '', timeoutMs, maxOutputBytes, signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('Worker aborted'));
    if (timeoutMs <= 0) return reject(new Error('Worker timeout'));
    const child = spawn(binary, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const stdout = [], stderr = [];
    let bytes = 0, failure;
    const stop = (error) => { failure ??= error; child.kill('SIGKILL'); };
    const abort = () => stop(new Error('Worker aborted'));
    const timer = setTimeout(() => stop(new Error('Worker timeout')), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    const collect = (chunks) => (chunk) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) { stop(new Error('Worker output limit exceeded')); return; }
      chunks.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.on('error', () => { failure ??= new Error('Docker runtime unavailable'); });
    child.stdin.on('error', () => { /* Process exit/error handles a closed pipe. */ });
    child.on('close', (exitCode) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (failure) return reject(failure);
      if (exitCode !== 0) return reject(new Error(`Docker command failed (exit ${exitCode})`));
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'), exitCode: 0 });
    });
    child.stdin.end(input);
  });
}

/** Execute untrusted bytes in Docker; stdout remains untrusted, never an authorization. */
export async function runIsolated(bundle, {
  input = {}, timeoutMs = 5000, maxOutputBytes = 65536, dockerBinary = 'docker', signal,
} = {}) {
  // Capture and validate before the first await. A caller cannot swap bytes or image mid-run.
  validateBundle(bundle);
  const captured = structuredClone(bundle);
  validateBundle(captured);
  const inputJSON = canonicalJSON(input) + '\n';
  if (Buffer.byteLength(inputJSON) > MAX_INPUT_BYTES) throw new Error('Worker input limit exceeded');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error('Invalid timeout');
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 1048576) {
    throw new Error('Invalid output limit');
  }
  if (typeof dockerBinary !== 'string' || !dockerBinary) throw new Error('Invalid Docker binary');
  if (signal?.aborted) throw new Error('Worker aborted');
  const deadline = Date.now() + timeoutMs;
  const name = `agenttrust-worker-${randomUUID()}`;
  const label = 'org.agenttrust.isolated-worker=true';
  let privateRoot, createAttempted = false, result, failure;
  const invoke = (args, options = {}) => command(dockerBinary, args, {
    timeoutMs: deadline - Date.now(), maxOutputBytes: 65536, signal, ...options,
  });
  try {
    // Only inspect an already-present immutable image. Never pull and never run image hooks.
    const inspection = await invoke(['image', 'inspect', '--format', '{{json .Config}}', captured.runtimeImage]);
    const config = JSON.parse(inspection.stdout);
    if (!config || typeof config !== 'object' || (config.Volumes && Object.keys(config.Volumes).length)) {
      throw new Error('Runtime image must not declare volumes');
    }
    if (config.Env != null && !Array.isArray(config.Env)) throw new Error('Invalid runtime image environment');
    const env = Object.create(null);
    if ((config.Env?.length ?? 0) > 256) throw new Error('Runtime image environment limit exceeded');
    for (const item of config.Env ?? []) {
      if (typeof item !== 'string') throw new Error('Invalid runtime image environment');
      const key = item.split('=', 1)[0];
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error('Invalid runtime image environment');
      env[key] = ''; // Do not expose baked-in environment values either.
    }
    Object.assign(env, SAFE_ENV);
    privateRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'agenttrust-worker-'));
    await fs.chmod(privateRoot, 0o700);
    const snapshot = path.join(privateRoot, 'bundle');
    if (snapshot.includes(',')) throw new Error('Temporary directory cannot contain commas');
    await fs.mkdir(snapshot, { mode: 0o755 });
    for (const file of captured.files) {
      const target = path.resolve(snapshot, file.path);
      if (!target.startsWith(snapshot + path.sep)) throw new Error('Unsafe snapshot path');
      await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o755 });
      await fs.writeFile(target, Buffer.from(file.content, 'base64'), { flag: 'wx', mode: 0o444 });
    }
    const args = ['create', '--pull', 'never', '--name', name, '--label', label,
      '--network', 'none', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--user', '65534:65534',
      '--pids-limit', '32', '--memory', '128m', '--memory-swap', '128m', '--cpus', '0.5',
      '--ulimit', 'nofile=64:64', '--ulimit', 'core=0', '--no-healthcheck',
      '--stop-timeout', '1', '--log-driver', 'none',
      '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777',
      '--mount', `type=bind,src=${snapshot},dst=/bundle,readonly,bind-propagation=rprivate`,
      '--workdir', '/bundle', '--entrypoint', '/usr/local/bin/node', '--interactive'];
    for (const [key, value] of Object.entries(env)) args.push('--env', `${key}=${value}`);
    args.push(captured.runtimeImage, `/bundle/${captured.entrypoint}`);
    createAttempted = true;
    await invoke(args);
    result = await invoke(['start', '--attach', '--interactive', name], { input: inputJSON, maxOutputBytes });
  } catch (error) { failure = error; }
  finally {
    if (createAttempted) {
      try {
        // Independent of the worker timeout/abort: remove the entire container, including descendants.
        await command(dockerBinary, ['rm', '--force', '--volumes', name], {
          timeoutMs: 5000, maxOutputBytes: 65536,
        });
      } catch {
        // A lost create response does not prove the daemon failed to create it.
        failure = new Error(`Worker cleanup not confirmed; inspect container ${name}`, { cause: failure });
      }
    }
    if (privateRoot) {
      try { await fs.rm(privateRoot, { recursive: true, force: true }); }
      catch { failure = new Error('Worker snapshot cleanup failed', { cause: failure }); }
    }
  }
  if (failure) { failure.workerContainer = name; throw failure; }
  return result;
}

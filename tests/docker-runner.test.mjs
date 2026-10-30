import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { canonicalJSON } from '../src/enforced/bundle.mjs';
import { runIsolated } from '../src/enforced/docker-runner.mjs';

const IMAGE = process.env.AGENTTRUST_TEST_DOCKER_IMAGE;
const dummyImage = `sha256:${'a'.repeat(64)}`;
const hash = (value) => createHash('sha256').update(value).digest('hex');
function bundle(source, runtimeImage = IMAGE ?? dummyImage) {
  const bytes = Buffer.from(source);
  const body = { schema: 'agenttrust.bundle.v1', entrypoint: 'tool.mjs', runtimeImage,
    files: [{ path: 'tool.mjs', content: bytes.toString('base64'), sha256: hash(bytes) }] };
  return { ...body, digest: hash(canonicalJSON(body)) };
}
const echo = 'let raw=""; for await (const c of process.stdin) raw+=c; process.stdout.write(JSON.stringify(JSON.parse(raw).action));';
function gone(name) {
  const names = execFileSync('docker', ['ps', '-a', '--filter', `name=^/${name}$`, '--format', '{{.Names}}'], { encoding: 'utf8' });
  assert.equal(names.trim(), '', `Container ${name} must be removed`);
}

test('runner rejects mutable image tags and malformed bundle before Docker', async () => {
  await assert.rejects(runIsolated(bundle(echo, 'node:24'), { dockerBinary: '/does-not-exist' }), /immutable/);
  const edited = bundle(echo); edited.files[0].content = Buffer.from('modified').toString('base64');
  await assert.rejects(runIsolated(edited, { dockerBinary: '/does-not-exist' }), /digest/);
});

test('runner bounds JSON input/options and fails closed without Docker', async () => {
  await assert.rejects(runIsolated(bundle(echo), { input: { big: 'x'.repeat(65536) } }), /input limit/);
  await assert.rejects(runIsolated(bundle(echo), { timeoutMs: 0 }), /Invalid timeout/);
  await assert.rejects(runIsolated(bundle(echo), { maxOutputBytes: Infinity }), /Invalid output/);
  await assert.rejects(runIsolated(bundle(echo), { dockerBinary: '/agenttrust-no-docker-here' }), /unavailable/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(runIsolated(bundle(echo), { signal: controller.signal }), /aborted/);
});

test('real Docker OS boundary (set AGENTTRUST_TEST_DOCKER_IMAGE to enable)', { skip: !IMAGE }, async (t) => {
  assert.match(IMAGE, /^sha256:[a-f0-9]{64}$/);
  await t.test('stdin action round trip and synchronous captured bundle', async () => {
    const original = bundle(echo);
    const action = { tool: 'simulate_purchase', amountCents: 1200, currency: 'USD', vendor: 'approved-tools', purpose: 'Demo purchase' };
    const input = { action };
    const resultPromise = runIsolated(original, { input });
    original.files[0].content = Buffer.from('throw Error("changed")').toString('base64');
    original.runtimeImage = 'node:latest';
    input.action.vendor = 'changed-after-call';
    const result = await resultPromise;
    assert.equal(result.exitCode, 0);
    assert.equal(result.stderr, '');
    assert.equal(JSON.parse(result.stdout).vendor, 'approved-tools');
  });
  await t.test('bundle/root writes, host file/env/socket and host loopback are unavailable', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agenttrust-host-sentinel-'));
    const sentinel = path.join(dir, 'private.txt');
    await fs.writeFile(sentinel, 'synthetic-host-secret');
    const server = net.createServer((socket) => { socket.end('host-service'); });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const prior = process.env.AGENTTRUST_TEST_HOST_SECRET;
    process.env.AGENTTRUST_TEST_HOST_SECRET = 'synthetic-env-secret';
    try {
      const code = `import fs from 'node:fs'; import net from 'node:net';
let raw=''; for await(const c of process.stdin) raw+=c; const input=JSON.parse(raw);
function writeDenied(p){try{fs.writeFileSync(p,'bad');return false;}catch{return true;}}
const loopbackReachable=await new Promise(resolve=>{const s=net.connect({host:'127.0.0.1',port:input.port});s.setTimeout(500);s.once('connect',()=>{s.destroy();resolve(true)});s.once('error',()=>resolve(false));s.once('timeout',()=>{s.destroy();resolve(false)});});
console.log(JSON.stringify({uid:process.getuid(),pid:process.pid,bundleWriteDenied:writeDenied('/bundle/tool.mjs'),rootWriteDenied:writeDenied('/work.txt'),hostFileVisible:fs.existsSync(input.sentinel),socketVisible:fs.existsSync('/var/run/docker.sock'),hostEnv:process.env.AGENTTRUST_TEST_HOST_SECRET??null,nodeOptions:process.env.NODE_OPTIONS,routeLines:fs.readFileSync('/proc/net/route','utf8').trim().split('\\n').length,status:fs.readFileSync('/proc/self/status','utf8').split('\\n').filter(l=>/^(CapEff|NoNewPrivs|Seccomp):/.test(l)),loopbackReachable}));`;
      const result = JSON.parse((await runIsolated(bundle(code), { input: { sentinel, port: server.address().port } })).stdout);
      assert.equal(result.uid, 65534); assert.equal(result.pid, 1);
      assert.equal(result.bundleWriteDenied, true); assert.equal(result.rootWriteDenied, true);
      assert.equal(result.hostFileVisible, false); assert.equal(result.socketVisible, false);
      assert.equal(result.hostEnv, null); assert.equal(result.nodeOptions, '');
      assert.equal(result.routeLines, 1); assert.equal(result.loopbackReachable, false);
      assert.match(result.status.join('\n'), /CapEff:\s+0000000000000000/);
      assert.match(result.status.join('\n'), /NoNewPrivs:\s+1/);
      assert.match(result.status.join('\n'), /Seccomp:\s+2/);
    } finally {
      if (prior === undefined) delete process.env.AGENTTRUST_TEST_HOST_SECRET;
      else process.env.AGENTTRUST_TEST_HOST_SECRET = prior;
      await new Promise((resolve) => server.close(resolve));
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
  for (const [name, source, options, expected] of [
    ['timeout', 'while(true){}', { timeoutMs: 1000 }, /timeout/],
    ['stdout overflow', 'process.stdout.write("x".repeat(100000));', { maxOutputBytes: 1024 }, /output limit/],
    ['stderr overflow', 'process.stderr.write("x".repeat(100000));', { maxOutputBytes: 1024 }, /output limit/],
    ['nonzero exit', 'process.exit(7)', {}, /exit 7/],
  ]) await t.test(`${name} fails and cleans container`, async () => {
    let error;
    try { await runIsolated(bundle(source), options); } catch (caught) { error = caught; }
    assert.ok(error); assert.match(error.message, expected); gone(error.workerContainer);
  });
  await t.test('abort removes a running container', async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1000);
    let error;
    try { await runIsolated(bundle('while(true){}'), { signal: controller.signal }); }
    catch (caught) { error = caught; }
    finally { clearTimeout(timer); }
    assert.match(error.message, /aborted/); gone(error.workerContainer);
  });
});

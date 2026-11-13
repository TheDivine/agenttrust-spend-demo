# Local isolated worker runtime

The enforced demo runs bundle code in a separate Docker container. The worker receives bounded JSON on stdin and emits an **untrusted action proposal** on stdout. The broker must separately verify the approved bundle, immutable image, requested action and replay state before performing its simulated action. The example worker emits exactly `JSON.stringify(input.action)`; it cannot authorize a purchase. There are no real payments.

## Build and pin

Use Linux x86_64 (WSL is supported), glibc, Python 3.8+, Node 24+ for the host broker, and a running local Docker daemon. The helper does not install packages or change Docker/system configuration:

```sh
python3 tools/build-worker-runtime.py --node-binary "$(command -v node)"
```

This uses the explicitly selected, trusted installed Node 24+ binary without network access. Alternatively, `--download` explicitly permits downloading Node 24.19.0 from the official [Node distribution](https://nodejs.org/dist/v24.19.0/); that mode verifies the archive against both the published checksum file and a pinned SHA256 in the helper, then extracts only the Node executable. Both modes copy the executable's dynamic runtime libraries from the current Linux host into a fresh `FROM scratch` build context. No base image is pulled, no package install scripts run, and no unrelated application image is reused. A manifest records executable and library hashes, archive provenance when applicable, and the resulting immutable Docker image ID in ignored `data/worker-runtime/`. Select another destination with `--cache-dir`.

For an offline build after downloading the official archive and `SHASUMS256.txt` separately:

```sh
python3 tools/build-worker-runtime.py \
  --archive /path/to/node-v24.19.0-linux-x64.tar.xz \
  --checksums /path/to/SHASUMS256.txt
```

Use the printed `sha256:<64 hexadecimal characters>` as `runtimeImage` in the captured bundle and approval. The final stdout line contains only this ID; logs and the manifest location go to stderr, so CI can capture `image=$(python3 tools/build-worker-runtime.py --node-binary "$(command -v node)")`. A tag such as `node:24` is rejected. The runner uses `--pull never` and `/usr/local/bin/node` as its explicit entrypoint. Building on another host can produce another image ID because the host libraries differ; inspect and approve that image independently. This is a reproducible build procedure with retained hashes, not a claim of byte-identical builds, signed vendor provenance for the whole image, or a hardened production image. Keep cache/binary artifacts out of commits. Distribution of rebuilt runtimes requires preserving applicable Node and library licenses.

## Restrictions and failure behavior

The runner validates and copies the bundle and JSON input before its first asynchronous operation. It materializes a private temporary snapshot and mounts only that snapshot read-only at `/bundle`. Container settings require:

- Network disabled, root filesystem read-only, UID/GID 65534, all capabilities dropped and no new privileges.
- No host secrets, home directory, Docker socket or other host filesystem mounts. Image environment values are blanked; Node options, loader and proxy variables are explicitly cleared.
- PID limit 32, memory/swap limit 128 MiB, CPU limit 0.5, bounded descriptors and an 8 MiB `/tmp` tmpfs. Docker's default seccomp profile remains active.
- JSON input at most 64 KiB, combined stdout/stderr bounded (default 64 KiB), and a deadline including runtime inspection/startup (default 5 seconds).

Missing Docker/image, validation failure, nonzero exit, timeout, cancellation and output overflow fail closed. There is no in-process fallback. Cleanup force-removes the container and descendants, then removes the private snapshot, including on failures. Cleanup has its own bounded timeout; a daemon failure that prevents confirmed removal is reported as an error, not success. Inspect any reported container name after restoring Docker.

The trusted host/daemon, operating-system kernel, runtime image and broker remain part of the trust boundary. Containers share a kernel; these tests do not demonstrate resistance to kernel exploits. Archive mode verifies known Node bytes; installed-binary mode trusts the explicitly selected executable. Neither verifies the safety of all host libraries. A compromised host or daemon is outside this local demo's protection.

## Verify the actual boundary

Default tests clearly skip real-container checks unless an immutable image is supplied:

```sh
AGENTTRUST_TEST_DOCKER_IMAGE=sha256:YOUR_64_HEX_IMAGE_ID \
  node --test tests/docker-runner.test.mjs
```

Real tests cover captured bundle/input mutation, exact action output, nonroot execution, effective capabilities/seccomp/no-new-privileges, blocked root/bundle writes, unavailable synthetic host file/environment/socket, blocked access to a host loopback service, timeout, stdout/stderr overflow, nonzero exit and cancellation cleanup. Passing these local checks does not certify production isolation or safe bundle behavior.

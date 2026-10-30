#!/usr/bin/env python3
"""Build a local Linux x64 Node worker from verified Node bytes and host libraries.

No package installation, registry pull, or privileged container is needed.
The resulting image is a local development artifact, not a vendor-signed runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

VERSION = "24.19.0"
ARCHIVE = f"node-v{VERSION}-linux-x64.tar.xz"
EXPECTED_SHA256 = "14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647"
ORIGIN = f"https://nodejs.org/dist/v{VERSION}/"


def sha256(file):
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Previously downloaded official archive")
    parser.add_argument("--checksums", type=Path, help="Previously downloaded official SHASUMS256.txt")
    parser.add_argument("--node-binary", type=Path, help="Use an explicitly trusted installed Node 24+ executable")
    parser.add_argument("--download", action="store_true", help="Allow official Node archive/checksum download")
    parser.add_argument("--cache-dir", type=Path, default=Path("data/worker-runtime"))
    parser.add_argument("--image-tag", default="agenttrust-node24-worker:local")
    args = parser.parse_args()
    if args.node_binary and (args.archive or args.checksums or args.download):
        parser.error("Choose installed Node or official archive mode, not both")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        parser.error("Use Linux x86_64 (including WSL) with Python 3.8+, glibc and Docker")
    cache = args.cache_dir.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    archive = args.archive.resolve() if args.archive else cache / ARCHIVE
    sums = args.checksums.resolve() if args.checksums else cache / "SHASUMS256.txt"
    for target, name, provided in (() if args.node_binary else ((archive, ARCHIVE, args.archive), (sums, "SHASUMS256.txt", args.checksums))):
        if not target.exists() and not provided and args.download:
            with urllib.request.urlopen(ORIGIN + name, timeout=60) as response:
                temporary = target.with_suffix(target.suffix + ".partial")
                try:
                    with temporary.open("wb") as output:
                        shutil.copyfileobj(response, output)
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
        if not target.exists():
            parser.error("Supply --node-binary, --archive and --checksums, or explicitly enable --download")
    actual = None
    if not args.node_binary:
        official = dict((name.lstrip("*"), digest) for digest, name in
                        (line.split() for line in sums.read_text().splitlines() if line.strip()))
        actual = sha256(archive)
        if official.get(ARCHIVE) != EXPECTED_SHA256 or actual != EXPECTED_SHA256:
            raise SystemExit("Node archive/checksum does not match the reviewed pinned SHA256")

    # A fresh context prevents unrelated/stale files entering the image. Only one
    # exact archive member is extracted; archive paths and symlinks are never used.
    with tempfile.TemporaryDirectory(prefix="agenttrust-runtime-build-") as directory:
        context = Path(directory)
        root = context / "rootfs"
        node = root / "usr/local/bin/node"
        node.parent.mkdir(parents=True)
        if args.node_binary:
            shutil.copyfile(args.node_binary.resolve(), node)
        else:
            with tarfile.open(archive, "r:xz") as tar:
                member = tar.getmember(f"node-v{VERSION}-linux-x64/bin/node")
                if not member.isfile():
                    raise SystemExit("Expected regular Node executable")
                with tar.extractfile(member) as source, node.open("wb") as output:
                    shutil.copyfileobj(source, output)
        node.chmod(0o755)
        version = subprocess.check_output([str(node), "--version"], text=True).strip()
        if not re.fullmatch(r"v\d+\.\d+\.\d+", version) or int(version[1:].split(".")[0]) < 24:
            raise SystemExit("Node 24+ required")
        if not args.node_binary and version != "v" + VERSION:
            raise SystemExit("Unexpected Node executable version")
        dependencies = subprocess.check_output(["ldd", str(node)], text=True)
        if "not found" in dependencies:
            raise SystemExit("Missing host runtime library; use a glibc Linux host")
        paths = sorted(set(re.findall(r"(/[^\s()]+)", dependencies)))
        if not paths:
            raise SystemExit("Could not identify dynamic runtime libraries")
        manifest = {"nodeVersion": version, "nodeArchiveURL": None if args.node_binary else ORIGIN + ARCHIVE,
                    "nodeArchiveSHA256": actual, "nodeExecutableSHA256": sha256(node),
                    "provenance": ("Explicitly trusted installed Node" if args.node_binary else "Verified official Node archive") + "; runtime libraries copied from this local host",
                    "libraries": []}
        for library in paths:
            source = Path(library)
            if not source.is_absolute() or not source.is_file() or ".." in source.parts:
                raise SystemExit("Unexpected library path")
            destination = root / library.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination, follow_symlinks=True)
            destination.chmod(0o755)
            manifest["libraries"].append({"path": library, "sha256": sha256(destination)})
        for name in ("tmp", "work"):
            (root / name).mkdir()
        (context / "Dockerfile").write_text(
            'FROM scratch\nCOPY rootfs /\nUSER 65534:65534\nWORKDIR /work\nENTRYPOINT ["/usr/local/bin/node"]\n')
        subprocess.run(["docker", "build", "--network", "none", "--pull=false", "--tag", args.image_tag, str(context)], check=True, stdout=sys.stderr)
        image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", args.image_tag], text=True).strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise SystemExit("Docker did not return an immutable image ID")
        manifest["runtimeImage"] = image
        manifest["imageTag"] = args.image_tag
        output = cache / (image.replace(":", "-") + ".json")
        output.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Hash manifest: {output}", file=sys.stderr)
        print(image)


if __name__ == "__main__":
    main()

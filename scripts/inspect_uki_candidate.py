#!/usr/bin/env python3
"""Inspect UKIs inside an immutable candidate image without granting trust."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path


FORMAT = "attestos.uki_static_inspection/v1"
MAX_CANDIDATES = 8


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True)
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"{args[0]} failed ({proc.returncode}): {detail[:500]}")
    return proc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def container_lines(container: str, command: str) -> list[str]:
    proc = run("podman", "exec", container, "bash", "-lc", command, check=False)
    if proc.returncode != 0:
        return []
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


def copy_from(container: str, source: str, destination: Path) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    proc = run("podman", "cp", f"{container}:{source}", str(destination), check=False)
    return proc.returncode == 0 and destination.is_file()


def convert_certificate(source: Path, destination: Path) -> bool:
    for inform in ("DER", "PEM"):
        proc = run(
            "openssl", "x509", "-inform", inform,
            "-in", str(source), "-out", str(destination),
            check=False,
        )
        if proc.returncode == 0 and destination.is_file():
            return True
    return False


def dump_cmdline(uki: Path, destination: Path) -> bytes | None:
    proc = run(
        "objcopy", "--dump-section", f".cmdline={destination}", str(uki),
        check=False,
    )
    if proc.returncode != 0 or not destination.is_file():
        return None
    return destination.read_bytes().rstrip(b"\x00")


def inspect_candidate(uki: Path, certs: list[Path], root: Path, source_path: str) -> dict:
    signature_list = run("sbverify", "--list", str(uki), check=False)
    verified_cert = None
    verified_cert_path = None
    for cert in certs:
        proc = run("sbverify", "--cert", str(cert), str(uki), check=False)
        if proc.returncode == 0:
            verified_cert = sha256(cert)
            verified_cert_path = cert
            break

    section = root / f"{uki.name}.cmdline"
    raw_cmdline = dump_cmdline(uki, section)
    cmdline = raw_cmdline.decode("utf-8", errors="replace").strip() if raw_cmdline is not None else ""
    words = cmdline.split()

    tampered_rejected = False
    if raw_cmdline is not None and verified_cert_path is not None:
        tampered_section = root / f"{uki.name}.tampered-cmdline"
        tampered_section.write_bytes(raw_cmdline + b" attestos_tamper=1\x00")
        tampered_uki = root / f"{uki.name}.tampered.efi"
        shutil.copy2(uki, tampered_uki)
        update = run(
            "objcopy", "--update-section",
            f".cmdline={tampered_section}", str(tampered_uki),
            check=False,
        )
        if update.returncode == 0:
            verify = run(
                "sbverify", "--cert", str(verified_cert_path), str(tampered_uki),
                check=False,
            )
            tampered_rejected = verify.returncode != 0

    return {
        "container_path": source_path,
        "size_bytes": uki.stat().st_size,
        "sha256": sha256(uki),
        "signature_present": signature_list.returncode == 0,
        "signature_summary": (signature_list.stdout or signature_list.stderr)[-1000:],
        "verified_certificate_sha256": verified_cert,
        "embedded_cmdline": {
            "available": raw_cmdline is not None,
            "sha256": hashlib.sha256(raw_cmdline).hexdigest() if raw_cmdline is not None else None,
            "lockdown_confidentiality_present": "lockdown=confidentiality" in words,
            "module_sig_enforce_present": "module.sig_enforce=1" in words,
        },
        "tampered_cmdline_signature_rejected": tampered_rejected,
    }


def inspect(image: str) -> dict:
    container = f"attestos-uki-inspect-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="attestos-uki-static-") as tmp:
        root = Path(tmp)
        run(
            "podman", "create", "--name", container,
            "--entrypoint", "/bin/sleep", image, "infinity",
        )
        try:
            run("podman", "start", container)
            packages = container_lines(container, "rpm -qa 'kernel-uki-virt*'")
            uki_paths = container_lines(
                container,
                "for p in $(rpm -qa 'kernel-uki-virt*'); do rpm -ql \"$p\"; done | "
                "grep -E '\\.efi$' | sort -u",
            )[:MAX_CANDIDATES]
            cert_paths = container_lines(
                container,
                "find /usr/share/pki/sb-certs /etc/pki -type f "
                "\\( -name '*.cer' -o -name '*.crt' -o -name '*.pem' \\) "
                "2>/dev/null | sort -u",
            )

            certs = []
            cert_sources = []
            for index, source in enumerate(cert_paths):
                copied = root / "certs" / f"{index}.source"
                pem = root / "certs" / f"{index}.pem"
                if copy_from(container, source, copied) and convert_certificate(copied, pem):
                    certs.append(pem)
                    cert_sources.append({"path": source, "sha256": sha256(pem)})

            candidates = []
            for index, source in enumerate(uki_paths):
                local = root / "ukis" / f"{index}-{Path(source).name}"
                if copy_from(container, source, local):
                    candidates.append(inspect_candidate(local, certs, root, source))
        finally:
            run("podman", "rm", "-f", container, check=False)

    return {
        "format": FORMAT,
        "image": image,
        "kernel_uki_packages": packages,
        "certificates": cert_sources,
        "candidates": candidates,
        "package_present": bool(packages),
        "uki_present": bool(candidates),
        "signature_verified": any(
            item["verified_certificate_sha256"] for item in candidates),
        "tampered_uki_rejected": bool(candidates) and all(
            item["tampered_cmdline_signature_rejected"] for item in candidates),
        "policy_cmdline_present": any(
            item["embedded_cmdline"]["lockdown_confidentiality_present"] and
            item["embedded_cmdline"]["module_sig_enforce_present"]
            for item in candidates),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "output": str(args.output),
        "package_present": result["package_present"],
        "uki_present": result["uki_present"],
        "signature_verified": result["signature_verified"],
        "tampered_uki_rejected": result["tampered_uki_rejected"],
        "policy_cmdline_present": result["policy_cmdline_present"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

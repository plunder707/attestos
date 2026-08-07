#!/usr/bin/env python3
"""Inspect the installed ESP before boot without granting policy trust."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


FORMAT = "attestos.fedora_sealed_static/v1"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True)
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"{args[0]} failed ({proc.returncode}): {detail[-500:]}")
    return proc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def dump_cmdline(uki: Path, destination: Path) -> bytes:
    run("objcopy", "--dump-section", f".cmdline={destination}", str(uki))
    return destination.read_bytes().rstrip(b"\x00")


def inspect(
    esp: Path,
    certificate: Path,
    source_reference: str,
    installer_reference: str,
) -> dict:
    esp = esp.resolve()
    systemd_boot = esp / "EFI" / "systemd" / "systemd-bootx64.efi"
    ukis = sorted((esp / "EFI" / "Linux").glob("*.efi"))
    if len(ukis) != 1:
        raise RuntimeError(f"expected exactly one installed UKI, found {len(ukis)}")
    if not systemd_boot.is_file():
        raise RuntimeError("installed ESP has no EFI/systemd/systemd-bootx64.efi")

    uki = ukis[0]
    uefi_path = "\\" + str(uki.relative_to(esp)).replace("/", "\\")
    signature = run("sbverify", "--cert", str(certificate), str(uki), check=False)

    with tempfile.TemporaryDirectory(prefix="attestos-fedora-static-") as tmp:
        root = Path(tmp)
        raw_cmdline = dump_cmdline(uki, root / "cmdline")
        tampered_cmdline = root / "cmdline.tampered"
        tampered_cmdline.write_bytes(raw_cmdline + b" attestos_tamper=1\x00")
        tampered_uki = root / "tampered.efi"
        shutil.copy2(uki, tampered_uki)
        update = run(
            "objcopy",
            "--update-section",
            f".cmdline={tampered_cmdline}",
            str(tampered_uki),
            check=False,
        )
        tampered_verify = run(
            "sbverify", "--cert", str(certificate), str(tampered_uki), check=False
        ) if update.returncode == 0 else update

    return {
        "format": FORMAT,
        "source_reference": source_reference,
        "installer_reference": installer_reference,
        "esp": {
            "systemd_boot_path": "\\EFI\\systemd\\systemd-bootx64.efi",
            "systemd_boot_sha256": sha256(systemd_boot),
            "uki_count": len(ukis),
        },
        "uki": {
            "uefi_path": uefi_path,
            "sha256": sha256(uki),
            "size_bytes": uki.stat().st_size,
            "signature_verified": signature.returncode == 0,
            "signature_diagnostic": (signature.stdout or signature.stderr)[-1000:],
            "certificate_sha256": sha256(certificate),
            "embedded_cmdline": raw_cmdline.decode("utf-8", errors="replace").strip(),
            "embedded_cmdline_sha256": hashlib.sha256(raw_cmdline).hexdigest(),
            "tampered_cmdline_signature_rejected": tampered_verify.returncode != 0,
        },
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--esp", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--source-reference", required=True)
    parser.add_argument("--installer-reference", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(
        args.esp,
        args.certificate,
        args.source_reference,
        args.installer_reference,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "output": str(args.output),
        "systemd_boot": True,
        "uki_sha256": result["uki"]["sha256"],
        "signature_verified": result["uki"]["signature_verified"],
        "tamper_rejected": result["uki"]["tampered_cmdline_signature_rejected"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

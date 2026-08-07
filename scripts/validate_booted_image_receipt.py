#!/usr/bin/env python3
"""Extract and validate the bounded booted-image receipt from serial output."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


MARKER = "ATTESTOS_BOOT_EVIDENCE_V1="
GUEST_FORMAT = "attestos.boot_guest_evidence/v1"
RECEIPT_FORMAT = "attestos.booted_image_canary/v1"
PCRS = {"7", "11", "12", "15"}


class ReceiptError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_guest(serial_text: str) -> dict:
    lines = [line.split(MARKER, 1)[1] for line in serial_text.splitlines()
             if MARKER in line]
    if len(lines) != 1:
        raise ReceiptError(f"expected exactly one guest marker, found {len(lines)}")
    try:
        guest = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ReceiptError("guest marker does not contain valid JSON") from exc
    validate_guest(guest)
    return guest


def validate_guest(guest: object) -> None:
    if not isinstance(guest, dict) or guest.get("format") != GUEST_FORMAT:
        raise ReceiptError("unexpected guest receipt format")
    for trust_key in (
        "manufacturer_trusted", "policy_trusted", "production_trusted",
    ):
        if guest.get(trust_key) is not False:
            raise ReceiptError(f"{trust_key} must remain false")
    if guest.get("emulated") is not True:
        raise ReceiptError("boot canary must identify itself as emulated")
    if guest.get("success") is not True:
        raise ReceiptError(f"guest canary failed: {guest.get('errors', [])}")

    tpm = guest.get("tpm")
    required_tpm = {
        "device_available", "provision_service_active",
        "ek_handle_available", "ak_handle_available",
        "required_state_available", "quote_self_check_valid",
    }
    if not isinstance(tpm, dict) or any(tpm.get(key) is not True for key in required_tpm):
        raise ReceiptError("guest TPM mechanics evidence is incomplete")

    pcrs = guest.get("pcr_values", {}).get("sha256")
    if not isinstance(pcrs, dict) or set(pcrs) != PCRS:
        raise ReceiptError("guest must report exactly SHA-256 PCRs 7, 11, 12, and 15")
    if any(not isinstance(value, str) or len(value) != 64 or
           any(c not in "0123456789abcdef" for c in value) for value in pcrs.values()):
        raise ReceiptError("guest PCR values must be lowercase SHA-256 hex digests")

    firmware = guest.get("event_logs", {}).get("tcg_firmware")
    if not isinstance(firmware, dict) or firmware.get("available") is not True:
        raise ReceiptError("TCG firmware event log is unavailable")
    if not isinstance(firmware.get("size"), int) or firmware["size"] <= 0:
        raise ReceiptError("TCG firmware event log is empty")
    if not isinstance(firmware.get("sha256"), str) or len(firmware["sha256"]) != 64:
        raise ReceiptError("TCG firmware event log digest is invalid")

    deployment = guest.get("deployment")
    if not isinstance(deployment, dict) or deployment.get("available") is not True:
        raise ReceiptError("bootc deployment evidence is unavailable")
    boot = guest.get("boot")
    if not isinstance(boot, dict) or boot.get("efi_available") is not True:
        raise ReceiptError("guest did not boot through EFI")


def build_receipt(
    guest: dict,
    disk: Path,
    source_commit: str,
    base_reference: str,
    builder_reference: str,
) -> dict:
    validate_guest(guest)
    return {
        "format": RECEIPT_FORMAT,
        "success": True,
        "source_commit": source_commit,
        "base_reference": base_reference,
        "builder_reference": builder_reference,
        "disk_sha256": sha256_file(disk),
        "execution": {
            "environment": "github-hosted-disposable-runner",
            "firmware": "ovmf",
            "machine": "q35",
            "accelerator": "tcg",
            "tpm": "swtpm-2.0",
            "network": "none",
            "local_host_mutated": False,
        },
        "guest": guest,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial-log", type=Path, required=True)
    parser.add_argument("--disk", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--base-reference", required=True)
    parser.add_argument("--builder-reference", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    guest = extract_guest(args.serial_log.read_text(encoding="utf-8", errors="replace"))
    receipt = build_receipt(
        guest,
        args.disk,
        args.source_commit,
        args.base_reference,
        args.builder_reference,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "success": True,
        "receipt": str(args.output),
        "receipt_sha256": sha256_file(args.output),
        "disk_sha256": receipt["disk_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

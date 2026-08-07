#!/usr/bin/env python3
"""Evaluate a booted UKI candidate without promoting it to policy trust."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import tempfile
from pathlib import Path

import yaml


FORMAT = "attestos.uki_admission/v1"
ZERO_SHA256 = "0" * 64


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def normalize_digest(value: object) -> str | None:
    if not isinstance(value, (str, int)):
        return None
    text = str(value).lower()
    if text.startswith("0x"):
        text = text[2:]
    return text.zfill(64) if len(text) <= 64 else None


def replay_firmware_pcr7(guest: dict) -> dict:
    encoded = guest.get("event_log_payloads", {}).get("tcg_firmware")
    expected = normalize_digest(
        guest.get("pcr_values", {}).get("sha256", {}).get("7"))
    if not isinstance(encoded, str) or expected is None:
        return {"available": False, "matches_quote": False, "reason": "missing_payload_or_pcr"}
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError:
        return {"available": False, "matches_quote": False, "reason": "invalid_base64"}
    with tempfile.TemporaryDirectory(prefix="attestos-eventlog-") as tmp:
        path = Path(tmp) / "firmware.bin"
        path.write_bytes(raw)
        proc = subprocess.run(
            ["tpm2_eventlog", "--eventlog-version=2", str(path)],
            capture_output=True,
            text=True,
        )
    if proc.returncode != 0:
        return {
            "available": True,
            "matches_quote": False,
            "reason": "tpm2_eventlog_failed",
            "diagnostic": (proc.stderr or proc.stdout)[-500:],
        }
    try:
        parsed = yaml.safe_load(proc.stdout)
        pcrs = parsed["pcrs"]["sha256"]
        actual = normalize_digest(pcrs.get(7, pcrs.get("7")))
    except (KeyError, TypeError, AttributeError, yaml.YAMLError):
        actual = None
    return {
        "available": True,
        "matches_quote": actual == expected,
        "replayed_pcr7": actual,
        "quoted_pcr7": expected,
        "reason": "ok" if actual == expected else "pcr7_mismatch",
    }


def evaluate(receipt: dict, static: dict) -> dict:
    guest = receipt.get("guest", {})
    boot = guest.get("boot", {})
    pcrs = guest.get("pcr_values", {}).get("sha256", {})
    boot_ukis = boot.get("uki_files", [])
    static_hashes = {
        item.get("sha256") for item in static.get("candidates", [])
        if isinstance(item, dict)
    }
    boot_hashes = {
        item.get("sha256") for item in boot_ukis if isinstance(item, dict)
    }
    loaded = [
        item for item in boot_ukis
        if isinstance(item, dict) and item.get("matches_loader_identifier") is True
    ]
    loaded_cmdline = loaded[0].get("embedded_cmdline", {}) if len(loaded) == 1 else {}
    loaded_hash = loaded[0].get("sha256") if len(loaded) == 1 else None
    static_matches = [
        item for item in static.get("candidates", [])
        if isinstance(item, dict) and item.get("sha256") == loaded_hash
    ]
    static_loaded = static_matches[0] if len(static_matches) == 1 else {}
    static_cmdline = static_loaded.get("embedded_cmdline", {})
    firmware_replay = replay_firmware_pcr7(guest)
    systemd_payload = guest.get("event_log_payloads", {}).get("systemd_tpm2_measure")

    gates = {
        "loaded_uki_pe_signature_verified": bool(
            static_loaded.get("verified_certificate_sha256")),
        "loaded_uki_tamper_rejected": (
            static_loaded.get("tampered_cmdline_signature_rejected") is True),
        "secure_boot_enabled": boot.get("secure_boot_enabled") is True,
        "systemd_stub_observed": (
            boot.get("stub_info_variable_present") is True and
            boot.get("stub_pcr_kernel_image_variable_present") is True),
        "exactly_one_loaded_uki": len(loaded) == 1,
        "loaded_uki_matches_one_static_candidate": len(static_matches) == 1,
        "loaded_static_cmdline_digest_matches": (
            isinstance(loaded_cmdline.get("sha256"), str) and
            loaded_cmdline.get("sha256") == static_cmdline.get("sha256")),
        "static_embedded_policy_cmdline": (
            static_cmdline.get("lockdown_confidentiality_present") is True and
            static_cmdline.get("module_sig_enforce_present") is True),
        "embedded_policy_cmdline": (
            loaded_cmdline.get("lockdown_confidentiality_present") is True and
            loaded_cmdline.get("module_sig_enforce_present") is True),
        "runtime_policy_cmdline": (
            boot.get("lockdown_confidentiality_present") is True and
            boot.get("module_sig_enforce_present") is True),
        "pcr11_nonzero": normalize_digest(pcrs.get("11")) not in (None, ZERO_SHA256),
        "firmware_pcr7_replayed": firmware_replay.get("matches_quote") is True,
        "systemd_event_log_present": isinstance(systemd_payload, str) and bool(systemd_payload),
        # A later verifier must replay the CEL-JSON sequence through the quoted
        # PCR 11/15 state. Presence alone deliberately cannot satisfy this gate.
        "systemd_event_log_replayed": False,
        # Requires two signed deployments and observed bootc transition/rollback.
        "update_rollback_invariants": False,
    }
    admitted = all(gates.values())
    return {
        "format": FORMAT,
        "admitted": admitted,
        "gates": gates,
        "firmware_replay": firmware_replay,
        "loaded_uki_count": len(loaded),
        "matched_static_candidate_count": len(static_matches),
        "boot_uki_hashes": sorted(value for value in boot_hashes if value),
        "static_uki_hashes": sorted(value for value in static_hashes if value),
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
        "non_authority": [
            "software TPM",
            "canary signing or base certificate only",
            "no manufacturer admission",
            "no anti-cheat acceptance",
            "no production policy",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--static-inspection", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    result = evaluate(load_json(args.receipt), load_json(args.static_inspection))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "admitted": result["admitted"],
        "failed_gates": sorted(name for name, passed in result["gates"].items() if not passed),
        "output": str(args.output),
    }, sort_keys=True))
    return 1 if args.enforce and not result["admitted"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Join static and boot evidence for the Fedora sealed UKI positive control."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


FORMAT = "attestos.fedora_sealed_positive_control/v1"
ZERO_SHA256 = "0" * 64
TRUST_KEYS = ("manufacturer_trusted", "policy_trusted", "production_trusted")


class EvidenceError(RuntimeError):
    pass


def load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain a JSON object")
    return value


def digest(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return None


def normalize_uefi_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return "\\" + value.replace("/", "\\").lstrip("\\").lower()


def enforce_non_authority(*artifacts: dict) -> None:
    for artifact in artifacts:
        for key in TRUST_KEYS:
            if artifact.get(key) is not False:
                raise EvidenceError(f"{key} must be explicitly false")


def evaluate(
    static: dict,
    guest: dict,
    provenance: dict,
    compatibility: dict,
    certificate_strip: dict,
    tamper: dict,
) -> dict:
    enforce_non_authority(static, guest, compatibility, certificate_strip, tamper)
    static_uki = static.get("uki", {})
    guest_uki = guest.get("loaded_uki", {})
    pcr11 = digest(guest.get("pcr_values", {}).get("sha256", {}).get("11"))
    source_reference = static.get("source_reference")
    provenance_reference = provenance.get("image_reference")
    installer_reference = static.get("installer_reference")
    provenance_installer = provenance.get("installer_reference")

    gates = {
        "immutable_source_join": (
            isinstance(source_reference, str) and
            source_reference == provenance_reference and
            "@sha256:" in source_reference
        ),
        "immutable_installer_join": (
            isinstance(installer_reference, str) and
            installer_reference == provenance_installer and
            "@sha256:" in installer_reference
        ),
        "exactly_one_static_uki": static.get("esp", {}).get("uki_count") == 1,
        "compatibility_signature_prepared": (
            static_uki.get("signature_prepared") is True and
            static_uki.get("signature_tool") ==
            "strict_certificate_strip_then_systemd-sbsign" and
            static_uki.get("signature_verification_mode") ==
            "secure_boot_firmware_admission"
        ),
        "compatibility_receipt_join": (
            compatibility.get("format") ==
            "attestos.fedora_sealed_compat_resign/v1" and
            compatibility.get("purpose") ==
            "harness_compatibility_positive_control_only" and
            compatibility.get("signature_tool") ==
            "strict_certificate_strip_then_systemd-sbsign" and
            compatibility.get("signature_verification_mode") ==
            "secure_boot_firmware_admission" and
            compatibility.get("canary_rsa_bits") == 2048 and
            compatibility.get("private_key_persisted") is False and
            digest(compatibility.get("original_uki_sha256")) is not None and
            compatibility.get("original_uki_sha256") ==
            static_uki.get("upstream_sha256") and
            digest(compatibility.get("unsigned_uki_sha256")) is not None and
            compatibility.get("unsigned_uki_sha256") not in (
                compatibility.get("original_uki_sha256"),
                compatibility.get("compatibility_signed_uki_sha256"),
            ) and
            digest(compatibility.get("compatibility_signed_uki_sha256"))
            is not None and
            compatibility.get("compatibility_signed_uki_sha256") ==
            static_uki.get("sha256") and
            digest(compatibility.get("embedded_cmdline_sha256")) is not None and
            compatibility.get("embedded_cmdline_sha256") ==
            static_uki.get("embedded_cmdline_sha256") and
            digest(compatibility.get("canary_certificate_sha256")) is not None and
            compatibility.get("canary_certificate_sha256") ==
            static_uki.get("certificate_sha256") and
            compatibility.get("original_uki_sha256") !=
            compatibility.get("compatibility_signed_uki_sha256")
        ),
        "certificate_strip_receipt_join": (
            certificate_strip.get("format") ==
            "attestos.pe_certificate_strip/v1" and
            certificate_strip.get("operation") ==
            "remove_terminal_pe_certificate_table" and
            certificate_strip.get("input_sha256") ==
            compatibility.get("original_uki_sha256") and
            certificate_strip.get("output_sha256") ==
            compatibility.get("unsigned_uki_sha256") and
            isinstance(certificate_strip.get("input_size_bytes"), int) and
            isinstance(certificate_strip.get("output_size_bytes"), int) and
            certificate_strip.get("input_size_bytes", 0) >
            certificate_strip.get("output_size_bytes", 0) > 0 and
            isinstance(
                certificate_strip.get("terminal_padding_size_bytes"), int
            ) and
            0 <= certificate_strip.get("terminal_padding_size_bytes", -1) <=
            4096 and
            certificate_strip.get("terminal_padding_all_zero") is True and
            isinstance(certificate_strip.get("certificate_count"), int) and
            certificate_strip.get("certificate_count", 0) >= 1
        ),
        "tampered_cmdline_firmware_rejected": (
            tamper.get("format") == "attestos.fedora_sealed_tamper/v1" and
            tamper.get("mutation") == "embedded_cmdline_without_resigning" and
            tamper.get("firmware_rejected") is True and
            digest(tamper.get("original_uki_sha256")) is not None and
            tamper.get("original_uki_sha256") == static_uki.get("sha256") and
            tamper.get("original_uki_sha256") ==
            compatibility.get("compatibility_signed_uki_sha256") and
            digest(tamper.get("tampered_uki_sha256")) is not None and
            tamper.get("tampered_uki_sha256") !=
            tamper.get("original_uki_sha256") and
            digest(tamper.get("original_cmdline_sha256")) is not None and
            tamper.get("original_cmdline_sha256") ==
            compatibility.get("embedded_cmdline_sha256") and
            digest(tamper.get("tampered_cmdline_sha256")) is not None and
            tamper.get("tampered_cmdline_sha256") !=
            tamper.get("original_cmdline_sha256")
        ),
        "guest_probe_success": guest.get("success") is True,
        "secure_boot_enabled": guest.get("secure_boot_enabled") is True,
        "systemd_boot_observed": (
            isinstance(guest.get("loader_info"), str) and
            guest["loader_info"].startswith("systemd-boot ")
        ),
        "systemd_stub_observed": (
            isinstance(guest.get("stub_info"), str) and
            guest["stub_info"].startswith("systemd-stub ")
        ),
        "stub_declares_pcr11": guest.get("stub_pcr_kernel_image") == "11",
        "loaded_uki_path_matches_static": (
            normalize_uefi_path(guest.get("stub_image_identifier")) ==
            normalize_uefi_path(static_uki.get("uefi_path")) ==
            normalize_uefi_path(guest_uki.get("uefi_path"))
        ),
        "loaded_uki_hash_matches_static": (
            digest(guest_uki.get("sha256")) is not None and
            guest_uki.get("sha256") == static_uki.get("sha256")
        ),
        "pcr11_nonzero": pcr11 not in (None, ZERO_SHA256),
    }
    passed = all(gates.values())
    return {
        "format": FORMAT,
        "passed": passed,
        "gates": gates,
        "failed_gates": sorted(name for name, value in gates.items() if not value),
        "image_reference": source_reference,
        "installer_reference": installer_reference,
        "loaded_uki_sha256": guest_uki.get("sha256"),
        "pcr11_sha256": pcr11,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
        "authority": "harness_positive_control_only",
        "non_authority": [
            "software TPM",
            "upstream development signing key",
            "run-local compatibility signing key",
            "no attestos agent or policy command line",
            "no manufacturer admission",
            "no production deployment",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--static", type=Path, required=True)
    parser.add_argument("--guest", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--compatibility", type=Path, required=True)
    parser.add_argument("--certificate-strip", type=Path, required=True)
    parser.add_argument("--tamper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    result = evaluate(
        load_object(args.static),
        load_object(args.guest),
        load_object(args.provenance),
        load_object(args.compatibility),
        load_object(args.certificate_strip),
        load_object(args.tamper),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "output": str(args.output),
        "passed": result["passed"],
        "failed_gates": result["failed_gates"],
    }, sort_keys=True))
    return 1 if args.enforce and not result["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

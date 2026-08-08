#!/usr/bin/env python3
"""Evaluate the isolated Fedora PCR12 signed-cmdline-addon experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


FORMAT = "attestos.fedora_pcr12_addon_canary/v1"
ZERO_SHA256 = "0" * 64
POLICY_TOKENS = ("lockdown=confidentiality", "module.sig_enforce=1")
TRUST_KEYS = ("manufacturer_trusted", "policy_trusted", "production_trusted")
BUILDER = {
    "systemd_nvr": "systemd-259.5-1.fc44",
    "ukify_rpm_sha256": "88cab2599d0f3c673bc4e4b32316682196e3be6c8376f39cd77ad5af52cca4db",
    "boot_unsigned_rpm_sha256": "a392ae378b3b6b2d2cee9233c1f3aa2333c8f9f95f65c0b30724840706a29f3f",
    "ukify_sha256": "33c1bc2a0143ac287fe2300ef6177ea4f8e6ccaa71fab8ad44741e2d5a8a7edd",
    "addon_stub_sha256": "23370bb3685f804f5c722648379f3dcbe4474998030b1595ee85690e38350ce5",
    "signature_tool": "pinned_fedora_systemd-sbsign",
    "signer_base_reference": "docker.io/library/fedora@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898",
    "systemd_rpm_sha256": "c9b1a19777ba6076bcaf6b73e4c296b3bcc2c0b983fa1c62379546f0c13da645",
    "systemd_shared_rpm_sha256": "78b5b31d5a93d5f254d534c6afa8bc4a9f105d4f39319af36971b984f7308a67",
    "systemd_sbsign_sha256": "57043bf3c84cb3e57bcf2eca79a25376db4c215f2268067b2a439b854136765a",
    "systemd_shared_object_sha256": "e7793ddb7e73eba0c1d93d3030b8eee6b71f707d68c8bb61babdaedd3762b388",
}


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


def enforce_non_authority(*artifacts: dict) -> None:
    for artifact in artifacts:
        for key in TRUST_KEYS:
            if artifact.get(key) is not False:
                raise EvidenceError(f"{key} must be explicitly false")


def pcr(guest: dict, index: str) -> str | None:
    return digest(guest.get("pcr_values", {}).get("sha256", {}).get(index))


def policy_tokens(guest: dict) -> list[str]:
    tokens = guest.get("cmdline_tokens")
    return tokens if isinstance(tokens, list) and all(isinstance(x, str) for x in tokens) else []


def replay_load_options_pcr12(tokens: tuple[str, ...] = POLICY_TOKENS) -> str:
    """Replay systemd-stub's single EFI load-options extend into SHA-256 PCR 12."""
    load_options = " ".join(tokens).encode("utf-16-le") + b"\0\0"
    event_digest = hashlib.sha256(load_options).digest()
    return hashlib.sha256(bytes(32) + event_digest).hexdigest()


def observed_addons(guest: dict) -> list[dict]:
    addons = guest.get("observed_addon_files")
    return addons if isinstance(addons, list) and all(isinstance(x, dict) for x in addons) else []


def arm_join(arm: dict, name: str, uki_sha256: str, addon_sha256: str | None) -> bool:
    expected_count = 0 if addon_sha256 is None else 1
    if not (
        arm.get("format") == "attestos.fedora_pcr12_arm/v1"
        and arm.get("arm") == name
        and arm.get("uki_sha256") == uki_sha256
        and arm.get("addon_count") == expected_count
        and arm.get("affects_uki_identity") is False
        and digest(arm.get("disk_sha256_after_install")) is not None
    ):
        return False
    addon = arm.get("addon")
    if addon_sha256 is None:
        return addon is None
    return (
        isinstance(addon, dict)
        and addon.get("name") == "10-attestos-policy.addon.efi"
        and addon.get("uefi_path") == "\\loader\\addons\\10-attestos-policy.addon.efi"
        and addon.get("sha256") == addon_sha256
        and isinstance(addon.get("size_bytes"), int)
        and addon.get("size_bytes", 0) > 0
    )


def boot_input_join(boot: dict, arm: dict, addon_static: dict, firmware: dict) -> bool:
    return (
        boot.get("format") == "attestos.fedora_sealed_boot_input/v1"
        and boot.get("disk_sha256") == arm.get("disk_sha256_after_install")
        and boot.get("ovmf_code_sha256") == firmware.get("code", {}).get("sha256")
        and boot.get("ovmf_vars_source_sha256") ==
        addon_static.get("variable_store", {}).get("extended_sha256")
        and boot.get("acceleration") == "tcg"
        and boot.get("guest_network") is False
        and boot.get("fresh_swtpm_state") is True
    )


def guest_common(guest: dict, uki_sha256: str) -> bool:
    return (
        guest.get("format") == "attestos.fedora_sealed_guest/v1"
        and guest.get("success") is True
        and guest.get("secure_boot_enabled") is True
        and isinstance(guest.get("loader_info"), str)
        and guest["loader_info"].startswith("systemd-boot ")
        and isinstance(guest.get("stub_info"), str)
        and guest["stub_info"].startswith("systemd-stub ")
        and guest.get("stub_pcr_kernel_image") == "11"
        and guest.get("loaded_uki", {}).get("sha256") == uki_sha256
        and pcr(guest, "11") not in (None, ZERO_SHA256)
        and pcr(guest, "12") is not None
    )


def guest_addon_join(guest: dict, expected_sha256: str | None) -> bool:
    addons = observed_addons(guest)
    if expected_sha256 is None:
        return addons == []
    return (
        len(addons) == 1
        and addons[0].get("name") == "10-attestos-policy.addon.efi"
        and addons[0].get("sha256") == expected_sha256
        and isinstance(addons[0].get("size_bytes"), int)
        and addons[0].get("size_bytes", 0) > 0
    )


def evaluate(
    static: dict,
    firmware: dict,
    addon_static: dict,
    baseline_arm: dict,
    baseline_boot_input: dict,
    baseline: dict,
    signed_arm_one: dict,
    signed_boot_input_one: dict,
    signed_one: dict,
    signed_arm_two: dict,
    signed_boot_input_two: dict,
    signed_two: dict,
    tampered_arm: dict,
    tampered_boot_input: dict,
    tampered: dict,
) -> dict:
    artifacts = (
        static, addon_static, baseline_arm, baseline_boot_input, baseline,
        signed_arm_one, signed_boot_input_one, signed_one, signed_arm_two,
        signed_boot_input_two, signed_two, tampered_arm, tampered_boot_input,
        tampered,
    )
    enforce_non_authority(*artifacts)

    static_uki = static.get("uki", {})
    uki_sha256 = digest(static_uki.get("sha256"))
    addon = addon_static.get("addon", {})
    builder = addon_static.get("builder", {})
    tamper_static = addon_static.get("tamper", {})
    mutation = tamper_static.get("mutation", {})
    signed_addon_sha256 = digest(addon.get("sha256"))
    tampered_addon_sha256 = digest(tamper_static.get("sha256"))
    guests = (baseline, signed_one, signed_two, tampered)
    pcr11_values = [pcr(guest, "11") for guest in guests]
    signed_pcr12 = (pcr(signed_one, "12"), pcr(signed_two, "12"))
    expected_signed_pcr12 = replay_load_options_pcr12()

    gates = {
        "frozen_upstream_uki": (
            static.get("format") == "attestos.fedora_sealed_static/v1"
            and static.get("esp", {}).get("uki_count") == 1
            and uki_sha256 is not None
            and static_uki.get("signature_verified") is True
        ),
        "addon_static_contract": (
            addon_static.get("format") == "attestos.fedora_pcr12_addon_static/v1"
            and addon_static.get("purpose") == "disposable_pcr12_addon_harness_only"
            and addon.get("name") == "10-attestos-policy.addon.efi"
            and addon.get("uefi_path") == "\\loader\\addons\\10-attestos-policy.addon.efi"
            and signed_addon_sha256 is not None
            and isinstance(addon.get("size_bytes"), int)
            and addon.get("size_bytes", 0) > 0
            and addon.get("cmdline_tokens") == list(POLICY_TOKENS)
            and addon.get("signature_verified") is True
            and addon.get("contains_linux_section") is False
            and addon.get("sbat_present") is True
            and digest(addon.get("certificate_sha256")) is not None
            and addon_static.get("private_key_persisted") is False
            and addon_static.get("source_reference") == static.get("source_reference")
        ),
        "pinned_matching_addon_builder": (
            builder == {
                **BUILDER,
                "unsigned_addon_sha256": builder.get("unsigned_addon_sha256"),
            }
            and digest(builder.get("unsigned_addon_sha256")) is not None
        ),
        "extended_variable_store_contract": (
            firmware.get("format") == "attestos.fedora_sealed_firmware/v1"
            and addon_static.get("variable_store", {}).get("source_sha256") ==
            firmware.get("variable_store", {}).get("raw_sha256")
            and addon_static.get("variable_store", {}).get(
                "original_certificates_preserved"
            ) is True
            and addon_static.get("variable_store", {}).get("canary_certificate_occurrences") == 1
            and isinstance(addon_static.get("variable_store", {}).get("original_certificate_count"), int)
            and addon_static.get("variable_store", {}).get("extended_certificate_count") ==
            addon_static.get("variable_store", {}).get("original_certificate_count") + 1
            and digest(addon_static.get("variable_store", {}).get("source_sha256")) is not None
            and digest(addon_static.get("variable_store", {}).get("extended_sha256")) is not None
            and addon_static.get("variable_store", {}).get("source_sha256") !=
            addon_static.get("variable_store", {}).get("extended_sha256")
        ),
        "tamper_static_contract": (
            tampered_addon_sha256 is not None
            and tampered_addon_sha256 != signed_addon_sha256
            and tamper_static.get("signature_rejected") is True
            and mutation.get("format") == "attestos.pe_cmdline_mutation/v1"
            and mutation.get("mutation") == "embedded_cmdline_bytes_without_resigning"
            and mutation.get("original_uki_sha256") == signed_addon_sha256
            and mutation.get("tampered_uki_sha256") == tampered_addon_sha256
            and mutation.get("only_cmdline_section_changed") is True
            and mutation.get("certificate_table_valid") is True
            and mutation.get("certificate_table_preserved") is True
            and mutation.get("outside_cmdline_sha256_before") ==
            mutation.get("outside_cmdline_sha256_after")
            and digest(mutation.get("outside_cmdline_sha256_before")) is not None
            and mutation.get("file_size_unchanged") is True
        ),
        "baseline_arm_join": arm_join(baseline_arm, "baseline", uki_sha256 or "", None),
        "signed_arm_one_join": arm_join(
            signed_arm_one, "signed", uki_sha256 or "", signed_addon_sha256
        ),
        "signed_arm_two_join": arm_join(
            signed_arm_two, "signed", uki_sha256 or "", signed_addon_sha256
        ),
        "tampered_arm_join": arm_join(
            tampered_arm, "tampered", uki_sha256 or "", tampered_addon_sha256
        ),
        "identical_firmware_inputs_joined": all((
            boot_input_join(baseline_boot_input, baseline_arm, addon_static, firmware),
            boot_input_join(signed_boot_input_one, signed_arm_one, addon_static, firmware),
            boot_input_join(signed_boot_input_two, signed_arm_two, addon_static, firmware),
            boot_input_join(tampered_boot_input, tampered_arm, addon_static, firmware),
        )),
        "all_guests_booted_common_uki": (
            uki_sha256 is not None
            and all(guest_common(guest, uki_sha256) for guest in guests)
        ),
        "pcr11_unchanged_between_arms": (
            None not in pcr11_values and len(set(pcr11_values)) == 1
        ),
        "baseline_has_no_addon": guest_addon_join(baseline, None),
        "baseline_pcr12_unextended": (
            baseline.get("stub_pcr_kernel_parameters") is None
            and pcr(baseline, "12") == ZERO_SHA256
            and all(token not in policy_tokens(baseline) for token in POLICY_TOKENS)
        ),
        "signed_addon_file_join": (
            guest_addon_join(signed_one, signed_addon_sha256)
            and guest_addon_join(signed_two, signed_addon_sha256)
        ),
        "signed_addon_policy_applied": (
            all(policy_tokens(signed_one).count(token) == 1 for token in POLICY_TOKENS)
            and all(policy_tokens(signed_two).count(token) == 1 for token in POLICY_TOKENS)
        ),
        "signed_addon_pcr12_exact_replay": (
            signed_pcr12[0] == expected_signed_pcr12
            and signed_pcr12[1] == expected_signed_pcr12
        ),
        "signed_addon_pcr12_nonzero_reproducible": (
            signed_pcr12[0] not in (None, ZERO_SHA256)
            and signed_pcr12[0] == signed_pcr12[1]
        ),
        "tampered_addon_file_join": guest_addon_join(tampered, tampered_addon_sha256),
        "tampered_addon_ignored": (
            tampered.get("stub_pcr_kernel_parameters") is None
            and pcr(tampered, "12") == ZERO_SHA256
            and pcr(tampered, "12") == pcr(baseline, "12")
            and all(token not in policy_tokens(tampered) for token in POLICY_TOKENS)
        ),
    }
    passed = all(gates.values())
    return {
        "format": FORMAT,
        "passed": passed,
        "gates": gates,
        "failed_gates": sorted(name for name, value in gates.items() if not value),
        "loaded_uki_sha256": uki_sha256,
        "signed_addon_sha256": signed_addon_sha256,
        "tampered_addon_sha256": tampered_addon_sha256,
        "pcr11_sha256": pcr11_values[0] if pcr11_values else None,
        "baseline_pcr12_sha256": pcr(baseline, "12"),
        "signed_pcr12_sha256": signed_pcr12[0],
        "expected_signed_pcr12_sha256": expected_signed_pcr12,
        "stub_pcr_kernel_parameters": {
            "baseline": baseline.get("stub_pcr_kernel_parameters"),
            "signed_one": signed_one.get("stub_pcr_kernel_parameters"),
            "signed_two": signed_two.get("stub_pcr_kernel_parameters"),
            "tampered": tampered.get("stub_pcr_kernel_parameters"),
        },
        "tampered_pcr12_sha256": pcr(tampered, "12"),
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
        "authority": "harness_pcr12_addon_only",
        "non_authority": [
            "software TPM",
            "run-local disposable addon signing key",
            "modified disposable OVMF variable store",
            "guest observations rather than externally verified quote",
            "no event-log replay",
            "no manufacturer or production admission",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in (
        "static", "firmware", "addon_static", "baseline_arm",
        "baseline_boot_input", "baseline_guest", "signed_arm_one",
        "signed_boot_input_one", "signed_guest_one", "signed_arm_two",
        "signed_boot_input_two", "signed_guest_two", "tampered_arm",
        "tampered_boot_input", "tampered_guest",
    ):
        parser.add_argument(f"--{name.replace('_', '-')}", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    result = evaluate(
        load_object(args.static),
        load_object(args.firmware),
        load_object(args.addon_static),
        load_object(args.baseline_arm),
        load_object(args.baseline_boot_input),
        load_object(args.baseline_guest),
        load_object(args.signed_arm_one),
        load_object(args.signed_boot_input_one),
        load_object(args.signed_guest_one),
        load_object(args.signed_arm_two),
        load_object(args.signed_boot_input_two),
        load_object(args.signed_guest_two),
        load_object(args.tampered_arm),
        load_object(args.tampered_boot_input),
        load_object(args.tampered_guest),
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

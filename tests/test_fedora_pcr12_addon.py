from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load(
    "fedora_pcr12_validator", ROOT / "scripts/validate_fedora_pcr12_addon.py"
)
probe = load("fedora_probe_pcr12", ROOT / "scripts/fedora_sealed_guest_probe.py")

UKI = "a" * 64
PCR11 = "b" * 64
PCR12 = "c" * 64
ADDON = "d" * 64
TAMPERED = "e" * 64
ZERO = "0" * 64
POLICY = ["lockdown=confidentiality", "module.sig_enforce=1"]


def non_authority() -> dict:
    return {
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def static_evidence() -> dict:
    return {
        "format": "attestos.fedora_sealed_static/v1",
        "source_reference": "example.invalid/fedora@sha256:" + "6" * 64,
        "esp": {"uki_count": 1},
        "uki": {"sha256": UKI, "signature_verified": True},
        **non_authority(),
    }


def addon_static() -> dict:
    return {
        "format": "attestos.fedora_pcr12_addon_static/v1",
        "purpose": "disposable_pcr12_addon_harness_only",
        "source_reference": "example.invalid/fedora@sha256:" + "6" * 64,
        "builder": {
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
            "unsigned_addon_sha256": "8" * 64,
        },
        "addon": {
            "name": "10-attestos-policy.addon.efi",
            "uefi_path": "\\loader\\addons\\10-attestos-policy.addon.efi",
            "sha256": ADDON,
            "size_bytes": 4096,
            "cmdline_tokens": POLICY,
            "signature_verified": True,
            "contains_linux_section": False,
            "certificate_sha256": "f" * 64,
            "sbat_present": True,
        },
        "tamper": {
            "sha256": TAMPERED,
            "signature_rejected": True,
            "mutation": {
                "format": "attestos.pe_cmdline_mutation/v1",
                "mutation": "embedded_cmdline_bytes_without_resigning",
                "original_uki_sha256": ADDON,
                "tampered_uki_sha256": TAMPERED,
                "certificate_table_valid": True,
                "certificate_table_preserved": True,
                "outside_cmdline_sha256_before": "0" * 64,
                "outside_cmdline_sha256_after": "0" * 64,
                "only_cmdline_section_changed": True,
                "file_size_unchanged": True,
            },
        },
        "variable_store": {
            "source_sha256": "1" * 64,
            "extended_sha256": "2" * 64,
            "original_certificates_preserved": True,
            "original_certificate_count": 3,
            "extended_certificate_count": 4,
            "canary_certificate_occurrences": 1,
        },
        "private_key_persisted": False,
        **non_authority(),
    }


def arm(name: str, addon_hash: str | None) -> dict:
    disk_hash = {"baseline": "3", "signed": "4", "tampered": "5"}[name] * 64
    return {
        "format": "attestos.fedora_pcr12_arm/v1",
        "arm": name,
        "uki_sha256": UKI,
        "addon_count": 0 if addon_hash is None else 1,
        "addon": None if addon_hash is None else {
            "name": "10-attestos-policy.addon.efi",
            "uefi_path": "\\loader\\addons\\10-attestos-policy.addon.efi",
            "sha256": addon_hash,
            "size_bytes": 4096,
        },
        "affects_uki_identity": False,
        "disk_sha256_after_install": disk_hash,
        **non_authority(),
    }


def firmware() -> dict:
    return {
        "format": "attestos.fedora_sealed_firmware/v1",
        "code": {"sha256": "6" * 64},
        "variable_store": {"raw_sha256": "1" * 64},
    }


def boot_input(arm_evidence: dict) -> dict:
    return {
        "format": "attestos.fedora_sealed_boot_input/v1",
        "disk_sha256": arm_evidence["disk_sha256_after_install"],
        "ovmf_code_sha256": "6" * 64,
        "ovmf_vars_source_sha256": "2" * 64,
        "acceleration": "tcg",
        "guest_network": False,
        "fresh_swtpm_state": True,
        **non_authority(),
    }


def guest(kind: str) -> dict:
    if kind == "baseline":
        pcr12, stub_parameters, tokens, addons = ZERO, None, ["rw"], []
    elif kind == "signed":
        pcr12, stub_parameters, tokens = PCR12, "12", ["rw", *POLICY]
        addons = [{"name": "10-attestos-policy.addon.efi", "sha256": ADDON, "size_bytes": 4096}]
    elif kind == "tampered":
        pcr12, stub_parameters, tokens = ZERO, None, ["rw"]
        addons = [{"name": "10-attestos-policy.addon.efi", "sha256": TAMPERED, "size_bytes": 4096}]
    else:
        raise AssertionError(kind)
    return {
        "format": "attestos.fedora_sealed_guest/v1",
        "success": True,
        "secure_boot_enabled": True,
        "loader_info": "systemd-boot 259.5-1.fc44",
        "stub_info": "systemd-stub 259.5-1.fc44",
        "stub_pcr_kernel_image": "11",
        "stub_pcr_kernel_parameters": stub_parameters,
        "loaded_uki": {"sha256": UKI},
        "pcr_values": {"sha256": {"11": PCR11, "12": pcr12}},
        "cmdline_tokens": tokens,
        "observed_addon_files": addons,
        **non_authority(),
    }


def evaluate_with(
    *,
    addon_static_evidence: dict | None = None,
    baseline_guest: dict | None = None,
    signed_guest_one: dict | None = None,
    signed_guest_two: dict | None = None,
    tampered_guest: dict | None = None,
    baseline_boot_input: dict | None = None,
) -> dict:
    baseline_arm = arm("baseline", None)
    signed_arm_one = arm("signed", ADDON)
    signed_arm_two = arm("signed", ADDON)
    tampered_arm = arm("tampered", TAMPERED)
    return validator.evaluate(
        static_evidence(), firmware(), addon_static_evidence or addon_static(), baseline_arm,
        baseline_boot_input or boot_input(baseline_arm),
        baseline_guest or guest("baseline"),
        signed_arm_one, boot_input(signed_arm_one),
        signed_guest_one or guest("signed"),
        signed_arm_two, boot_input(signed_arm_two),
        signed_guest_two or guest("signed"),
        tampered_arm, boot_input(tampered_arm),
        tampered_guest or guest("tampered"),
    )


def test_complete_three_arm_contract_passes():
    result = evaluate_with()
    assert result["passed"] is True
    assert all(result["gates"].values())
    assert result["authority"] == "harness_pcr12_addon_only"


def test_pcr11_change_refutes_additive_claim():
    signed = guest("signed")
    signed["pcr_values"]["sha256"]["11"] = "9" * 64
    result = evaluate_with(signed_guest_one=signed)
    assert result["gates"]["pcr11_unchanged_between_arms"] is False


def test_addon_pcr12_must_reproduce():
    second = guest("signed")
    second["pcr_values"]["sha256"]["12"] = "8" * 64
    result = evaluate_with(signed_guest_two=second)
    assert result["gates"]["signed_addon_pcr12_nonzero_reproducible"] is False


def test_tampered_addon_must_be_present_but_not_applied():
    tampered = guest("tampered")
    tampered["stub_pcr_kernel_parameters"] = "12"
    tampered["cmdline_tokens"].append(POLICY[0])
    result = evaluate_with(tampered_guest=tampered)
    assert result["gates"]["tampered_addon_file_join"] is True
    assert result["gates"]["tampered_addon_ignored"] is False


def test_decoy_addon_cannot_satisfy_signed_arm():
    signed = guest("signed")
    signed["observed_addon_files"][0]["sha256"] = "7" * 64
    result = evaluate_with(signed_guest_one=signed)
    assert result["gates"]["signed_addon_file_join"] is False


def test_guest_cannot_promote_policy_trust():
    signed = guest("signed")
    signed["policy_trusted"] = True
    with pytest.raises(validator.EvidenceError, match="policy_trusted"):
        evaluate_with(signed_guest_one=signed)


def test_boot_input_must_join_exact_installed_disk_and_firmware():
    baseline_arm = arm("baseline", None)
    wrong = boot_input(baseline_arm)
    wrong["disk_sha256"] = "9" * 64
    result = evaluate_with(baseline_boot_input=wrong)
    assert result["gates"]["identical_firmware_inputs_joined"] is False


def test_signer_base_must_match_the_pinned_builder():
    evidence = addon_static()
    evidence["builder"]["signer_base_reference"] = "example.invalid/decoy@sha256:" + "9" * 64
    result = evaluate_with(addon_static_evidence=evidence)
    assert result["gates"]["pinned_matching_addon_builder"] is False


def test_tamper_requires_a_valid_preserved_certificate_table():
    evidence = addon_static()
    evidence["tamper"]["mutation"]["certificate_table_valid"] = False
    result = evaluate_with(addon_static_evidence=evidence)
    assert result["gates"]["tamper_static_contract"] is False


def test_pcr12_read_command_selects_only_sha256_pcr12():
    command = probe.pcr_read_command(12)
    tag, size, command_code = struct.unpack_from(">HII", command)
    assert tag == 0x8001
    assert size == len(command)
    assert command_code == 0x0000017E
    assert command[-3:] == bytes((0x00, 0x10, 0x00))


def test_scripts_preserve_nonpublication_and_private_key_boundary():
    preparer = (ROOT / "scripts/prepare_fedora_pcr12_addon.sh").read_text()
    installer = (ROOT / "scripts/install_fedora_pcr12_arm.sh").read_text()
    runner = (ROOT / "scripts/run_fedora_sealed_positive_control.sh").read_text()
    workflow = (
        ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml"
    ).read_text()
    signer_containerfile = (
        ROOT / "canary/fedora-sealed/Containerfile.addon-signer"
    ).read_text()
    assert 'python3 "$ukify" build' in workflow
    assert '--stub="$stub"' in workflow
    assert "systemd-sbsign" in preparer
    assert "--private-key" not in preparer
    assert "ATTESTOS_FEDORA_SIGNER_IMAGE" in preparer
    assert "ATTESTOS_FEDORA_SIGNER_PREFLIGHT" in preparer
    assert "ATTESTOS_SYSTEMD_SBSIGN_SHA256" in preparer
    assert "ATTESTOS_SYSTEMD_SHARED_OBJECT_SHA256" in preparer
    assert 'mktemp -d -p "$(dirname "$output")"' in preparer
    assert "signed add-on did not grow a certificate table" in preparer
    assert "--network=none" in preparer
    assert "10-attestos-policy.unsigned.addon.efi" in preparer
    assert "--add-db" in preparer
    assert "private_key_persisted: false" in preparer
    assert 'test ! -e "$preflight/addon.key"' in preparer
    assert "packages: write" not in preparer
    assert "expected exactly one installed UKI" in installer
    assert '[[ "$uki_sha256" == "$expected_uki_sha256" ]]' in installer
    assert "base disk unexpectedly contains" in installer
    assert "attestos.fedora_sealed_boot_input/v1" in runner
    assert "disk_sha256: $disk_sha256" in runner
    assert "permissions:\n  contents: read" in workflow
    assert "packages: write" not in workflow
    assert "attestos PCR12 disposable canary" in workflow
    assert "tampered signer preflight add-on still verifies" in workflow
    assert 'rm -f "$smoke/addon.key"' in workflow
    assert "/usr/lib/systemd/systemd-sbsign sign" in workflow
    assert "ATTESTOS_FEDORA_SIGNER_PREFLIGHT" in workflow
    assert "RUN " not in signer_containerfile
    assert "fedora@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898" in signer_containerfile
    assert "COPY usr/lib/systemd/systemd-sbsign" in signer_containerfile
    assert "fedora-output/static-inspection.json" in workflow
    assert "fedora-output/firmware-provenance.json" in workflow
    assert "fedora-output/pcr12/addon-public.pem" in workflow
    assert "fedora-output/pcr12/addon.key" not in workflow

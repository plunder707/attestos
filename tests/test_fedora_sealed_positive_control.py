from __future__ import annotations

import importlib.util
import json
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
    "fedora_validator", ROOT / "scripts/validate_fedora_sealed_positive_control.py"
)
probe = load("fedora_probe", ROOT / "scripts/fedora_sealed_guest_probe.py")
console = load(
    "fedora_console", ROOT / "scripts/drive_fedora_sealed_console.py"
)
stripper = load(
    "pe_certificate_stripper", ROOT / "scripts/strip_pe_certificate_table.py"
)
inspector = load(
    "fedora_disk_inspector", ROOT / "scripts/inspect_fedora_sealed_disk.py"
)
cmdline_mutator = load(
    "pe_cmdline_mutator", ROOT / "scripts/mutate_pe_cmdline.py"
)


IMAGE = (
    "quay.io/fedora-atomic-desktops-sealed/silverblue@sha256:"
    + "d" * 64
)
INSTALLER = (
    "quay.io/fedora-atomic-desktops-sealed/tools@sha256:"
    + "e" * 64
)
UKI = "a" * 64
PCR11 = "b" * 64


def static_evidence() -> dict:
    return {
        "format": "attestos.fedora_sealed_static/v1",
        "source_reference": IMAGE,
        "installer_reference": INSTALLER,
        "esp": {"uki_count": 1},
        "uki": {
            "uefi_path": "\\EFI\\Linux\\fedora.efi",
            "sha256": UKI,
            "upstream_sha256": "c" * 64,
            "upstream_size_bytes": 8192,
            "installed_upstream_sha256": "f" * 64,
            "installed_upstream_size_bytes": 4096,
            "immutable_source_reference": IMAGE,
            "immutable_source_signature_verified": True,
            "embedded_cmdline_sha256": "b" * 64,
            "certificate_sha256": "d" * 64,
            "signature_verified": False,
            "signature_prepared": True,
            "signature_tool": "strict_certificate_strip_then_systemd-sbsign",
            "signature_verification_mode": "secure_boot_firmware_admission",
            "tampered_cmdline_firmware_rejected": True,
        },
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def guest_evidence() -> dict:
    return {
        "format": "attestos.fedora_sealed_guest/v1",
        "success": True,
        "secure_boot_enabled": True,
        "loader_info": "systemd-boot 261",
        "stub_info": "systemd-stub 261",
        "stub_image_identifier": "\\EFI\\Linux\\fedora.efi",
        "stub_pcr_kernel_image": "11",
        "loaded_uki": {
            "uefi_path": "/EFI/Linux/fedora.efi",
            "sha256": UKI,
        },
        "pcr_values": {"sha256": {"11": PCR11}},
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def provenance() -> dict:
    return {"image_reference": IMAGE, "installer_reference": INSTALLER}


def compatibility_evidence() -> dict:
    return {
        "format": "attestos.fedora_sealed_compat_resign/v1",
        "purpose": "harness_compatibility_positive_control_only",
        "source_reference": IMAGE,
        "installed_upstream_uki_sha256": "f" * 64,
        "installed_upstream_uki_size_bytes": 4096,
        "immutable_source_uki_sha256": "c" * 64,
        "immutable_source_uki_size_bytes": 8192,
        "immutable_source_signature_verified": True,
        "installed_and_source_cmdline_match": True,
        "original_uki_sha256": "c" * 64,
        "unsigned_uki_sha256": "1" * 64,
        "compatibility_signed_uki_sha256": UKI,
        "embedded_cmdline_sha256": "b" * 64,
        "canary_certificate_sha256": "d" * 64,
        "canary_rsa_bits": 2048,
        "signature_tool": "strict_certificate_strip_then_systemd-sbsign",
        "signature_verification_mode": "secure_boot_firmware_admission",
        "private_key_persisted": False,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def tamper_evidence() -> dict:
    return {
        "format": "attestos.fedora_sealed_tamper/v1",
        "layout_format": "attestos.pe_cmdline_mutation/v1",
        "mutation": "embedded_cmdline_bytes_without_resigning",
        "original_uki_sha256": UKI,
        "tampered_uki_sha256": "f" * 64,
        "original_cmdline_sha256": "b" * 64,
        "tampered_cmdline_sha256": "e" * 64,
        "certificate_table_sha256_before": "9" * 64,
        "certificate_table_sha256_after": "9" * 64,
        "certificate_table_preserved": True,
        "file_size_unchanged": True,
        "firmware_rejected": True,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def certificate_strip_evidence() -> dict:
    return {
        "format": "attestos.pe_certificate_strip/v1",
        "operation": "remove_terminal_pe_certificate_table",
        "input_sha256": "c" * 64,
        "input_size_bytes": 4096,
        "output_sha256": "1" * 64,
        "output_size_bytes": 2048,
        "terminal_padding_size_bytes": 0,
        "terminal_padding_all_zero": True,
        "certificate_count": 1,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def synthetic_signed_pe(extra: bytes = b"") -> bytes:
    pe_offset = 0x80
    optional_offset = pe_offset + 4 + 20
    certificate_directory = optional_offset + 112 + 4 * 8
    certificate_offset = 0x200
    data = bytearray(certificate_offset)
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4 + 16, 0xF0)
    struct.pack_into("<H", data, optional_offset, 0x20B)
    struct.pack_into("<I", data, optional_offset + 108, 16)
    struct.pack_into("<II", data, certificate_directory, certificate_offset, 16)
    data.extend(struct.pack("<IHH8s", 16, 0x0200, 0x0002, b"signature"))
    data.extend(extra)
    return bytes(data)


def synthetic_signed_pe_with_cmdline() -> bytes:
    pe_offset = 0x80
    optional_offset = pe_offset + 4 + 20
    optional_end = optional_offset + 0xF0
    certificate_directory = optional_offset + 112 + 4 * 8
    cmdline_offset = 0x200
    cmdline_size = 0x40
    certificate_offset = cmdline_offset + cmdline_size
    data = bytearray(certificate_offset)
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe_offset + 4 + 2, 1)
    struct.pack_into("<H", data, pe_offset + 4 + 16, 0xF0)
    struct.pack_into("<H", data, optional_offset, 0x20B)
    struct.pack_into("<I", data, optional_offset + 108, 16)
    struct.pack_into("<II", data, certificate_directory, certificate_offset, 16)
    section = optional_end
    data[section:section + 8] = b".cmdline"
    struct.pack_into("<II", data, section + 16, cmdline_size, cmdline_offset)
    data[cmdline_offset:cmdline_offset + len(b"quiet\0")] = b"quiet\0"
    data.extend(struct.pack("<IHH8s", 16, 0x0200, 0x0002, b"signature"))
    return bytes(data)


def test_strict_certificate_strip_removes_only_terminal_table():
    source = synthetic_signed_pe()
    stripped, details = stripper.strip_certificate_table(source)
    assert stripped == source[:0x200][:0x128] + b"\0" * 8 + source[:0x200][0x130:]
    assert details["certificate_table_offset"] == 0x200
    assert details["certificate_table_size"] == 16
    assert details["terminal_padding_size_bytes"] == 0
    assert details["terminal_padding_all_zero"] is True
    assert details["certificate_count"] == 1
    assert details["certificates"][0]["certificate_type"] == 0x0002


def test_certificate_strip_rejects_nonterminal_or_malformed_tables():
    with pytest.raises(stripper.PEError, match="unexplained trailing overlay"):
        stripper.strip_certificate_table(synthetic_signed_pe(b"overlay"))
    with pytest.raises(stripper.PEError, match="unexplained trailing overlay"):
        stripper.strip_certificate_table(
            synthetic_signed_pe(b"\0" * (stripper.MAX_TERMINAL_PADDING + 8))
        )
    malformed = bytearray(synthetic_signed_pe())
    struct.pack_into("<I", malformed, 0x200, 7)
    with pytest.raises(stripper.PEError, match="smaller than its header"):
        stripper.strip_certificate_table(bytes(malformed))


def test_certificate_strip_accepts_only_bounded_zero_terminal_padding():
    source = synthetic_signed_pe(b"\0" * 504)
    stripped, details = stripper.strip_certificate_table(source)
    assert stripped == source[:0x200][:0x128] + b"\0" * 8 + source[:0x200][0x130:]
    assert details["terminal_padding_size_bytes"] == 504
    assert details["terminal_padding_all_zero"] is True


def test_certificate_strip_reports_possible_omitted_certificate_alignment():
    source = bytearray(synthetic_signed_pe())
    struct.pack_into("<I", source, 0x200, 15)
    del source[-1]
    with pytest.raises(
        stripper.PEError,
        match=r"missing=1 .*possible_omitted_alignment=True",
    ):
        stripper.strip_certificate_table(bytes(source))


def test_cmdline_mutation_preserves_certificate_bytes_and_file_size():
    source = synthetic_signed_pe_with_cmdline()
    mutated, details = cmdline_mutator.mutate_cmdline(source)
    assert len(mutated) == len(source)
    assert mutated[:0x200] == source[:0x200]
    assert mutated[0x240:] == source[0x240:]
    assert details["certificate_table_preserved"] is True
    assert details["file_size_unchanged"] is True
    assert details["original_cmdline_sha256"] != details["tampered_cmdline_sha256"]


def test_cmdline_dump_uses_disposable_objcopy_input(tmp_path, monkeypatch):
    source = tmp_path / "source.efi"
    destination = tmp_path / "cmdline"
    source.write_bytes(b"signed-source")

    def fake_run(*args, **_kwargs):
        scratch = Path(args[-1])
        assert scratch != source
        scratch.write_bytes(b"objcopy-rewrite")
        destination.write_bytes(b"quiet\0")

    monkeypatch.setattr(inspector, "run", fake_run)
    assert inspector.dump_cmdline(source, destination) == b"quiet"
    assert source.read_bytes() == b"signed-source"


def test_positive_control_requires_every_join():
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is True
    assert all(result["gates"].values())
    assert result["authority"] == "harness_positive_control_only"
    assert result["policy_trusted"] is False


def test_direct_upstream_positive_control_requires_original_signed_uki():
    static = static_evidence()
    static["uki"]["signature_verified"] = True
    result = validator.evaluate_direct(
        static, guest_evidence(), provenance(), tamper_evidence()
    )
    assert result["passed"] is True
    assert all(result["gates"].values())
    assert result["mode"] == "immutable_upstream_uki"
    assert "run-local compatibility signing key" not in result["non_authority"]


def test_direct_upstream_rejects_tamper_receipt_that_rewrites_certificate():
    static = static_evidence()
    static["uki"]["signature_verified"] = True
    tamper = tamper_evidence()
    tamper["certificate_table_preserved"] = False
    result = validator.evaluate_direct(static, guest_evidence(), provenance(), tamper)
    assert result["passed"] is False
    assert result["gates"]["tampered_cmdline_firmware_rejected"] is False


def test_zero_pcr11_fails_closed():
    guest = guest_evidence()
    guest["pcr_values"]["sha256"]["11"] = "0" * 64
    result = validator.evaluate(
        static_evidence(), guest, provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["pcr11_nonzero"] is False


def test_guest_probe_failure_is_named_in_failed_gates():
    guest = guest_evidence()
    guest["success"] = False
    result = validator.evaluate(
        static_evidence(), guest, provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["guest_probe_success"] is False
    assert "guest_probe_success" in result["failed_gates"]


def test_installer_version_cannot_drift_from_provenance():
    evidence = provenance()
    evidence["installer_reference"] = INSTALLER.replace("e" * 64, "f" * 64)
    result = validator.evaluate(
        static_evidence(), guest_evidence(), evidence,
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["immutable_installer_join"] is False


def test_unloaded_decoy_cannot_satisfy_identity_join():
    guest = guest_evidence()
    guest["loaded_uki"]["sha256"] = "c" * 64
    result = validator.evaluate(
        static_evidence(), guest, provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["loaded_uki_hash_matches_static"] is False


def test_wrong_loaded_path_fails_even_when_hash_matches():
    guest = guest_evidence()
    guest["stub_image_identifier"] = "\\EFI\\Linux\\decoy.efi"
    result = validator.evaluate(
        static_evidence(), guest, provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["loaded_uki_path_matches_static"] is False


@pytest.mark.parametrize(
    "key", ["manufacturer_trusted", "policy_trusted", "production_trusted"]
)
def test_guest_cannot_promote_a_trust_stage(key):
    guest = guest_evidence()
    guest[key] = True
    with pytest.raises(validator.EvidenceError, match=key):
        validator.evaluate(
            static_evidence(), guest, provenance(),
            compatibility_evidence(), certificate_strip_evidence(), tamper_evidence()
        )


def test_compatibility_receipt_must_bind_original_and_resigned_hashes():
    compatibility = compatibility_evidence()
    compatibility["compatibility_signed_uki_sha256"] = "e" * 64
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility, certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["compatibility_receipt_join"] is False


def test_compatibility_receipt_must_bind_installed_and_immutable_source():
    compatibility = compatibility_evidence()
    compatibility["immutable_source_uki_sha256"] = "e" * 64
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility, certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["compatibility_receipt_join"] is False


@pytest.mark.parametrize(
    "field",
    ["embedded_cmdline_sha256", "canary_certificate_sha256"],
)
def test_compatibility_receipt_must_bind_signing_inputs(field):
    compatibility = compatibility_evidence()
    compatibility[field] = "e" * 64
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility, certificate_strip_evidence(), tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["compatibility_receipt_join"] is False


def test_certificate_strip_receipt_must_join_original_and_unsigned_hashes():
    certificate_strip = certificate_strip_evidence()
    certificate_strip["output_sha256"] = "2" * 64
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility_evidence(), certificate_strip, tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["certificate_strip_receipt_join"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("terminal_padding_size_bytes", 4097),
        ("terminal_padding_all_zero", False),
    ],
)
def test_certificate_strip_receipt_rejects_unexplained_padding(field, value):
    certificate_strip = certificate_strip_evidence()
    certificate_strip[field] = value
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility_evidence(), certificate_strip, tamper_evidence()
    )
    assert result["passed"] is False
    assert result["gates"]["certificate_strip_receipt_join"] is False


def test_tamper_receipt_must_bind_exact_signed_hash_and_firmware_rejection():
    tamper = tamper_evidence()
    tamper["firmware_rejected"] = False
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper
    )
    assert result["passed"] is False
    assert result["gates"]["tampered_cmdline_firmware_rejected"] is False


def test_tamper_receipt_must_bind_the_normalized_embedded_cmdline():
    tamper = tamper_evidence()
    tamper["original_cmdline_sha256"] = "a" * 64
    result = validator.evaluate(
        static_evidence(), guest_evidence(), provenance(),
        compatibility_evidence(), certificate_strip_evidence(), tamper
    )
    assert result["passed"] is False
    assert result["gates"]["tampered_cmdline_firmware_rejected"] is False


def test_pcr_read_command_selects_only_sha256_pcr11():
    command = probe.pcr_read_command(11)
    tag, size, command_code = struct.unpack_from(">HII", command)
    assert tag == 0x8001
    assert size == len(command)
    assert command_code == 0x0000017E
    assert command[-3:] == bytes((0x00, 0x08, 0x00))


def test_pcr_read_response_parser_accepts_one_canonical_digest():
    digest = bytes.fromhex(PCR11)
    body = (
        struct.pack(">I", 7)
        + struct.pack(">IHB", 1, 0x000B, 3)
        + bytes((0x00, 0x08, 0x00))
        + struct.pack(">IH", 1, 32)
        + digest
    )
    response = struct.pack(">HII", 0x8001, 10 + len(body), 0) + body
    assert probe.parse_pcr_read_response(response) == PCR11


def test_workflow_and_runner_preserve_isolation_and_nonpublication():
    workflow = (ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml").read_text()
    runner = (ROOT / "scripts/run_fedora_sealed_positive_control.sh").read_text()
    assert "contents: read" in workflow
    assert "packages: write" not in workflow
    assert "id-token: write" not in workflow
    assert "-nic none" in runner
    assert "accel=tcg" in runner
    assert "-enable-kvm" not in runner
    assert "--network=none" in (
        ROOT / "scripts/build_fedora_sealed_disk.sh"
    ).read_text()


def test_version_matched_installer_uses_source_prepare_root_contract():
    builder = (ROOT / "scripts/build_fedora_sealed_disk.sh").read_text()
    assert '"$source_reference"' in builder
    assert "sh -c 'for path in" in builder
    assert '/usr/lib/ostree/prepare-root.conf:ro' in builder
    assert 'source-prepare-root.sha256' in builder


def test_static_inspection_discovers_nested_bootc_uki_path():
    inspector = (ROOT / "scripts/inspect_fedora_sealed_disk.py").read_text()
    assert '(esp / "EFI" / "Linux").rglob("*.efi")' in inspector


def test_historical_control_binds_source_and_installer_to_one_digest():
    workflow = (
        ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml"
    ).read_text()
    image_line = next(
        line for line in workflow.splitlines()
        if line.strip().startswith("ATTESTOS_FEDORA_IMAGE_REFERENCE:")
    )
    installer_line = next(
        line for line in workflow.splitlines()
        if line.strip().startswith("ATTESTOS_FEDORA_INSTALLER_IMAGE_REFERENCE:")
    )
    assert image_line.split(": ", 1)[1] == installer_line.split(": ", 1)[1]
    assert "ATTESTOS_FEDORA_UPSTREAM_RUN_ID: '24482575655'" in workflow
    assert "source-inspection.json" in workflow


def test_upstream_pair_is_frozen_without_a_run_local_signing_authority():
    workflow = (
        ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml"
    ).read_text()
    runner = (ROOT / "scripts/run_fedora_sealed_positive_control.sh").read_text()
    assert "ATTESTOS_FEDORA_EDK2_NVR: edk2-20260213-4.fc44" in workflow
    assert "ATTESTOS_FEDORA_EDK2_OVMF_RPM_SHA256:" in workflow
    assert "kojipkgs.fedoraproject.org/packages/edk2/20260213/4.fc44" in workflow
    assert "rpm2cpio ../edk2-ovmf.rpm" in workflow
    assert 'qemu-img convert -f qcow2 -O raw "$code_qcow2" "$code"' in workflow
    assert "ATTESTOS_FEDORA_OVMF_VARS_SHA256:" in workflow
    assert 'fedora-output/OVMF_VARS_CUSTOM.qcow2' in workflow
    assert "--set-pk" not in workflow
    assert "--add-kek" not in workflow
    assert "--add-db" not in workflow
    assert "--extract-certs" in workflow
    assert "[[ $rc -eq 80 ]]" in workflow
    assert 'fedora-output/upstream-tamper.qcow2' in workflow
    assert '-b "$PWD/fedora-output/fedora-sealed.qcow2"' in workflow
    assert 'rm -f fedora-output/upstream-tamper.qcow2' in workflow
    assert "canary-signing.key" not in workflow
    assert "prepare_fedora_sealed_compat_control.sh" not in workflow.split(
        "- name: Install sealed image through systemd-boot", 1
    )[1]
    assert "ATTESTOS_FEDORA_OVMF_CODE=$code" in workflow
    assert "ATTESTOS_FEDORA_OVMF_CODE" in runner


def test_console_driver_is_observation_only_across_slow_tcg_boot():
    source = (ROOT / "scripts/drive_fedora_sealed_console.py").read_text()
    assert 'default=960' in source
    assert '"--screenshot-interval", type=int, default=30' in source
    assert "human-monitor-command" not in source
    assert "sendkey" not in source
    assert "ctrl-alt-f9" not in source
    assert "console_probe_attempt" not in source
    assert 'qmp.screendump(screenshot)' in source


def test_disposable_positive_control_root_is_explicitly_unencrypted():
    builder = (ROOT / "scripts/build_fedora_sealed_disk.sh").read_text()
    partition = (
        ROOT / "canary/fedora-sealed/repart.d/02-sysroot.conf"
    ).read_text()
    assert "plain root" in builder
    assert 'sudo mount "$root" "$mount_root"' in builder
    assert "cryptsetup" not in builder
    assert not any(line.startswith("Encrypt=") for line in partition.splitlines())


def test_fedora_runner_preserves_visual_diagnostics_without_guest_network():
    runner = (ROOT / "scripts/run_fedora_sealed_positive_control.sh").read_text()
    workflow = (
        ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml"
    ).read_text()
    assert "-nic none" in runner
    assert "-vga std" in runner
    assert '--output-dir "$output"' in runner
    assert "unlock_attempts=" not in runner
    assert "screen-*.ppm" in workflow


def test_probe_unit_is_explicitly_outside_sealed_usr_and_non_authoritative():
    builder = (ROOT / "scripts/build_fedora_sealed_disk.sh").read_text()
    unit = (
        ROOT / "canary/fedora-sealed/fedora-sealed-positive-control.service"
    ).read_text()
    assert "scripts/inspect_fedora_sealed_disk.py" in builder
    assert builder.index("scripts/inspect_fedora_sealed_disk.py") < builder.index(
        'probe_dir="$mount_root/etc/attestos-positive-control"'
    )
    assert "mutable_etc_outside_sealed_usr" in builder
    assert "affects_static_uki_identity: false" in builder
    assert "manufacturer_trusted: false" in builder
    assert "policy_trusted: false" in builder
    assert "production_trusted: false" in builder
    assert "ConditionPathExists=/dev/vdb" in unit
    assert "/etc/attestos-positive-control/fedora_sealed_guest_probe.py" in unit


def test_firmware_rejection_stops_without_waiting_for_global_timeout():
    runner = (ROOT / "scripts/run_fedora_sealed_positive_control.sh").read_text()
    assert "Secure Boot firmware rejected the installed UKI" in runner
    assert "exit 80" in runner


def test_compatibility_resign_preserves_original_as_a_separate_negative_gate():
    preparer = (
        ROOT / "scripts/prepare_fedora_sealed_compat_control.sh"
    ).read_text()
    assert 'installed_sha256=$(sudo sha256sum "$installed_uki"' in preparer
    assert '[[ "$installed_sha256" == "$expected_sha256" ]]' in preparer
    assert '[[ "$upstream_cert_sha256" == "$expected_cert_sha256" ]]' in preparer
    assert 'podman cp "$source_container:/boot/EFI/Linux/."' in preparer
    assert 'sbverify --cert "$upstream_cert" "$work/original.efi"' in preparer
    assert 'cmp "$work/installed.cmdline" "$work/original.cmdline"' in preparer
    assert "--network=none" in preparer
    assert "scripts/strip_pe_certificate_table.py" in preparer
    assert '--receipt "$output/certificate-strip.json"' in preparer
    assert "systemd-sbsign" in preparer
    assert "--private-key=/work/canary-signing.key" in preparer
    assert "/work/unsigned.efi" in preparer
    assert 'rm -f "$work/canary-signing.key"' in preparer
    assert 'cmp "$work/original.cmdline" "$work/signed.cmdline"' in preparer
    assert 'purpose: "harness_compatibility_positive_control_only"' in preparer
    assert "private_key_persisted: false" in preparer
    assert "manufacturer_trusted: false" in preparer
    assert "policy_trusted: false" in preparer
    assert "production_trusted: false" in preparer


def test_tamper_negative_changes_exact_signed_uki_in_throwaway_overlay():
    tamper = (ROOT / "scripts/tamper_fedora_sealed_uki.sh").read_text()
    workflow = (
        ROOT / ".github/workflows/fedora-sealed-uki-positive-control.yml"
    ).read_text()
    assert '[[ "$original_sha256" == "$expected_sha256" ]]' in tamper
    assert "scripts/mutate_pe_cmdline.py" in tamper
    assert "certificate_table_preserved" in tamper
    assert "embedded_cmdline_bytes_without_resigning" in tamper
    assert "fedora-output/upstream-tamper.qcow2" in workflow
    assert "[[ $rc -eq 80 ]]" in workflow
    assert ".firmware_rejected = true" in workflow
    assert "--tamper fedora-output/upstream-tamper/tamper-admission.json" in workflow


@pytest.mark.parametrize(
    "script",
    [
        "scripts/prepare_fedora_sealed_compat_control.sh",
        "scripts/tamper_fedora_sealed_uki.sh",
    ],
)
def test_disk_mutators_retry_only_the_post_disconnect_lock_race(script):
    source = (ROOT / script).read_text()
    assert "sudo udevadm settle" in source
    assert "for _ in $(seq 1 50)" in source
    assert 'Failed to get shared "write" lock' in source
    assert "qcow2 write lock did not clear after NBD disconnect" in source


def test_cli_enforcement_writes_failure_receipt(tmp_path):
    static = static_evidence()
    guest = guest_evidence()
    guest["stub_info"] = None
    for name, value in (("static", static), ("guest", guest), ("provenance", provenance())):
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    output = tmp_path / "result.json"
    assert validator.main is not None
    result = validator.evaluate(
        static, guest, provenance(), compatibility_evidence(),
        certificate_strip_evidence(), tamper_evidence()
    )
    output.write_text(json.dumps(result))
    assert result["passed"] is False
    assert "systemd_stub_observed" in result["failed_gates"]

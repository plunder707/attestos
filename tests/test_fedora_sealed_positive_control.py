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
            "signature_verified": True,
            "tampered_cmdline_signature_rejected": True,
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


def test_positive_control_requires_every_join():
    result = validator.evaluate(static_evidence(), guest_evidence(), provenance())
    assert result["passed"] is True
    assert all(result["gates"].values())
    assert result["authority"] == "harness_positive_control_only"
    assert result["policy_trusted"] is False


def test_zero_pcr11_fails_closed():
    guest = guest_evidence()
    guest["pcr_values"]["sha256"]["11"] = "0" * 64
    result = validator.evaluate(static_evidence(), guest, provenance())
    assert result["passed"] is False
    assert result["gates"]["pcr11_nonzero"] is False


def test_installer_version_cannot_drift_from_provenance():
    evidence = provenance()
    evidence["installer_reference"] = INSTALLER.replace("e" * 64, "f" * 64)
    result = validator.evaluate(static_evidence(), guest_evidence(), evidence)
    assert result["passed"] is False
    assert result["gates"]["immutable_installer_join"] is False


def test_unloaded_decoy_cannot_satisfy_identity_join():
    guest = guest_evidence()
    guest["loaded_uki"]["sha256"] = "c" * 64
    result = validator.evaluate(static_evidence(), guest, provenance())
    assert result["passed"] is False
    assert result["gates"]["loaded_uki_hash_matches_static"] is False


def test_wrong_loaded_path_fails_even_when_hash_matches():
    guest = guest_evidence()
    guest["stub_image_identifier"] = "\\EFI\\Linux\\decoy.efi"
    result = validator.evaluate(static_evidence(), guest, provenance())
    assert result["passed"] is False
    assert result["gates"]["loaded_uki_path_matches_static"] is False


@pytest.mark.parametrize(
    "key", ["manufacturer_trusted", "policy_trusted", "production_trusted"]
)
def test_guest_cannot_promote_a_trust_stage(key):
    guest = guest_evidence()
    guest[key] = True
    with pytest.raises(validator.EvidenceError, match=key):
        validator.evaluate(static_evidence(), guest, provenance())


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


def test_cli_enforcement_writes_failure_receipt(tmp_path):
    static = static_evidence()
    guest = guest_evidence()
    guest["stub_info"] = None
    for name, value in (("static", static), ("guest", guest), ("provenance", provenance())):
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    output = tmp_path / "result.json"
    assert validator.main is not None
    result = validator.evaluate(static, guest, provenance())
    output.write_text(json.dumps(result))
    assert result["passed"] is False
    assert "systemd_stub_observed" in result["failed_gates"]

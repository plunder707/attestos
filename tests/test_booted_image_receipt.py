import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_booted_image_receipt.py"
PROBE = ROOT / "system_files" / "usr" / "libexec" / "attestos-boot-evidence-canary"
RUNNER = ROOT / "scripts" / "run_booted_image_canary.sh"
UNIT = ROOT / "system_files" / "usr" / "lib" / "systemd" / "system" / "attestos-boot-evidence-canary.service"
SPEC = importlib.util.spec_from_file_location("boot_receipt", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def load_probe():
    loader = importlib.machinery.SourceFileLoader("boot_probe", str(PROBE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec and spec.loader
    probe = importlib.util.module_from_spec(spec)
    loader.exec_module(probe)
    return probe


def guest_receipt() -> dict:
    digest = "a" * 64
    return {
        "format": "attestos.boot_guest_evidence/v1",
        "success": True,
        "emulated": True,
        "tpm": {
            "device_available": True,
            "provision_service_active": True,
            "ek_handle_available": True,
            "ak_handle_available": True,
            "required_state_available": True,
            "quote_self_check_valid": True,
        },
        "pcr_values": {"sha256": {str(pcr): digest for pcr in (7, 11, 12, 15)}},
        "event_logs": {
            "tcg_firmware": {"available": True, "size": 128, "sha256": digest},
            "systemd_tpm2_measure": {"available": False, "size": 0, "sha256": None},
        },
        "deployment": {"available": True, "image_reference": "example", "image_digest": digest},
        "boot": {
            "efi_available": True,
            "stub_info_variable_present": False,
            "uki_file_count": 0,
            "cmdline_sha256": digest,
            "lockdown_confidentiality_present": False,
            "module_sig_enforce_present": False,
        },
        "errors": [],
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }


def test_extracts_exactly_one_valid_guest_marker():
    guest = guest_receipt()
    serial = "firmware noise\n" + module.MARKER + json.dumps(guest) + "\n"
    assert module.extract_guest(serial) == guest


@pytest.mark.parametrize("field", [
    "manufacturer_trusted", "policy_trusted", "production_trusted",
])
def test_trust_flags_fail_closed(field):
    guest = guest_receipt()
    guest[field] = True
    with pytest.raises(module.ReceiptError, match=field):
        module.validate_guest(guest)


def test_missing_or_extra_pcr_fails_closed():
    guest = guest_receipt()
    guest["pcr_values"]["sha256"].pop("15")
    with pytest.raises(module.ReceiptError, match="exactly"):
        module.validate_guest(guest)


def test_failed_guest_cannot_be_wrapped_as_success(tmp_path):
    guest = guest_receipt()
    guest["success"] = False
    guest["errors"] = ["probe failed"]
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"disk")
    with pytest.raises(module.ReceiptError, match="probe failed"):
        module.build_receipt(guest, disk, "commit", "base", "builder")


def test_host_receipt_preserves_non_authority(tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"disk")
    receipt = module.build_receipt(guest_receipt(), disk, "commit", "base", "builder")
    assert receipt["success"] is True
    assert receipt["execution"]["accelerator"] == "tcg"
    assert receipt["execution"]["network"] == "none"
    assert receipt["manufacturer_trusted"] is False
    assert receipt["policy_trusted"] is False
    assert receipt["production_trusted"] is False


def test_qemu_runner_allows_firmware_boot_option_reset():
    runner = RUNNER.read_text(encoding="utf-8")
    assert "-no-reboot" not in runner
    assert "-nic none" in runner
    assert "accel=tcg" in runner
    assert "guest_progress" in runner


def test_guest_probe_runs_after_provision_before_multi_user():
    unit = UNIT.read_text(encoding="utf-8")
    assert "After=attestos-provision.service\n" in unit
    assert "Before=multi-user.target\n" in unit
    assert "After=attestos-provision.service multi-user.target" not in unit


def test_agent_failure_prefers_structured_diagnostic(monkeypatch):
    probe = load_probe()

    class Failed:
        returncode = 1
        stdout = '{"error":"internal_error:TypeError:bad value"}'
        stderr = "Traceback that would otherwise hide the exception"

    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: Failed())
    with pytest.raises(RuntimeError, match="internal_error:TypeError:bad value"):
        probe.invoke_agent({"kind": "quote_challenge"})


def test_agent_failure_uses_traceback_tail_when_stdout_is_empty(monkeypatch):
    probe = load_probe()

    class Failed:
        returncode = 1
        stdout = ""
        stderr = "Traceback header\nTypeError: guest-only incompatibility"

    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: Failed())
    with pytest.raises(RuntimeError, match="TypeError: guest-only incompatibility"):
        probe.invoke_agent({"kind": "quote_challenge"})

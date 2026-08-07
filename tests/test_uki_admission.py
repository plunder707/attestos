import importlib.util
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_uki_admission.py"
SPEC = importlib.util.spec_from_file_location("uki_admission", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_normalize_digest_accepts_tpm2_eventlog_yaml_integer():
    digest = "186c5a18e20524ef9ede9f5781abdf84bbbc6f56dfeb8affe8272ee7f1088283"
    assert module.normalize_digest(int(digest, 16)) == digest


def test_normalize_digest_rejects_non_hex_and_boolean_values():
    assert module.normalize_digest("not-a-digest") is None
    assert module.normalize_digest(True) is None


def test_replay_firmware_pcr7_accepts_tpm2_eventlog_yaml_integer(monkeypatch):
    digest = "186c5a18e20524ef9ede9f5781abdf84bbbc6f56dfeb8affe8272ee7f1088283"
    output = f"pcrs:\n  sha256:\n    7  : 0x{digest}\n"
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, output, ""))
    guest = {
        "event_log_payloads": {"tcg_firmware": "AA=="},
        "pcr_values": {"sha256": {"7": digest}},
    }
    result = module.replay_firmware_pcr7(guest)
    assert result["matches_quote"] is True
    assert result["replayed_pcr7"] == digest
    assert result["reason"] == "ok"


def fixtures():
    digest = "a" * 64
    guest_uki = {
        "sha256": digest,
        "matches_loader_identifier": True,
        "embedded_cmdline": {
            "lockdown_confidentiality_present": True,
            "module_sig_enforce_present": True,
        },
    }
    receipt = {
        "guest": {
            "pcr_values": {"sha256": {"7": "b" * 64, "11": "c" * 64}},
            "event_log_payloads": {
                "tcg_firmware": "AA==",
                "systemd_tpm2_measure": "Hg==",
            },
            "boot": {
                "secure_boot_enabled": True,
                "stub_info_variable_present": True,
                "stub_pcr_kernel_image_variable_present": True,
                "lockdown_confidentiality_present": True,
                "module_sig_enforce_present": True,
                "uki_files": [guest_uki],
            },
        },
    }
    static = {
        "signature_verified": True,
        "tampered_uki_rejected": True,
        "candidates": [{
            "sha256": digest,
            "verified_certificate_sha256": "e" * 64,
            "tampered_cmdline_signature_rejected": True,
            "embedded_cmdline": {
                "sha256": None,
                "lockdown_confidentiality_present": True,
                "module_sig_enforce_present": True,
            },
        }],
    }
    static["candidates"][0]["embedded_cmdline"]["sha256"] = "f" * 64
    guest_uki["embedded_cmdline"]["sha256"] = "f" * 64
    return receipt, static


def test_unimplemented_replay_and_update_gates_hold_admission(monkeypatch):
    receipt, static = fixtures()
    monkeypatch.setattr(module, "replay_firmware_pcr7", lambda _guest: {
        "available": True, "matches_quote": True, "reason": "ok",
    })
    result = module.evaluate(receipt, static)
    assert result["admitted"] is False
    assert result["gates"]["systemd_event_log_replayed"] is False
    assert result["gates"]["update_rollback_invariants"] is False
    assert result["policy_trusted"] is False


def test_missing_secure_boot_fails_independently(monkeypatch):
    receipt, static = fixtures()
    receipt["guest"]["boot"]["secure_boot_enabled"] = False
    monkeypatch.setattr(module, "replay_firmware_pcr7", lambda _guest: {
        "available": True, "matches_quote": True, "reason": "ok",
    })
    result = module.evaluate(receipt, static)
    assert result["gates"]["secure_boot_enabled"] is False


def test_loaded_uki_must_match_static_inspection(monkeypatch):
    receipt, static = fixtures()
    static["candidates"][0]["sha256"] = "d" * 64
    monkeypatch.setattr(module, "replay_firmware_pcr7", lambda _guest: {
        "available": True, "matches_quote": True, "reason": "ok",
    })
    result = module.evaluate(receipt, static)
    assert result["gates"]["loaded_uki_matches_one_static_candidate"] is False


def test_unloaded_signed_decoy_cannot_authorize_loaded_uki(monkeypatch):
    receipt, static = fixtures()
    loaded_hash = receipt["guest"]["boot"]["uki_files"][0]["sha256"]
    static["candidates"] = [{
        "sha256": loaded_hash,
        "verified_certificate_sha256": None,
        "tampered_cmdline_signature_rejected": False,
        "embedded_cmdline": {
            "sha256": "f" * 64,
            "lockdown_confidentiality_present": True,
            "module_sig_enforce_present": True,
        },
    }, {
        "sha256": "9" * 64,
        "verified_certificate_sha256": "e" * 64,
        "tampered_cmdline_signature_rejected": True,
        "embedded_cmdline": {
            "sha256": "f" * 64,
            "lockdown_confidentiality_present": True,
            "module_sig_enforce_present": True,
        },
    }]
    monkeypatch.setattr(module, "replay_firmware_pcr7", lambda _guest: {
        "available": True, "matches_quote": True, "reason": "ok",
    })
    result = module.evaluate(receipt, static)
    assert result["gates"]["loaded_uki_matches_one_static_candidate"] is True
    assert result["gates"]["loaded_uki_pe_signature_verified"] is False
    assert result["gates"]["loaded_uki_tamper_rejected"] is False


def test_unloaded_uki_is_reported_as_candidate_not_loaded(monkeypatch):
    receipt, static = fixtures()
    candidate = receipt["guest"]["boot"]["uki_files"][0]
    candidate["matches_loader_identifier"] = False
    monkeypatch.setattr(module, "replay_firmware_pcr7", lambda _guest: {
        "available": True, "matches_quote": True, "reason": "ok",
    })
    result = module.evaluate(receipt, static)
    assert result["guest_uki_candidate_hashes"] == [candidate["sha256"]]
    assert result["loaded_uki_hashes"] == []
    assert result["loaded_uki_count"] == 0
    assert "boot_uki_hashes" not in result

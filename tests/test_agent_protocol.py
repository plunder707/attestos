from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).parents[1]
AGENT_PATH = ROOT / "system_files/usr/bin/attestos-agent"


def load_agent():
    loader = importlib.machinery.SourceFileLoader("attestos_agent", str(AGENT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def agent(tmp_path, monkeypatch):
    module = load_agent()
    state = tmp_path / "state"
    state.mkdir()
    (state / "ak.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nak mechanics\n-----END PUBLIC KEY-----\n")
    (state / "ak.name").write_bytes(b"ak-name")
    (state / "ek.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nek mechanics\n-----END PUBLIC KEY-----\n")
    monkeypatch.setattr(module, "STATE", state)
    monkeypatch.setattr(module, "AK_PUB", state / "ak.pem")
    monkeypatch.setattr(module, "AK_NAME", state / "ak.name")
    monkeypatch.setattr(module, "EK_PUB", state / "ek.pem")
    monkeypatch.setattr(module, "EK_CERT", state / "ek.crt")
    monkeypatch.setattr(module, "FIRMWARE_LOG", tmp_path / "firmware.log")
    monkeypatch.setattr(module, "SYSTEMD_LOG", tmp_path / "systemd.log")
    return module


def schema():
    return json.loads((ROOT / "protocol/v1/attestation.schema.json").read_text())


def test_identity_is_schema_valid_and_does_not_mislabel_ek_certificate(agent):
    message = {
        "protocol": agent.PROTOCOL,
        "kind": "identity_challenge",
        "request_id": "a" * 32,
        "device_class": "emulator",
    }
    response = agent.identity(message)
    jsonschema.validate(response, schema())
    assert response["ek"]["certificate_der_b64"] is None
    assert "certificate" not in response["ak"]


def test_identity_rejects_unknown_fields(agent):
    message = {
        "protocol": agent.PROTOCOL,
        "kind": "identity_challenge",
        "request_id": "a" * 32,
        "device_class": "emulator",
        "trust_me": True,
    }
    with pytest.raises(agent.AgentError, match="extra"):
        agent.identity(message)


def test_activate_credential_returns_only_recovered_secret(agent, monkeypatch):
    def fake_run(*args, **kwargs):
        if args[0] == "tpm2_activatecredential":
            output = Path(args[args.index("-o") + 1])
            output.write_bytes(b"s" * 32)
        return b""

    monkeypatch.setattr(agent, "run", fake_run)
    response = agent.activate({
        "protocol": agent.PROTOCOL,
        "kind": "activation_challenge",
        "request_id": "b" * 32,
        "enrollment_id": "c" * 32,
        "credential_blob_b64": agent.b64(b"credential"),
    })
    jsonschema.validate(response, schema())
    assert response["secret_b64"] == agent.b64(b"s" * 32)


def test_quote_captures_pcrs_in_same_tpm_command(agent, monkeypatch, tmp_path):
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)
        if args[0] == "tpm2_quote":
            Path(args[args.index("-m") + 1]).write_bytes(b"message")
            Path(args[args.index("-s") + 1]).write_bytes(b"signature")
            Path(args[args.index("-o") + 1]).write_bytes(b"serialized-pcrs")
            return b""
        if args[:3] == ("bootc", "status", "--json"):
            return json.dumps({
                "status": {
                    "booted": {
                        "image": {
                            "image": {"image": "ghcr.io/example/image:stable"},
                            "imageDigest": "sha256:" + "d" * 64,
                        },
                        "ostree": {"checksum": "e" * 64},
                    }
                }
            }).encode()
        raise AssertionError(args)

    monkeypatch.setattr(agent, "run", fake_run)
    (tmp_path / "firmware.log").write_bytes(b"firmware-events")
    response = agent.quote({
        "protocol": agent.PROTOCOL,
        "kind": "quote_challenge",
        "request_id": "d" * 32,
        "enrollment_id": "e" * 32,
        "qualifying_data_b64": agent.b64(b"q" * 32),
        "binding_mode": "nonce_only",
    })
    jsonschema.validate(response, schema())
    quote_commands = [c for c in commands if c[0] == "tpm2_quote"]
    assert len(quote_commands) == 1
    assert "-o" in quote_commands[0]
    assert not any(c[0] == "tpm2_pcrread" for c in commands)
    assert response["deployment_claim"]["image_digest"] == "sha256:" + "d" * 64
    assert response["event_logs"][0]["source"] == "tcg_firmware"


def test_quote_refuses_caller_supplied_channel_binding(agent):
    message = {
        "protocol": agent.PROTOCOL,
        "kind": "quote_challenge",
        "request_id": "d" * 32,
        "enrollment_id": "e" * 32,
        "qualifying_data_b64": agent.b64(b"q" * 32),
        "binding_mode": "nonce_only",
        "channel_id": "caller-controlled",
    }
    with pytest.raises(agent.AgentError, match="extra"):
        agent.quote(message)


def test_provisioner_repairs_state_and_uses_distinct_ek_certificate():
    script = (ROOT / "system_files/usr/bin/attestos-provision").read_text()
    unit = (ROOT / "system_files/usr/lib/systemd/system/attestos-provision.service").read_text()
    assert "EK_HANDLE=0x81010001" in script
    assert "AK_HANDLE=0x81010002" in script
    assert '"$STATE/ek.crt"' in script
    assert "ak.crt" not in script
    assert "ConditionPathExists=!/var/lib/attestos/ak.pem" not in unit
    assert "ConditionPathExists=/dev/tpmrm0" in unit


def test_vendored_protocol_is_byte_identical_when_source_checkout_exists():
    source = Path("/home/plunder/workspace/attested-gaming/protocol/v1/attestation.schema.json")
    if not source.exists():
        pytest.skip("authoritative protocol checkout is not present")
    assert (ROOT / "protocol/v1/attestation.schema.json").read_bytes() == source.read_bytes()

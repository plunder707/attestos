#!/usr/bin/env python3
"""Read bounded UKI and PCR evidence from an unchanged sealed guest."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path


FORMAT = "attestos.fedora_sealed_guest/v1"
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
GLOBAL_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
OUTPUT = Path("/mnt/guest-evidence.json")
ZERO_SHA256 = "0" * 64


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_efivar(name: str, guid: str = LOADER_GUID) -> bytes | None:
    path = Path("/sys/firmware/efi/efivars") / f"{name}-{guid}"
    if not path.is_file():
        return None
    data = path.read_bytes()
    return data[4:] if len(data) >= 4 else None


def read_efivar_text(name: str) -> str | None:
    data = read_efivar(name)
    if data is None:
        return None
    try:
        return data.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None


def read_secure_boot() -> bool | None:
    data = read_efivar("SecureBoot", GLOBAL_GUID)
    return None if not data else data[0] == 1


def pcr_read_command(pcr: int) -> bytes:
    if not 0 <= pcr <= 23:
        raise ValueError("PCR index is outside the SHA-256 PC Client bank")
    bitmap = bytearray(3)
    bitmap[pcr // 8] = 1 << (pcr % 8)
    body = struct.pack(">IHB", 1, 0x000B, len(bitmap)) + bytes(bitmap)
    return struct.pack(">HII", 0x8001, 10 + len(body), 0x0000017E) + body


def parse_pcr_read_response(response: bytes) -> str:
    if len(response) < 10:
        raise RuntimeError("TPM response is shorter than its header")
    _tag, size, rc = struct.unpack_from(">HII", response, 0)
    if rc != 0:
        raise RuntimeError(f"TPM2_PCR_Read failed with response code 0x{rc:08x}")
    if size != len(response):
        raise RuntimeError("TPM response size does not match its header")

    offset = 10
    if offset + 8 > len(response):
        raise RuntimeError("TPM response has no selection list")
    offset += 4  # pcrUpdateCounter
    selection_count = struct.unpack_from(">I", response, offset)[0]
    offset += 4
    if selection_count != 1:
        raise RuntimeError(f"expected one PCR selection, received {selection_count}")
    if offset + 3 > len(response):
        raise RuntimeError("TPM selection is truncated")
    algorithm, bitmap_size = struct.unpack_from(">HB", response, offset)
    offset += 3
    if algorithm != 0x000B or bitmap_size != 3:
        raise RuntimeError("TPM did not return the requested SHA-256 selection")
    offset += bitmap_size
    if offset + 4 > len(response):
        raise RuntimeError("TPM digest list is truncated")
    digest_count = struct.unpack_from(">I", response, offset)[0]
    offset += 4
    if digest_count != 1 or offset + 2 > len(response):
        raise RuntimeError(f"expected one PCR digest, received {digest_count}")
    digest_size = struct.unpack_from(">H", response, offset)[0]
    offset += 2
    digest = response[offset:offset + digest_size]
    if digest_size != 32 or len(digest) != 32 or offset + digest_size != len(response):
        raise RuntimeError("TPM returned a non-canonical SHA-256 digest")
    return digest.hex()


def read_pcr11() -> str:
    device = next((path for path in (Path("/dev/tpmrm0"), Path("/dev/tpm0")) if path.exists()), None)
    if device is None:
        raise RuntimeError("guest exposes no TPM character device")
    fd = os.open(device, os.O_RDWR)
    try:
        os.write(fd, pcr_read_command(11))
        response = os.read(fd, 4096)
    finally:
        os.close(fd)
    return parse_pcr_read_response(response)


def locate_loaded_uki(identifier: str) -> Path:
    relative = identifier.replace("\\", "/").lstrip("/")
    candidates = [root / relative for root in (Path("/boot"), Path("/boot/efi"), Path("/efi"))]
    matches = [path for path in candidates if path.is_file()]
    if len(matches) != 1:
        raise RuntimeError(
            f"StubImageIdentifier mapped to {len(matches)} files: {identifier!r}"
        )
    return matches[0]


def collect() -> dict:
    loader_info = read_efivar_text("LoaderInfo")
    loader_entry = read_efivar_text("LoaderEntrySelected")
    stub_info = read_efivar_text("StubInfo")
    stub_identifier = read_efivar_text("StubImageIdentifier")
    stub_pcr = read_efivar_text("StubPcrKernelImage")
    if not stub_identifier:
        raise RuntimeError("systemd-stub did not expose StubImageIdentifier")
    loaded_uki = locate_loaded_uki(stub_identifier)
    pcr11 = read_pcr11()

    evidence = {
        "format": FORMAT,
        "success": True,
        "secure_boot_enabled": read_secure_boot(),
        "loader_info": loader_info,
        "loader_entry_selected": loader_entry,
        "stub_info": stub_info,
        "stub_image_identifier": stub_identifier,
        "stub_pcr_kernel_image": stub_pcr,
        "loaded_uki": {
            "path": str(loaded_uki),
            "uefi_path": "\\EFI\\" + str(loaded_uki).split("/EFI/", 1)[-1].replace("/", "\\")
            if "/EFI/" in str(loaded_uki) else stub_identifier,
            "sha256": sha256(loaded_uki),
            "size_bytes": loaded_uki.stat().st_size,
        },
        "pcr_values": {"sha256": {"11": pcr11}},
        "cmdline_sha256": hashlib.sha256(
            Path("/proc/cmdline").read_bytes().rstrip(b"\n")
        ).hexdigest(),
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }
    evidence["success"] = all((
        isinstance(loader_info, str) and loader_info.startswith("systemd-boot "),
        isinstance(stub_info, str) and stub_info.startswith("systemd-stub "),
        stub_pcr == "11",
        evidence["secure_boot_enabled"] is True,
        pcr11 != ZERO_SHA256,
    ))
    return evidence


def write_result() -> None:
    try:
        result = collect()
    except Exception as exc:  # The host must receive a bounded failure receipt.
        result = {
            "format": FORMAT,
            "success": False,
            "error": f"{type(exc).__name__}: {exc}"[:1000],
            "manufacturer_trusted": False,
            "policy_trusted": False,
            "production_trusted": False,
        }
    temporary = OUTPUT.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    os.sync()
    temporary.replace(OUTPUT)
    os.sync()


if __name__ == "__main__":
    try:
        write_result()
    finally:
        subprocess.run(["/usr/bin/systemctl", "poweroff", "-i"], check=False)

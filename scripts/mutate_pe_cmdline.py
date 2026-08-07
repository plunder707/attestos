#!/usr/bin/env python3
"""Mutate a PE .cmdline section without rewriting its certificate table."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


FORMAT = "attestos.pe_cmdline_mutation/v1"
DEFAULT_SUFFIX = b" attestos_tamper=1"


class PEError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutate_cmdline(
    data: bytes,
    suffix: bytes = DEFAULT_SUFFIX,
    *,
    require_certificate_table: bool = True,
) -> tuple[bytes, dict]:
    if not suffix or b"\0" in suffix:
        raise PEError("mutation suffix must be non-empty and contain no NUL")
    if len(data) < 0x40:
        raise PEError("input is too small for a DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise PEError("input has no valid PE signature")

    coff_offset = pe_offset + 4
    section_count = struct.unpack_from("<H", data, coff_offset + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise PEError("optional header extends beyond input")

    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        directory_offset = optional_offset + 96
        directory_count_offset = optional_offset + 92
    elif magic == 0x20B:
        directory_offset = optional_offset + 112
        directory_count_offset = optional_offset + 108
    else:
        raise PEError(f"unsupported optional-header magic: 0x{magic:04x}")
    directory_count = struct.unpack_from("<I", data, directory_count_offset)[0]
    if directory_count <= 4:
        raise PEError("optional header has no certificate-table directory")
    certificate_directory = directory_offset + 4 * 8
    if certificate_directory + 8 > optional_end:
        raise PEError("certificate-table directory exceeds optional header")
    certificate_offset, certificate_size = struct.unpack_from(
        "<II", data, certificate_directory
    )
    certificate_end = certificate_offset + certificate_size
    certificate_table_present = certificate_offset != 0 and certificate_size != 0
    if require_certificate_table and not certificate_table_present:
        raise PEError("input does not contain a complete certificate table")
    if certificate_table_present and certificate_end > len(data):
        raise PEError("certificate table extends beyond input")

    section_table_end = optional_end + section_count * 40
    if section_table_end > len(data):
        raise PEError("section table extends beyond input")
    cmdline_sections: list[tuple[int, int]] = []
    max_section_raw_end = 0
    for index in range(section_count):
        section_offset = optional_end + index * 40
        name = data[section_offset:section_offset + 8].rstrip(b"\0")
        raw_size, raw_offset = struct.unpack_from("<II", data, section_offset + 16)
        raw_end = raw_offset + raw_size
        if raw_size and (raw_offset == 0 or raw_end > len(data)):
            raise PEError(f"section {index} raw data extends beyond input")
        max_section_raw_end = max(max_section_raw_end, raw_end)
        if name == b".cmdline":
            cmdline_sections.append((raw_offset, raw_size))
    if len(cmdline_sections) != 1:
        raise PEError(f"expected exactly one .cmdline section, found {len(cmdline_sections)}")
    if certificate_table_present and certificate_offset < max_section_raw_end:
        raise PEError("certificate table overlaps section raw data")

    raw_offset, raw_size = cmdline_sections[0]
    original_raw = data[raw_offset:raw_offset + raw_size]
    original_cmdline = original_raw.rstrip(b"\0")
    if not original_cmdline:
        raise PEError("input has an empty .cmdline section")
    if suffix in original_cmdline:
        raise PEError("input .cmdline already contains the mutation suffix")
    tampered_cmdline = original_cmdline + suffix
    encoded = tampered_cmdline + b"\0"
    if len(encoded) > raw_size:
        raise PEError("mutated command line exceeds the existing section")

    certificate_before = (
        data[certificate_offset:certificate_end] if certificate_table_present else None
    )
    outside_cmdline_before = data[:raw_offset] + data[raw_offset + raw_size:]
    mutated = bytearray(data)
    mutated[raw_offset:raw_offset + raw_size] = encoded.ljust(raw_size, b"\0")
    certificate_after = (
        bytes(mutated[certificate_offset:certificate_end])
        if certificate_table_present else None
    )
    if certificate_table_present and certificate_after != certificate_before:
        raise PEError("command-line mutation changed certificate-table bytes")
    if len(mutated) != len(data):
        raise PEError("command-line mutation changed file size")
    outside_cmdline_after = bytes(mutated[:raw_offset] + mutated[raw_offset + raw_size:])
    if outside_cmdline_after != outside_cmdline_before:
        raise PEError("command-line mutation changed bytes outside its section")

    result = bytes(mutated)
    if result == data:
        raise PEError("command-line mutation did not change the input")
    return result, {
        "cmdline_raw_offset": raw_offset,
        "cmdline_raw_size": raw_size,
        "certificate_table_offset": certificate_offset,
        "certificate_table_size": certificate_size,
        "certificate_table_present": certificate_table_present,
        "certificate_table_sha256_before": (
            sha256(certificate_before) if certificate_before is not None else None
        ),
        "certificate_table_sha256_after": (
            sha256(certificate_after) if certificate_after is not None else None
        ),
        "certificate_table_preserved": (
            certificate_after == certificate_before if certificate_table_present else None
        ),
        "outside_cmdline_sha256_before": sha256(outside_cmdline_before),
        "outside_cmdline_sha256_after": sha256(outside_cmdline_after),
        "only_cmdline_section_changed": True,
        "file_size_unchanged": True,
        "original_cmdline_sha256": sha256(original_cmdline),
        "tampered_cmdline_sha256": sha256(tampered_cmdline),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--allow-missing-certificate-table", action="store_true")
    args = parser.parse_args()

    source = args.input.read_bytes()
    mutated, details = mutate_cmdline(
        source,
        require_certificate_table=not args.allow_missing_certificate_table,
    )
    args.output.write_bytes(mutated)
    receipt = {
        "format": FORMAT,
        "mutation": "embedded_cmdline_bytes_without_resigning",
        "original_uki_sha256": sha256(source),
        "tampered_uki_sha256": sha256(mutated),
        "file_size_bytes": len(source),
        **details,
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "original_uki_sha256": receipt["original_uki_sha256"],
        "tampered_uki_sha256": receipt["tampered_uki_sha256"],
        "certificate_table_preserved": receipt["certificate_table_preserved"],
        "only_cmdline_section_changed": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Remove a terminal PE certificate table under a strict, auditable contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


FORMAT = "attestos.pe_certificate_strip/v1"
MAX_TERMINAL_PADDING = 4096


class PEError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_certificate_table(data: bytes) -> tuple[bytes, dict]:
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
        pe_kind = "PE32"
    elif magic == 0x20B:
        directory_offset = optional_offset + 112
        directory_count_offset = optional_offset + 108
        pe_kind = "PE32+"
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
    if certificate_offset == 0 or certificate_size == 0:
        raise PEError("input has no certificate table to remove")
    if certificate_offset % 8 != 0 or certificate_size % 8 != 0:
        raise PEError("certificate table is not 8-byte aligned")

    section_table_end = optional_end + section_count * 40
    if section_table_end > len(data):
        raise PEError("section table extends beyond input")
    max_section_raw_end = 0
    for index in range(section_count):
        section_offset = optional_end + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, section_offset + 16)
        if raw_size == 0:
            continue
        raw_end = raw_offset + raw_size
        if raw_offset == 0 or raw_end > len(data):
            raise PEError(f"section {index} raw data extends beyond input")
        max_section_raw_end = max(max_section_raw_end, raw_end)
    if certificate_offset < max_section_raw_end:
        raise PEError("certificate table overlaps section raw data")

    certificate_end = certificate_offset + certificate_size
    if certificate_end > len(data):
        missing = certificate_end - len(data)
        last_length = None
        last_padded_end = None
        last_payload_end = None
        cursor = certificate_offset
        while cursor + 8 <= len(data):
            length = struct.unpack_from("<I", data, cursor)[0]
            if length < 8:
                break
            padded_end = cursor + ((length + 7) & ~7)
            payload_end = cursor + length
            last_length = length
            last_padded_end = padded_end
            last_payload_end = payload_end
            if padded_end >= certificate_end:
                break
            cursor = padded_end
        possible_omitted_alignment = (
            0 < missing <= 7 and
            last_payload_end == len(data) and
            last_padded_end == certificate_end
        )
        raise PEError(
            "certificate table extends beyond input: "
            f"offset={certificate_offset} size={certificate_size} "
            f"declared_end={certificate_end} file_size={len(data)} "
            f"missing={missing} last_length={last_length} "
            f"last_payload_end={last_payload_end} "
            f"last_padded_end={last_padded_end} "
            f"possible_omitted_alignment={possible_omitted_alignment}"
        )
    terminal_padding = data[certificate_end:]
    if terminal_padding and (
        len(terminal_padding) > MAX_TERMINAL_PADDING or any(terminal_padding)
    ):
        raise PEError(
            "certificate table has an unexplained trailing overlay: "
            f"size={len(terminal_padding)} "
            f"sha256={sha256(terminal_padding)} "
            f"all_zero={not any(terminal_padding)}"
        )

    entries: list[dict] = []
    cursor = certificate_offset
    while cursor < certificate_end:
        if cursor + 8 > certificate_end:
            raise PEError("truncated WIN_CERTIFICATE header")
        length, revision, certificate_type = struct.unpack_from("<IHH", data, cursor)
        if length < 8:
            raise PEError("WIN_CERTIFICATE length is smaller than its header")
        padded_length = (length + 7) & ~7
        if cursor + padded_length > certificate_end:
            raise PEError("WIN_CERTIFICATE extends beyond certificate table")
        entries.append({
            "offset": cursor,
            "length": length,
            "padded_length": padded_length,
            "revision": revision,
            "certificate_type": certificate_type,
        })
        cursor += padded_length
    if cursor != certificate_end or not entries:
        raise PEError("certificate entries do not exactly fill the table")

    stripped = bytearray(data[:certificate_offset])
    struct.pack_into("<II", stripped, certificate_directory, 0, 0)
    return bytes(stripped), {
        "pe_kind": pe_kind,
        "pe_offset": pe_offset,
        "certificate_directory_offset": certificate_directory,
        "certificate_table_offset": certificate_offset,
        "certificate_table_size": certificate_size,
        "max_section_raw_end": max_section_raw_end,
        "terminal_padding_size_bytes": len(terminal_padding),
        "terminal_padding_all_zero": True,
        "certificate_count": len(entries),
        "certificates": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    source = args.input.read_bytes()
    stripped, details = strip_certificate_table(source)
    if source == stripped:
        raise PEError("certificate-table removal did not change the input")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(stripped)
    receipt = {
        "format": FORMAT,
        "input_sha256": sha256(source),
        "input_size_bytes": len(source),
        "output_sha256": sha256(stripped),
        "output_size_bytes": len(stripped),
        **details,
        "operation": "remove_terminal_pe_certificate_table",
        "manufacturer_trusted": False,
        "policy_trusted": False,
        "production_trusted": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "certificate_count": receipt["certificate_count"],
        "input_sha256": receipt["input_sha256"],
        "output_sha256": receipt["output_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

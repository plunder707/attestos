#!/usr/bin/env python3
"""Drive bounded pre-boot prompts and capture the headless guest display."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


class QMP:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb", buffering=0)
        self._read()
        self.execute("qmp_capabilities")

    def _read(self) -> dict:
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            message = json.loads(line)
            if "event" not in message:
                return message

    def execute(self, command: str, arguments: dict | None = None) -> dict:
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode() + b"\n")
        response = self._read()
        if "error" in response:
            raise RuntimeError(f"QMP {command} failed: {response['error']}")
        return response

    def sendkey(self, key: str) -> None:
        self.execute(
            "human-monitor-command",
            {"command-line": f"sendkey {key}"},
        )

    def type_text(self, value: str) -> None:
        if not value or not value.isascii() or not value.isalnum():
            raise ValueError("console input must be non-empty ASCII alphanumeric text")
        for character in value.lower():
            self.sendkey(character)
            time.sleep(0.025)
        self.sendkey("ret")

    def status(self) -> str:
        return str(self.execute("query-status")["return"]["status"])

    def screendump(self, path: Path) -> None:
        self.execute("screendump", {"filename": str(path)})


def wait_for_socket(path: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"QMP socket did not appear: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qmp", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--luks-passphrase-file", type=Path, required=True)
    parser.add_argument("--drive-seconds", type=int, default=960)
    parser.add_argument("--input-start", type=int, default=120)
    parser.add_argument("--input-interval", type=int, default=60)
    parser.add_argument("--screenshot-interval", type=int, default=120)
    args = parser.parse_args()

    wait_for_socket(args.qmp)
    qmp = QMP(args.qmp)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    luks_passphrase = args.luks_passphrase_file.read_text(encoding="ascii").strip()
    if not luks_passphrase or not luks_passphrase.isascii() or not luks_passphrase.isalnum():
        raise ValueError("LUKS passphrase contract must be ASCII alphanumeric text")
    started = time.monotonic()
    next_input = started + args.input_start
    next_screenshot = started + args.screenshot_interval
    deadline = started + args.drive_seconds
    input_attempt = 0
    screenshot_attempt = 0

    # Under TCG the LUKS prompt appears about two minutes after firmware starts
    # the 247 MiB UKI. Disk construction and console input share one explicit,
    # intentionally public canary passphrase contract. The installed probe is a
    # systemd unit; typing shell commands on an assumed tty would be a false
    # execution signal.
    while time.monotonic() < deadline:
        now = time.monotonic()
        time.sleep(max(0.0, min(next_input, next_screenshot, deadline) - now))
        elapsed = int(time.monotonic() - started)
        try:
            if time.monotonic() >= next_input:
                qmp.type_text(luks_passphrase)
                input_attempt += 1
                print(
                    f"luks_unlock_attempt={input_attempt} "
                    f"elapsed_seconds={elapsed} qemu_status={qmp.status()}",
                    flush=True,
                )
                next_input += args.input_interval
            if time.monotonic() >= next_screenshot:
                screenshot_attempt += 1
                screenshot = args.output_dir / f"screen-{elapsed:04d}s.ppm"
                try:
                    qmp.screendump(screenshot)
                    print(
                        f"console_screenshot={screenshot.name} "
                        f"bytes={screenshot.stat().st_size}",
                        flush=True,
                    )
                except RuntimeError as error:
                    print(
                        f"console_screenshot_error={type(error).__name__}",
                        flush=True,
                    )
                next_screenshot += args.screenshot_interval
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            print("console_driver_qmp_closed=true", flush=True)
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

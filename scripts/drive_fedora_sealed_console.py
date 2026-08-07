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
    parser.add_argument("--input-interval", type=int, default=10)
    parser.add_argument("--input-stop", type=int, default=210)
    parser.add_argument("--screenshot-interval", type=int, default=30)
    args = parser.parse_args()
    if not 0 <= args.input_start <= args.input_stop < args.drive_seconds:
        raise ValueError("console input window must be ordered within the drive bound")
    if args.input_interval <= 0 or args.screenshot_interval <= 0:
        raise ValueError("console intervals must be positive")

    wait_for_socket(args.qmp)
    qmp = QMP(args.qmp)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    luks_passphrase = args.luks_passphrase_file.read_text(encoding="ascii").strip()
    if not luks_passphrase or not luks_passphrase.isascii() or not luks_passphrase.isalnum():
        raise ValueError("LUKS passphrase contract must be ASCII alphanumeric text")
    started = time.monotonic()
    next_input = started + args.input_start
    input_deadline = started + args.input_stop
    next_screenshot = started + args.screenshot_interval
    deadline = started + args.drive_seconds
    input_attempt = 0
    screenshot_attempt = 0

    # Under TCG the LUKS prompt appears shortly after systemd-cryptsetup starts,
    # but the observed prompt-to-emergency window is shorter than one minute.
    # Send the shared public canary passphrase only across that bounded window;
    # continuing after it closes would type into dracut's emergency shell and
    # create a misleading execution signal.
    while time.monotonic() < deadline:
        now = time.monotonic()
        wake_at = min(next_screenshot, deadline)
        if next_input is not None:
            wake_at = min(wake_at, next_input)
        time.sleep(max(0.0, wake_at - now))
        elapsed = int(time.monotonic() - started)
        try:
            if next_input is not None and time.monotonic() >= next_input:
                qmp.type_text(luks_passphrase)
                input_attempt += 1
                print(
                    f"luks_unlock_attempt={input_attempt} "
                    f"elapsed_seconds={elapsed} qemu_status={qmp.status()}",
                    flush=True,
                )
                next_input += args.input_interval
                if next_input > input_deadline:
                    next_input = None
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

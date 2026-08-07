#!/usr/bin/env python3
"""Drive the upstream-enabled debug console without giving the guest a NIC."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


KEYS = {
    " ": "spc",
    "/": "slash",
    ".": "dot",
}


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
        for character in value:
            key = KEYS.get(character, character)
            if not (key.isalnum() or key in KEYS.values()):
                raise ValueError(f"unsupported console character: {character!r}")
            self.sendkey(key)
            time.sleep(0.025)
        self.sendkey("ret")


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
    parser.add_argument("--boot-wait", type=int, default=150)
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--attempt-interval", type=int, default=45)
    args = parser.parse_args()

    wait_for_socket(args.qmp)
    qmp = QMP(args.qmp)
    # An empty LUKS passphrase and the systemd-boot default both accept Return.
    for _ in range(max(1, args.boot_wait // 20)):
        time.sleep(20)
        qmp.sendkey("ret")

    for attempt in range(1, args.attempts + 1):
        qmp.sendkey("ctrl-alt-f9")
        time.sleep(3)
        qmp.type_text("mount /dev/vdb /mnt")
        time.sleep(2)
        qmp.type_text("python3 /mnt/fedora_sealed_guest_probe.py")
        print(f"console_probe_attempt={attempt}", flush=True)
        if attempt != args.attempts:
            time.sleep(args.attempt_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

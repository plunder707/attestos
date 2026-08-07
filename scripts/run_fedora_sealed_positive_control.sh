#!/usr/bin/env bash
# Boot the sealed disk with TCG+swtpm and retrieve evidence over a probe disk.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 DISK_QCOW2 OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath "$1")
output=$(realpath -m "$2")
source_vars=${ATTESTOS_FEDORA_OVMF_VARS:?missing converted Fedora OVMF variable store}
code=${ATTESTOS_FEDORA_OVMF_CODE:?missing OVMF code paired with variable template}
mkdir -p "$output"

for command in debugfs mke2fs qemu-img qemu-system-x86_64 swtpm; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

[[ -f "$code" ]] || { echo "paired Secure Boot OVMF code was not found" >&2; exit 1; }

state="$output/swtpm-state"
tpm_socket="$output/swtpm.sock"
qmp_socket="$output/qmp.sock"
serial="$output/serial.log"
vars="$output/OVMF_VARS.fd"
probe="$output/probe.raw"
probe_root="$output/probe-root"
mkdir -p "$state" "$probe_root"
cp "$source_vars" "$vars"
cp scripts/fedora_sealed_guest_probe.py "$probe_root/fedora_sealed_guest_probe.py"
truncate -s 64M "$probe"
mke2fs -q -t ext4 -F -d "$probe_root" "$probe"

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$state" \
    --ctrl "type=unixio,path=$tpm_socket" \
    --flags startup-clear \
    --daemon
for _ in $(seq 1 50); do
    [[ -S "$tpm_socket" ]] && break
    sleep 0.1
done
[[ -S "$tpm_socket" ]] || { echo "swtpm socket did not become ready" >&2; exit 1; }

cleanup() {
    set +e
    [[ -n "${driver_pid:-}" ]] && kill "$driver_pid" >/dev/null 2>&1
    [[ -n "${qemu_pid:-}" ]] && kill "$qemu_pid" >/dev/null 2>&1
    pkill -f "swtpm socket.*$tpm_socket" >/dev/null 2>&1
}
trap cleanup EXIT

set +e
timeout --signal=TERM 18m qemu-system-x86_64 \
    -machine q35,accel=tcg,usb=off,smm=on \
    -cpu max \
    -smp 2 \
    -m 4096 \
    -display none \
    -monitor none \
    -qmp "unix:$qmp_socket,server=on,wait=off" \
    -serial "file:$serial" \
    -nic none \
    -drive "if=pflash,format=raw,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,file=$vars" \
    -global driver=cfi.pflash01,property=secure,value=on \
    -chardev "socket,id=chrtpm,path=$tpm_socket" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -drive "if=none,id=osdisk,file=$disk,format=qcow2,cache=unsafe" \
    -device virtio-blk-pci,drive=osdisk,bootindex=1 \
    -drive "if=none,id=probe,file=$probe,format=raw,cache=unsafe" \
    -device virtio-blk-pci,drive=probe &
qemu_pid=$!

python3 scripts/drive_fedora_sealed_console.py \
    --qmp "$qmp_socket" \
    > "$output/console-driver.log" 2>&1 &
driver_pid=$!

while kill -0 "$qemu_pid" >/dev/null 2>&1; do
    sleep 30
    printf 'guest_progress serial_bytes=%s probe_attempts=%s\n' \
        "$(stat -c %s "$serial" 2>/dev/null || echo 0)" \
        "$(grep -c console_probe_attempt "$output/console-driver.log" 2>/dev/null || true)"
done
wait "$qemu_pid"
qemu_rc=$?
qemu_pid=""
kill "$driver_pid" >/dev/null 2>&1 || true
wait "$driver_pid" >/dev/null 2>&1 || true
driver_pid=""
set -e

if [[ $qemu_rc -ne 0 ]]; then
    echo "QEMU exited with status $qemu_rc" >&2
    tail -200 "$serial" >&2 || true
    tail -100 "$output/console-driver.log" >&2 || true
    exit "$qemu_rc"
fi

debugfs -R "dump /guest-evidence.json $output/guest-evidence.json" "$probe" \
    > "$output/debugfs.log" 2>&1 || {
        tail -100 "$output/console-driver.log" >&2 || true
        cat "$output/debugfs.log" >&2 || true
        exit 1
    }
test -s "$output/guest-evidence.json"
qemu-img check "$disk"

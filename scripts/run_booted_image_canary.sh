#!/usr/bin/env bash
# Boot a QCOW2 with OVMF + swtpm under TCG and validate its bounded receipt.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 DISK_QCOW2 OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath "$1")
output=$(realpath -m "$2")
mkdir -p "$output"

for command in qemu-system-x86_64 swtpm python3; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

if [[ ! -f "$disk" ]]; then
    echo "disk image not found: $disk" >&2
    exit 1
fi

ovmf_code=""
ovmf_vars=""
for candidate in \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd; do
    [[ -f "$candidate" ]] && ovmf_code="$candidate" && break
done
for candidate in \
    /usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/OVMF/OVMF_VARS.fd; do
    [[ -f "$candidate" ]] && ovmf_vars="$candidate" && break
done
if [[ -z "$ovmf_code" || -z "$ovmf_vars" ]]; then
    echo "OVMF firmware files were not found" >&2
    exit 1
fi

state="$output/swtpm-state"
socket="$output/swtpm.sock"
serial="$output/serial.log"
vars="$output/OVMF_VARS.fd"
mkdir -p "$state"
cp "$ovmf_vars" "$vars"

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$state" \
    --ctrl "type=unixio,path=$socket" \
    --flags startup-clear \
    --daemon

for _ in $(seq 1 50); do
    [[ -S "$socket" ]] && break
    sleep 0.1
done
if [[ ! -S "$socket" ]]; then
    echo "swtpm control socket did not become ready" >&2
    exit 1
fi

cleanup() {
    pkill -f "swtpm socket.*$socket" >/dev/null 2>&1 || true
}
trap cleanup EXIT

set +e
timeout --signal=TERM 25m qemu-system-x86_64 \
    -machine q35,accel=tcg,usb=off \
    -cpu max \
    -smp 2 \
    -m 4096 \
    -display none \
    -monitor none \
    -serial "file:$serial" \
    -no-reboot \
    -nic none \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$vars" \
    -chardev "socket,id=chrtpm,path=$socket" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -drive "file=$disk,if=virtio,format=qcow2,cache=unsafe"
qemu_rc=$?
set -e

if [[ $qemu_rc -ne 0 ]]; then
    echo "QEMU exited with status $qemu_rc" >&2
    tail -200 "$serial" >&2 || true
    exit "$qemu_rc"
fi

python3 scripts/validate_booted_image_receipt.py \
    --serial-log "$serial" \
    --disk "$disk" \
    --source-commit "${GITHUB_SHA:-unknown}" \
    --base-reference "${ATTESTOS_BASE_REFERENCE:-unknown}" \
    --builder-reference "${ATTESTOS_BUILDER_REFERENCE:-unknown}" \
    --output "$output/receipt.json"

#!/usr/bin/env bash
# Mutate the compatibility-signed UKI in a throwaway overlay for a negative boot.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 DISK_QCOW2 STATIC_RECEIPT OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath "$1")
static_receipt=$(realpath "$2")
output=$(realpath -m "$3")
mount_root=$(mktemp -d -p /tmp attestos-fedora-tamper.XXXXXX)
work=$(mktemp -d -p /tmp attestos-fedora-tamper-work.XXXXXX)
nbd=""
mkdir -p "$output"

for command in jq objcopy python3 qemu-img qemu-nbd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    set +e
    mountpoint -q "$mount_root" && sudo umount "$mount_root"
    [[ -n "$nbd" ]] && sudo qemu-nbd --disconnect "$nbd" >/dev/null 2>&1
    rm -rf "$mount_root" "$work"
}
trap cleanup EXIT

sudo modprobe nbd max_part=16
for candidate in /dev/nbd{0..15}; do
    [[ -e "$candidate" ]] || continue
    if ! lsblk -no MOUNTPOINTS "$candidate" 2>/dev/null | grep -q .; then
        nbd="$candidate"
        break
    fi
done
[[ -n "$nbd" ]] || { echo "no free NBD device" >&2; exit 1; }

sudo qemu-nbd --connect="$nbd" --format=qcow2 "$disk"
sudo partprobe "$nbd"
sudo udevadm settle
esp="${nbd}p1"
[[ -b "$esp" ]] || { echo "expected ESP on $esp" >&2; exit 1; }
sudo mount "$esp" "$mount_root"

mapfile -t ukis < <(sudo find "$mount_root/EFI/Linux" -type f -name '*.efi' -print)
[[ ${#ukis[@]} -eq 1 ]] || {
    echo "expected exactly one installed UKI, found ${#ukis[@]}" >&2
    exit 1
}
uki=${ukis[0]}
expected_sha256=$(jq -r '.uki.sha256' "$static_receipt")
original_sha256=$(sudo sha256sum "$uki" | cut -d' ' -f1)
[[ "$original_sha256" == "$expected_sha256" ]]

sudo dd if="$uki" of="$work/tampered.efi" bs=4M status=none conv=fsync
sudo chown "$(id -u):$(id -g)" "$work/tampered.efi"
objcopy --dump-section .cmdline="$work/cmdline" "$work/tampered.efi"
original_cmdline_sha256=$(python3 - "$work/cmdline" <<'PY'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
cmdline = path.read_bytes().rstrip(b"\0")
if not cmdline:
    raise SystemExit("installed UKI has an empty embedded command line")
print(hashlib.sha256(cmdline).hexdigest())
path.write_bytes(cmdline + b" attestos_tamper=1\0")
PY
)
tampered_cmdline_sha256=$(python3 - "$work/cmdline" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes().rstrip(b"\0")).hexdigest())
PY
)
[[ "$tampered_cmdline_sha256" != "$original_cmdline_sha256" ]]
objcopy --update-section .cmdline="$work/cmdline" "$work/tampered.efi"
tampered_sha256=$(sha256sum "$work/tampered.efi" | cut -d' ' -f1)
[[ "$tampered_sha256" != "$original_sha256" ]]
sudo install -m 0644 "$work/tampered.efi" "$uki"
sync

jq -n \
    --arg original_sha256 "$original_sha256" \
    --arg tampered_sha256 "$tampered_sha256" \
    --arg original_cmdline_sha256 "$original_cmdline_sha256" \
    --arg tampered_cmdline_sha256 "$tampered_cmdline_sha256" \
    '{
      format: "attestos.fedora_sealed_tamper/v1",
      mutation: "embedded_cmdline_without_resigning",
      original_uki_sha256: $original_sha256,
      tampered_uki_sha256: $tampered_sha256,
      original_cmdline_sha256: $original_cmdline_sha256,
      tampered_cmdline_sha256: $tampered_cmdline_sha256,
      firmware_rejected: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output/tamper-preboot.json"

sudo umount "$mount_root"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
sudo udevadm settle
checked=false
for _ in $(seq 1 50); do
    if check_output=$(qemu-img check "$disk" 2>&1); then
        printf '%s\n' "$check_output"
        checked=true
        break
    fi
    if ! grep -Fq 'Failed to get shared "write" lock' <<<"$check_output"; then
        printf '%s\n' "$check_output" >&2
        exit 1
    fi
    sleep 0.2
done
[[ "$checked" == true ]] || {
    printf '%s\n' "$check_output" >&2
    echo "qcow2 write lock did not clear after NBD disconnect" >&2
    exit 1
}
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

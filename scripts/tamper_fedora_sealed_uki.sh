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

for command in jq python3 qemu-img qemu-nbd; do
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

sudo dd if="$uki" of="$work/original.efi" bs=4M status=none conv=fsync
sudo chown "$(id -u):$(id -g)" "$work/original.efi"
python3 scripts/mutate_pe_cmdline.py \
    --input "$work/original.efi" \
    --output "$work/tampered.efi" \
    --receipt "$work/mutation.json"
[[ "$(jq -r '.original_uki_sha256' "$work/mutation.json")" == "$original_sha256" ]]
[[ "$(jq -r '.certificate_table_preserved' "$work/mutation.json")" == true ]]
sudo install -m 0644 "$work/tampered.efi" "$uki"
sync

jq \
    '.layout_format = .format |
     .format = "attestos.fedora_sealed_tamper/v1" |
     .mutation = "embedded_cmdline_bytes_without_resigning" |
     .firmware_rejected = false' \
    "$work/mutation.json" > "$output/tamper-preboot.json"

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

#!/usr/bin/env bash
# Build the sealed disk with the exact upstream-tested bcvk path, then inspect its ESP.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 OUTPUT_QCOW2 OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath -m "$1")
output=$(realpath -m "$2")
source_reference=${ATTESTOS_FEDORA_IMAGE_REFERENCE:?missing immutable image reference}
installer_reference=${ATTESTOS_FEDORA_INSTALLER_IMAGE_REFERENCE:?missing immutable installer reference}
bcvk=${ATTESTOS_BCVK:-bcvk}
mount_root=$(mktemp -d -p /tmp attestos-fedora-esp.XXXXXX)
nbd=""
mkdir -p "$(dirname "$disk")" "$output"

for command in "$bcvk" objcopy podman qemu-img qemu-nbd sbverify; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    set +e
    mountpoint -q "$mount_root" && sudo umount "$mount_root"
    [[ -n "$nbd" ]] && sudo qemu-nbd --disconnect "$nbd" >/dev/null 2>&1
    rm -rf "$mount_root"
}
trap cleanup EXIT

# This is the exact disk-construction interface documented by the frozen
# upstream source. No composefs or boot-finalization check is skipped.
rm -f "$disk"
"$bcvk" to-disk \
    --filesystem=btrfs \
    --composefs-backend \
    --bootloader=systemd \
    --format=qcow2 \
    --disk-size=20G \
    "$source_reference" \
    "$disk"

test -s "$disk"
qemu-img check "$disk"

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
esp=$(lsblk -lnpo NAME,FSTYPE "$nbd" | awk '$2 == "vfat" {print $1; exit}')
[[ -b "$esp" ]] || { echo "installed disk has no vfat ESP" >&2; exit 1; }
sudo mount -o ro "$esp" "$mount_root"

sudo python3 scripts/inspect_fedora_sealed_disk.py \
    --esp "$mount_root" \
    --certificate trust/fedora-sealed-secureboot-db.pem \
    --source-reference "$source_reference" \
    --installer-reference "$installer_reference" \
    --output "$output/static-inspection.json"

sudo umount "$mount_root"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
sha256sum "$disk" > "$output/disk.sha256"
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

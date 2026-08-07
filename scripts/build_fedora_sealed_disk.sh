#!/usr/bin/env bash
# Install the immutable Fedora sealed container through its systemd-boot path.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 OUTPUT_QCOW2 OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath -m "$1")
output=$(realpath -m "$2")
source_reference=${ATTESTOS_FEDORA_IMAGE_REFERENCE:?missing immutable image reference}
mapper="attestos-fedora-${GITHUB_RUN_ID:-local}-$$"
mount_root=$(mktemp -d -p /tmp attestos-fedora-root.XXXXXX)
nbd=""
mkdir -p "$(dirname "$disk")" "$output"

for command in cryptsetup objcopy podman qemu-img qemu-nbd sbverify systemd-repart; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    set +e
    mountpoint -q "$mount_root/boot" && sudo umount "$mount_root/boot"
    mountpoint -q "$mount_root" && sudo umount "$mount_root"
    [[ -e "/dev/mapper/$mapper" ]] && sudo cryptsetup close "$mapper"
    [[ -n "$nbd" ]] && sudo qemu-nbd --disconnect "$nbd" >/dev/null 2>&1
    rm -rf "$mount_root"
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

rm -f "$disk"
qemu-img create -f qcow2 "$disk" 20G
sudo qemu-nbd --connect="$nbd" --format=qcow2 "$disk"
sudo systemd-repart \
    --empty=force \
    --definitions=canary/fedora-sealed/repart.d \
    --dry-run=no \
    --discard=no \
    "$nbd"
sudo partprobe "$nbd"
sudo udevadm settle

esp="${nbd}p1"
root="${nbd}p2"
[[ -b "$esp" && -b "$root" ]] || {
    echo "expected ESP and root partitions on $nbd" >&2
    exit 1
}

# The upstream development partition contract intentionally uses an empty
# passphrase. QMP sends Return during boot for the same bounded test-only path.
printf '\n' | sudo cryptsetup open "$root" "$mapper"
sudo mount "/dev/mapper/$mapper" "$mount_root"
sudo mkdir -p "$mount_root/boot"
sudo mount "$esp" "$mount_root/boot"

sudo podman pull "$source_reference"
sudo podman run \
    --rm \
    --privileged \
    --pid=host \
    --ipc=host \
    --network=none \
    --security-opt label=type:unconfined_t \
    -v /var/lib/containers:/var/lib/containers \
    -v /dev:/dev \
    -v /:/run/host \
    "$source_reference" \
    bootc install to-filesystem \
        --source-imgref="containers-storage:$source_reference" \
        --bootloader=systemd \
        --composefs-backend \
        --skip-finalize \
        "/run/host$mount_root"

sudo python3 scripts/inspect_fedora_sealed_disk.py \
    --esp "$mount_root/boot" \
    --certificate trust/fedora-sealed-secureboot-db.pem \
    --source-reference "$source_reference" \
    --output "$output/static-inspection.json"

sync
sudo umount "$mount_root/boot"
sudo umount "$mount_root"
sudo cryptsetup close "$mapper"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
qemu-img check "$disk"
sha256sum "$disk" > "$output/disk.sha256"
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

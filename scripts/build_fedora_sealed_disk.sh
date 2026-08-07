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
installer_reference=${ATTESTOS_FEDORA_INSTALLER_IMAGE_REFERENCE:?missing immutable installer reference}
mount_root=$(mktemp -d -p /tmp attestos-fedora-root.XXXXXX)
nbd=""
mkdir -p "$(dirname "$disk")" "$output"

for command in objcopy podman qemu-img qemu-nbd sbverify systemd-repart; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    set +e
    mountpoint -q "$mount_root/boot" && sudo umount "$mount_root/boot"
    mountpoint -q "$mount_root" && sudo umount "$mount_root"
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

# This disposable no-network positive control intentionally uses a plain root.
# Root encryption is not part of the UKI/PCR admission claim, and an interactive
# initramfs password prompt would make the harness depend on console timing.
sudo mount "$root" "$mount_root"
sudo mkdir -p "$mount_root/boot"
sudo mount "$esp" "$mount_root/boot"

sudo podman pull "$source_reference"
sudo podman pull "$installer_reference"
prepare_root="$output/source-prepare-root.conf"
sudo podman run \
    --rm \
    --network=none \
    "$source_reference" \
    sh -c 'for path in /usr/lib/ostree/prepare-root.conf /etc/ostree/prepare-root.conf; do
        if test -f "$path"; then
            cat "$path"
            exit 0
        fi
    done
    exit 1' > "$prepare_root"
[[ -s "$prepare_root" ]] || { echo "source prepare-root.conf is empty" >&2; exit 1; }
sha256sum "$prepare_root" > "$output/source-prepare-root.sha256"
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
    -v "$prepare_root:/usr/lib/ostree/prepare-root.conf:ro" \
    "$installer_reference" \
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
    --installer-reference "$installer_reference" \
    --output "$output/static-inspection.json"

# The physical partition root is not the root systemd enters. OSTree remaps the
# selected deployment at boot, including that deployment's writable /etc.
# Require the single fresh-install deployment explicitly so a probe can never be
# placed in an inactive deployment or the physical root by accident.
deployment_roots=()
while IFS= read -r candidate; do
    deployment_roots+=("$candidate")
done < <(sudo find "$mount_root/ostree/deploy" \
    -mindepth 3 -maxdepth 3 -type d -path '*/deploy/*.*' -print | sort)
[[ ${#deployment_roots[@]} -eq 1 ]] || {
    echo "expected exactly one OSTree deployment, found ${#deployment_roots[@]}" >&2
    exit 1
}
deployment_root=${deployment_roots[0]}
deployment_relative=${deployment_root#"$mount_root"}

# The positive-control probe is machine-local test instrumentation. It is
# installed only after the signed UKI has been inspected and never enters the
# sealed /usr tree or the PCR 11 identity under test.
probe_dir="$deployment_root/etc/attestos-positive-control"
unit_dir="$deployment_root/etc/systemd/system"
sudo install -d -m 0755 "$probe_dir" "$unit_dir/multi-user.target.wants"
sudo install -m 0644 \
    scripts/fedora_sealed_guest_probe.py \
    "$probe_dir/fedora_sealed_guest_probe.py"
sudo install -m 0644 \
    canary/fedora-sealed/fedora-sealed-positive-control.service \
    "$unit_dir/fedora-sealed-positive-control.service"
sudo ln -sfn \
    ../fedora-sealed-positive-control.service \
    "$unit_dir/multi-user.target.wants/fedora-sealed-positive-control.service"
jq -n \
    --arg probe_sha256 "$(sha256sum scripts/fedora_sealed_guest_probe.py | cut -d' ' -f1)" \
    --arg unit_sha256 "$(sha256sum canary/fedora-sealed/fedora-sealed-positive-control.service | cut -d' ' -f1)" \
    --arg deployment_root "$deployment_relative" \
    '{
      format: "attestos.fedora_sealed_probe_install/v1",
      location: "selected_ostree_deployment_etc_outside_sealed_usr",
      deployment_root: $deployment_root,
      probe_sha256: $probe_sha256,
      unit_sha256: $unit_sha256,
      affects_static_uki_identity: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output/probe-installation.json"

sync
sudo umount "$mount_root/boot"
sudo umount "$mount_root"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
qemu-img check "$disk"
sha256sum "$disk" > "$output/disk.sha256"
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

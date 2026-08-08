#!/usr/bin/env bash
# Install exactly zero or one bounded addon into a disposable disk overlay.
set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 DISK_QCOW2 ARM ADDON_OR_DASH STATIC_INSPECTION OUTPUT" >&2
    exit 2
fi

disk=$(realpath "$1")
arm=$2
addon=$3
static=$(realpath "$4")
output=$(realpath -m "$5")
disk_sha256_before=$(sha256sum "$disk" | cut -d' ' -f1)
mount_root=$(mktemp -d -p /tmp attestos-pcr12-arm.XXXXXX)
nbd=""

case "$arm" in
    baseline|signed|tampered) ;;
    *) echo "unsupported PCR12 arm: $arm" >&2; exit 2 ;;
esac
if [[ "$arm" == baseline ]]; then
    [[ "$addon" == - ]] || { echo "baseline arm cannot accept an addon" >&2; exit 2; }
else
    addon=$(realpath "$addon")
    [[ -f "$addon" ]] || { echo "addon file does not exist" >&2; exit 1; }
fi

cleanup() {
    set +e
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
expected_uki_sha256=$(jq -r '.uki.sha256' "$static")
uki_sha256=$(sudo sha256sum "${ukis[0]}" | cut -d' ' -f1)
[[ "$uki_sha256" == "$expected_uki_sha256" ]] || {
    echo "arm UKI does not match static inspection" >&2
    exit 1
}

addon_dir="$mount_root/loader/addons"
sudo install -d -m 0755 "$addon_dir"
mapfile -t existing < <(sudo find "$addon_dir" -maxdepth 1 -type f -name '*.addon.efi' -print)
[[ ${#existing[@]} -eq 0 ]] || {
    echo "base disk unexpectedly contains ${#existing[@]} addon files" >&2
    exit 1
}
if [[ "$arm" != baseline ]]; then
    sudo install -m 0644 "$addon" "$addon_dir/10-attestos-policy.addon.efi"
fi
mapfile -t installed < <(sudo find "$addon_dir" -maxdepth 1 -type f -name '*.addon.efi' -print)
expected_count=0
[[ "$arm" == baseline ]] || expected_count=1
[[ ${#installed[@]} -eq "$expected_count" ]] || {
    echo "arm $arm expected $expected_count addon files, found ${#installed[@]}" >&2
    exit 1
}

addon_sha256=""
addon_size=0
if [[ "$expected_count" -eq 1 ]]; then
    addon_sha256=$(sudo sha256sum "${installed[0]}" | cut -d' ' -f1)
    addon_size=$(sudo stat -c %s "${installed[0]}")
    [[ "$addon_sha256" == "$(sha256sum "$addon" | cut -d' ' -f1)" ]]
fi

mkdir -p "$(dirname "$output")"
jq -n \
    --arg arm "$arm" \
    --arg disk_sha256_before "$disk_sha256_before" \
    --arg uki_sha256 "$uki_sha256" \
    --arg addon_name "$([[ "$expected_count" -eq 1 ]] && echo '10-attestos-policy.addon.efi' || true)" \
    --arg addon_sha256 "$addon_sha256" \
    --argjson addon_size "$addon_size" \
    --argjson addon_count "$expected_count" \
    '{
      format: "attestos.fedora_pcr12_arm/v1",
      arm: $arm,
      disk_sha256_before_install: $disk_sha256_before,
      uki_sha256: $uki_sha256,
      addon_count: $addon_count,
      addon: (if $addon_count == 1 then {
        name: $addon_name,
        uefi_path: "\\loader\\addons\\10-attestos-policy.addon.efi",
        sha256: $addon_sha256,
        size_bytes: $addon_size
      } else null end),
      affects_uki_identity: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output"

sync
sudo umount "$mount_root"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
sudo udevadm settle
disk_sha256_after=$(sha256sum "$disk" | cut -d' ' -f1)
jq --arg disk_sha256_after "$disk_sha256_after" \
    '.disk_sha256_after_install = $disk_sha256_after' \
    "$output" > "$output.tmp"
mv "$output.tmp" "$output"
sudo chown "$(id -u):$(id -g)" "$output" "$disk"

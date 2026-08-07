#!/usr/bin/env bash
# Re-sign the frozen upstream UKI with a run-local compatibility key.
set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 DISK_QCOW2 OUTPUT_DIR UPSTREAM_CERT CANARY_KEY CANARY_CERT" >&2
    exit 2
fi

disk=$(realpath "$1")
output=$(realpath -m "$2")
upstream_cert=$(realpath "$3")
canary_key=$(realpath "$4")
canary_cert=$(realpath "$5")
source_reference=${ATTESTOS_FEDORA_IMAGE_REFERENCE:?missing immutable image reference}
installer_reference=${ATTESTOS_FEDORA_INSTALLER_IMAGE_REFERENCE:?missing immutable installer reference}
mount_root=$(mktemp -d -p /tmp attestos-fedora-compat.XXXXXX)
nbd=""
mkdir -p "$output"

for command in jq objcopy openssl podman qemu-img qemu-nbd sbverify; do
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
work=$(mktemp -d -p /tmp attestos-fedora-sign.XXXXXX)
trap 'rm -rf "$work"; cleanup' EXIT
expected_sha256=$(jq -r '.uki.sha256' "$output/upstream-static-inspection.json")
expected_cert_sha256=$(jq -r '.uki.certificate_sha256' "$output/upstream-static-inspection.json")
upstream_cert_sha256=$(sha256sum "$upstream_cert" | cut -d' ' -f1)
source_sha256=$(sudo sha256sum "$uki" | cut -d' ' -f1)
source_size=$(sudo stat -c %s "$uki")
printf 'compat_source size=%s sha256=%s expected_sha256=%s\n' \
    "$source_size" "$source_sha256" "$expected_sha256"
[[ "$source_sha256" == "$expected_sha256" ]]
[[ "$upstream_cert_sha256" == "$expected_cert_sha256" ]]
sudo dd if="$uki" of="$work/original.efi" bs=4M status=none conv=fsync
sudo chown "$(id -u):$(id -g)" "$work/original.efi"
copy_sha256=$(sha256sum "$work/original.efi" | cut -d' ' -f1)
copy_size=$(stat -c %s "$work/original.efi")
printf 'compat_copy size=%s sha256=%s\n' "$copy_size" "$copy_sha256"
[[ "$copy_sha256" == "$expected_sha256" ]]

objcopy --dump-section .cmdline="$work/original.cmdline" "$work/original.efi"
install -m 0600 "$canary_key" "$work/canary-signing.key"
install -m 0644 "$canary_cert" "$work/canary-signing.pem"
sudo podman run \
    --rm \
    --network=none \
    -v "$work:/work:rw,Z" \
    "$source_reference" \
    sh -eu -c '
        signer=$(command -v systemd-sbsign || true)
        if test -z "$signer"; then
            signer=/usr/lib/systemd/systemd-sbsign
        fi
        test -x "$signer"
        exec "$signer" sign \
            --private-key=/work/canary-signing.key \
            --certificate=/work/canary-signing.pem \
            --output=/work/signed.efi \
            /work/original.efi
    '
sudo chown "$(id -u):$(id -g)" "$work/signed.efi"
rm -f "$work/canary-signing.key"
sbverify --cert "$canary_cert" "$work/signed.efi"
objcopy --dump-section .cmdline="$work/signed.cmdline" "$work/signed.efi"
cmp "$work/original.cmdline" "$work/signed.cmdline"
[[ "$(sha256sum "$work/original.efi" | cut -d' ' -f1)" != \
   "$(sha256sum "$work/signed.efi" | cut -d' ' -f1)" ]]

sudo install -m 0644 "$work/signed.efi" "$uki"
sync

sudo python3 scripts/inspect_fedora_sealed_disk.py \
    --esp "$mount_root" \
    --certificate "$canary_cert" \
    --source-reference "$source_reference" \
    --installer-reference "$installer_reference" \
    --output "$output/static-inspection.json"

openssl x509 -in "$canary_cert" -outform DER > "$work/canary.der"
jq -n \
    --arg original_sha256 "$(sha256sum "$work/original.efi" | cut -d' ' -f1)" \
    --arg resigned_sha256 "$(sha256sum "$work/signed.efi" | cut -d' ' -f1)" \
    --arg cmdline_sha256 "$(sha256sum "$work/signed.cmdline" | cut -d' ' -f1)" \
    --arg certificate_sha256 "$(sha256sum "$work/canary.der" | cut -d' ' -f1)" \
    --arg key_bits "$(openssl x509 -in "$canary_cert" -noout -text | sed -n 's/.*Public-Key: (\([0-9][0-9]*\) bit).*/\1/p' | head -1)" \
    '{
      format: "attestos.fedora_sealed_compat_resign/v1",
      purpose: "harness_compatibility_positive_control_only",
      upstream_signature_admitted_by_firmware: false,
      original_uki_sha256: $original_sha256,
      compatibility_signed_uki_sha256: $resigned_sha256,
      embedded_cmdline_sha256: $cmdline_sha256,
      canary_certificate_sha256: $certificate_sha256,
      canary_rsa_bits: ($key_bits | tonumber),
      private_key_persisted: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output/compat-resign.json"

sudo umount "$mount_root"
sudo qemu-nbd --disconnect "$nbd"
nbd=""
qemu-img check "$disk"
sha256sum "$disk" > "$output/disk.sha256"
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

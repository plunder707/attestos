#!/usr/bin/env bash
# Re-sign the complete UKI from the frozen source image with a run-local key.
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
mount_root=$(mktemp -d -p /tmp attestos-fedora-compat.XXXXXX)
nbd=""
source_container=""
mkdir -p "$output"

for command in jq objcopy openssl podman python3 qemu-img qemu-nbd sbverify; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    set +e
    mountpoint -q "$mount_root" && sudo umount "$mount_root"
    [[ -n "$nbd" ]] && sudo qemu-nbd --disconnect "$nbd" >/dev/null 2>&1
    [[ -n "$source_container" ]] && sudo podman rm -f "$source_container" >/dev/null 2>&1
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
installed_uki=${ukis[0]}
work=$(mktemp -d -p /tmp attestos-fedora-sign.XXXXXX)
trap 'rm -rf "$work"; cleanup' EXIT
expected_sha256=$(jq -r '.uki.sha256' "$output/upstream-static-inspection.json")
expected_cert_sha256=$(jq -r '.uki.certificate_sha256' "$output/upstream-static-inspection.json")
upstream_cert_sha256=$(sha256sum "$upstream_cert" | cut -d' ' -f1)
installed_sha256=$(sudo sha256sum "$installed_uki" | cut -d' ' -f1)
installed_size=$(sudo stat -c %s "$installed_uki")
printf 'compat_installed size=%s sha256=%s expected_sha256=%s\n' \
    "$installed_size" "$installed_sha256" "$expected_sha256"
[[ "$installed_sha256" == "$expected_sha256" ]]
[[ "$upstream_cert_sha256" == "$expected_cert_sha256" ]]

mkdir "$work/source-efi"
source_container=$(sudo podman create --network=none "$source_reference")
sudo podman cp "$source_container:/boot/EFI/Linux/." "$work/source-efi"
sudo podman rm "$source_container" >/dev/null
source_container=""
sudo chown -R "$(id -u):$(id -g)" "$work/source-efi"
mapfile -t source_ukis < <(find "$work/source-efi" -type f -name '*.efi' -print)
[[ ${#source_ukis[@]} -eq 1 ]] || {
    echo "expected exactly one UKI in immutable source, found ${#source_ukis[@]}" >&2
    exit 1
}
install -m 0644 "${source_ukis[0]}" "$work/original.efi"
source_sha256=$(sha256sum "$work/original.efi" | cut -d' ' -f1)
source_size=$(stat -c %s "$work/original.efi")
printf 'compat_immutable_source size=%s sha256=%s installed_sha256=%s\n' \
    "$source_size" "$source_sha256" "$installed_sha256"
sbverify --cert "$upstream_cert" "$work/original.efi"

sudo objcopy --dump-section .cmdline="$work/installed.cmdline" "$installed_uki"
sudo chown "$(id -u):$(id -g)" "$work/installed.cmdline"
objcopy --dump-section .cmdline="$work/original.cmdline" "$work/original.efi"
cmp "$work/installed.cmdline" "$work/original.cmdline"
python3 scripts/strip_pe_certificate_table.py \
    --input "$work/original.efi" \
    --output "$work/unsigned.efi" \
    --receipt "$output/certificate-strip.json"
objcopy --dump-section .cmdline="$work/unsigned.cmdline" "$work/unsigned.efi"
cmp "$work/original.cmdline" "$work/unsigned.cmdline"
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
            /work/unsigned.efi
    '
sudo chown "$(id -u):$(id -g)" "$work/signed.efi"
rm -f "$work/canary-signing.key"
objcopy --dump-section .cmdline="$work/signed.cmdline" "$work/signed.efi"
cmp "$work/original.cmdline" "$work/signed.cmdline"
[[ "$(sha256sum "$work/original.efi" | cut -d' ' -f1)" != \
   "$(sha256sum "$work/signed.efi" | cut -d' ' -f1)" ]]

sudo install -m 0644 "$work/signed.efi" "$installed_uki"
sync

openssl x509 -in "$canary_cert" -outform DER > "$work/canary.der"
signed_sha256=$(sha256sum "$work/signed.efi" | cut -d' ' -f1)
signed_size=$(stat -c %s "$work/signed.efi")
canary_cert_sha256=$(sha256sum "$work/canary.der" | cut -d' ' -f1)
cmdline_sha256=$(python3 - "$work/signed.cmdline" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes().rstrip(b"\0")).hexdigest())
PY
)
jq \
    --arg installed_upstream_sha256 "$installed_sha256" \
    --argjson installed_upstream_size "$installed_size" \
    --arg immutable_source_sha256 "$source_sha256" \
    --argjson immutable_source_size "$source_size" \
    --arg immutable_source_reference "$source_reference" \
    --arg signed_sha256 "$signed_sha256" \
    --argjson signed_size "$signed_size" \
    --arg certificate_sha256 "$canary_cert_sha256" \
    '.uki.installed_upstream_sha256 = $installed_upstream_sha256 |
     .uki.installed_upstream_size_bytes = $installed_upstream_size |
     .uki.upstream_sha256 = $immutable_source_sha256 |
     .uki.upstream_size_bytes = $immutable_source_size |
     .uki.immutable_source_reference = $immutable_source_reference |
     .uki.immutable_source_signature_verified = true |
     .uki.upstream_signature_verified = .uki.signature_verified |
     .uki.upstream_tamper_rejected = .uki.tampered_cmdline_signature_rejected |
     .uki.sha256 = $signed_sha256 |
     .uki.size_bytes = $signed_size |
     .uki.certificate_sha256 = $certificate_sha256 |
     .uki.signature_verified = false |
     .uki.signature_prepared = true |
     .uki.signature_tool = "strict_certificate_strip_then_systemd-sbsign" |
     .uki.signature_verification_mode = "secure_boot_firmware_admission" |
     .uki.tampered_cmdline_signature_rejected = false |
     .uki.tampered_cmdline_firmware_rejected = false' \
    "$output/upstream-static-inspection.json" > "$output/static-inspection.json"

jq -n \
    --arg source_reference "$source_reference" \
    --arg installed_upstream_sha256 "$installed_sha256" \
    --argjson installed_upstream_size "$installed_size" \
    --arg immutable_source_sha256 "$source_sha256" \
    --argjson immutable_source_size "$source_size" \
    --arg original_sha256 "$(sha256sum "$work/original.efi" | cut -d' ' -f1)" \
    --arg unsigned_sha256 "$(sha256sum "$work/unsigned.efi" | cut -d' ' -f1)" \
    --arg resigned_sha256 "$(sha256sum "$work/signed.efi" | cut -d' ' -f1)" \
    --arg cmdline_sha256 "$cmdline_sha256" \
    --arg certificate_sha256 "$canary_cert_sha256" \
    --arg key_bits "$(openssl x509 -in "$canary_cert" -noout -text | sed -n 's/.*Public-Key: (\([0-9][0-9]*\) bit).*/\1/p' | head -1)" \
    '{
      format: "attestos.fedora_sealed_compat_resign/v1",
      purpose: "harness_compatibility_positive_control_only",
      source_reference: $source_reference,
      installed_upstream_uki_sha256: $installed_upstream_sha256,
      installed_upstream_uki_size_bytes: $installed_upstream_size,
      immutable_source_uki_sha256: $immutable_source_sha256,
      immutable_source_uki_size_bytes: $immutable_source_size,
      immutable_source_signature_verified: true,
      installed_and_source_cmdline_match: true,
      upstream_signature_admitted_by_firmware: false,
      original_uki_sha256: $original_sha256,
      unsigned_uki_sha256: $unsigned_sha256,
      compatibility_signed_uki_sha256: $resigned_sha256,
      embedded_cmdline_sha256: $cmdline_sha256,
      canary_certificate_sha256: $certificate_sha256,
      canary_rsa_bits: ($key_bits | tonumber),
      signature_tool: "strict_certificate_strip_then_systemd-sbsign",
      signature_verification_mode: "secure_boot_firmware_admission",
      private_key_persisted: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output/compat-resign.json"

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
sha256sum "$disk" > "$output/disk.sha256"
sudo chown -R "$(id -u):$(id -g)" "$output" "$disk"

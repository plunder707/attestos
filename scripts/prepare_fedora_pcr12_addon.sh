#!/usr/bin/env bash
# Admit one preflight-validated cmdline add-on and enroll only its public test key.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 SOURCE_OVMF_VARS OUTPUT_OVMF_VARS OUTPUT_DIR" >&2
    exit 2
fi

source_vars=$(realpath "$1")
output_vars=$(realpath -m "$2")
output=$(realpath -m "$3")
source_reference=${ATTESTOS_FEDORA_IMAGE_REFERENCE:?missing immutable image reference}
signer_base_reference=${ATTESTOS_FEDORA_SIGNER_BASE_REFERENCE:?missing immutable signer base}
signer_image=${ATTESTOS_FEDORA_SIGNER_IMAGE:?missing local signer image}
preflight=$(realpath "${ATTESTOS_FEDORA_SIGNER_PREFLIGHT:?missing validated signer preflight}")
systemd_nvr=${ATTESTOS_SYSTEMD_NVR:?missing pinned systemd NVR}
ukify_rpm_sha256=${ATTESTOS_SYSTEMD_UKIFY_RPM_SHA256:?missing ukify RPM digest}
boot_rpm_sha256=${ATTESTOS_SYSTEMD_BOOT_UNSIGNED_RPM_SHA256:?missing boot RPM digest}
expected_ukify_sha256=${ATTESTOS_SYSTEMD_UKIFY_SHA256:?missing ukify file digest}
expected_stub_sha256=${ATTESTOS_SYSTEMD_ADDON_STUB_SHA256:?missing add-on stub digest}
systemd_rpm_sha256=${ATTESTOS_SYSTEMD_RPM_SHA256:?missing systemd RPM digest}
systemd_shared_rpm_sha256=${ATTESTOS_SYSTEMD_SHARED_RPM_SHA256:?missing systemd-shared RPM digest}
expected_sbsign_sha256=${ATTESTOS_SYSTEMD_SBSIGN_SHA256:?missing systemd-sbsign digest}
expected_shared_object_sha256=${ATTESTOS_SYSTEMD_SHARED_OBJECT_SHA256:?missing systemd-shared object digest}
ukify=$(realpath "${ATTESTOS_FEDORA_UKIFY:?missing pinned Fedora ukify}")
addon_stub=$(realpath "${ATTESTOS_FEDORA_ADDON_STUB:?missing pinned Fedora add-on stub}")
policy='lockdown=confidentiality module.sig_enforce=1'
owner_guid='9d4f4ef8-5f6d-4a73-9b2c-90c8e6c2e6f1'
mkdir -p "$output" "$(dirname "$output_vars")"
work=$(mktemp -d -p "$(dirname "$output")" .attestos-pcr12-addon.XXXXXX)

for command in jq objcopy objdump openssl podman python3 sbverify sha256sum sudo virt-fw-vars; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ "$(sha256sum "$ukify" | cut -d' ' -f1)" == "$expected_ukify_sha256" ]]
[[ "$(sha256sum "$addon_stub" | cut -d' ' -f1)" == "$expected_stub_sha256" ]]

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT

unsigned="$work/10-attestos-policy.unsigned.addon.efi"
addon="$work/10-attestos-policy.addon.efi"
tampered="$work/10-attestos-policy.tampered.addon.efi"
mutation="$work/addon-mutation.json"
for file in unsigned.addon.efi signed.addon.efi tampered.addon.efi addon.pem mutation.json; do
    test -s "$preflight/$file"
done
test ! -e "$preflight/addon.key"
install -m 0644 "$preflight/unsigned.addon.efi" "$unsigned"
install -m 0644 "$preflight/signed.addon.efi" "$addon"
install -m 0644 "$preflight/tampered.addon.efi" "$tampered"
install -m 0644 "$preflight/addon.pem" "$work/addon.pem"
install -m 0644 "$preflight/mutation.json" "$mutation"

actual_sbsign_sha256=$(sudo podman run --rm --network=none "$signer_image" \
    sha256sum /usr/lib/systemd/systemd-sbsign | cut -d' ' -f1)
[[ "$actual_sbsign_sha256" == "$expected_sbsign_sha256" ]]
actual_shared_object_sha256=$(sudo podman run --rm --network=none "$signer_image" \
    sha256sum /usr/lib64/systemd/libsystemd-shared-259.5-1.fc44.so | cut -d' ' -f1)
[[ "$actual_shared_object_sha256" == "$expected_shared_object_sha256" ]]

test -s "$addon"
unsigned_size=$(stat -c %s "$unsigned")
signed_size=$(stat -c %s "$addon")
printf 'addon_signer_output unsigned_size=%s signed_size=%s\n' \
    "$unsigned_size" "$signed_size"
[[ "$signed_size" -gt "$unsigned_size" ]] || {
    echo "signed add-on did not grow a certificate table" >&2
    exit 1
}
sbverify --cert "$work/addon.pem" "$addon" >/dev/null
if objdump -h "$addon" | awk '$2 == ".linux" {found=1} END {exit !found}'; then
    echo "cmdline addon unexpectedly contains a .linux section" >&2
    exit 1
fi
if ! objdump -h "$addon" | awk '$2 == ".sbat" {found=1} END {exit !found}'; then
    echo "cmdline addon does not contain the required .sbat section" >&2
    exit 1
fi
cp --reflink=auto "$addon" "$work/addon.objcopy-input.efi"
objcopy --dump-section .cmdline="$work/addon.cmdline" \
    "$work/addon.objcopy-input.efi"
rm -f "$work/addon.objcopy-input.efi"
python3 - "$work/addon.cmdline" "$policy" <<'PY'
import sys
from pathlib import Path

actual = Path(sys.argv[1]).read_bytes().rstrip(b"\0").decode("utf-8")
if actual != sys.argv[2]:
    raise SystemExit(f"addon command line mismatch: {actual!r}")
PY

python3 scripts/mutate_pe_cmdline.py \
    --input "$addon" \
    --output "$work/recomputed-tampered.addon.efi" \
    --receipt "$work/recomputed-mutation.json" >/dev/null
cmp "$tampered" "$work/recomputed-tampered.addon.efi"
cmp "$mutation" "$work/recomputed-mutation.json"
if sbverify --cert "$work/addon.pem" "$tampered" \
    >/dev/null 2>&1; then
    echo "tampered addon still verifies" >&2
    exit 1
fi

rm -f "$output_vars"
virt-fw-vars \
    --input "$source_vars" \
    --output "$output_vars" \
    --add-db "$owner_guid" "$work/addon.pem"

mkdir "$work/original-certs" "$work/extended-certs"
(
    cd "$work/original-certs"
    virt-fw-vars --input "$source_vars" --extract-certs >/dev/null
)
(
    cd "$work/extended-certs"
    virt-fw-vars --input "$output_vars" --extract-certs >/dev/null
)

certificate_hashes() {
    local directory=$1
    for cert in "$directory"/*.pem; do
        openssl x509 -in "$cert" -outform DER | sha256sum | cut -d' ' -f1
    done | sort
}
certificate_hashes "$work/original-certs" > "$work/original-cert-hashes"
certificate_hashes "$work/extended-certs" > "$work/extended-cert-hashes"
missing_certificates=$(comm -23 "$work/original-cert-hashes" "$work/extended-cert-hashes")
if [[ -n "$missing_certificates" ]]; then
    echo "extending db removed an original Secure Boot certificate" >&2
    exit 1
fi

openssl x509 -in "$work/addon.pem" -outform DER > "$work/addon.der"
cert_sha256=$(sha256sum "$work/addon.der" | cut -d' ' -f1)
cert_occurrences=$(grep -Fxc "$cert_sha256" "$work/extended-cert-hashes" || true)
[[ "$cert_occurrences" -eq 1 ]] || {
    echo "expected one enrolled canary certificate, found $cert_occurrences" >&2
    exit 1
}

install -m 0644 "$addon" "$output/10-attestos-policy.addon.efi"
install -m 0644 \
    "$tampered" \
    "$output/10-attestos-policy.tampered.addon.efi"
install -m 0644 "$work/addon.pem" "$output/addon-public.pem"
install -m 0644 "$mutation" "$output/addon-mutation.json"

jq -n \
    --arg source_reference "$source_reference" \
    --arg systemd_nvr "$systemd_nvr" \
    --arg ukify_rpm_sha256 "$ukify_rpm_sha256" \
    --arg boot_rpm_sha256 "$boot_rpm_sha256" \
    --arg signer_base_reference "$signer_base_reference" \
    --arg systemd_rpm_sha256 "$systemd_rpm_sha256" \
    --arg systemd_shared_rpm_sha256 "$systemd_shared_rpm_sha256" \
    --arg systemd_sbsign_sha256 "$expected_sbsign_sha256" \
    --arg systemd_shared_object_sha256 "$expected_shared_object_sha256" \
    --arg ukify_sha256 "$expected_ukify_sha256" \
    --arg addon_stub_sha256 "$expected_stub_sha256" \
    --arg unsigned_addon_sha256 "$(sha256sum "$unsigned" | cut -d' ' -f1)" \
    --arg policy "$policy" \
    --arg owner_guid "$owner_guid" \
    --arg addon_sha256 "$(sha256sum "$addon" | cut -d' ' -f1)" \
    --argjson addon_size "$(stat -c %s "$addon")" \
    --arg tampered_sha256 "$(sha256sum "$tampered" | cut -d' ' -f1)" \
    --arg certificate_sha256 "$cert_sha256" \
    --arg source_vars_sha256 "$(sha256sum "$source_vars" | cut -d' ' -f1)" \
    --arg extended_vars_sha256 "$(sha256sum "$output_vars" | cut -d' ' -f1)" \
    --argjson original_certificate_count "$(wc -l < "$work/original-cert-hashes")" \
    --argjson extended_certificate_count "$(wc -l < "$work/extended-cert-hashes")" \
    --slurpfile mutation "$mutation" \
    '{
      format: "attestos.fedora_pcr12_addon_static/v1",
      purpose: "disposable_pcr12_addon_harness_only",
      source_reference: $source_reference,
      builder: {
        systemd_nvr: $systemd_nvr,
        ukify_rpm_sha256: $ukify_rpm_sha256,
        boot_unsigned_rpm_sha256: $boot_rpm_sha256,
        ukify_sha256: $ukify_sha256,
        addon_stub_sha256: $addon_stub_sha256,
        signature_tool: "pinned_fedora_systemd-sbsign",
        signer_base_reference: $signer_base_reference,
        systemd_rpm_sha256: $systemd_rpm_sha256,
        systemd_shared_rpm_sha256: $systemd_shared_rpm_sha256,
        systemd_sbsign_sha256: $systemd_sbsign_sha256,
        systemd_shared_object_sha256: $systemd_shared_object_sha256,
        unsigned_addon_sha256: $unsigned_addon_sha256
      },
      addon: {
        name: "10-attestos-policy.addon.efi",
        uefi_path: "\\loader\\addons\\10-attestos-policy.addon.efi",
        sha256: $addon_sha256,
        size_bytes: $addon_size,
        cmdline: $policy,
        cmdline_tokens: ($policy | split(" ")),
        signature_verified: true,
        contains_linux_section: false,
        certificate_sha256: $certificate_sha256,
        sbat_present: true
      },
      tamper: {
        sha256: $tampered_sha256,
        signature_rejected: true,
        mutation: $mutation[0]
      },
      variable_store: {
        owner_guid: $owner_guid,
        source_sha256: $source_vars_sha256,
        extended_sha256: $extended_vars_sha256,
        original_certificates_preserved: true,
        original_certificate_count: $original_certificate_count,
        extended_certificate_count: $extended_certificate_count,
        canary_certificate_occurrences: 1
      },
      private_key_persisted: false,
      manufacturer_trusted: false,
      policy_trusted: false,
      production_trusted: false
    }' > "$output/addon-static.json"

test ! -e "$preflight/addon.key"
test ! -e "$output/addon.key"

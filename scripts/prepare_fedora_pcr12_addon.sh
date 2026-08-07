#!/usr/bin/env bash
# Build one run-local signed cmdline addon and enroll only its public test key.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 SOURCE_OVMF_VARS OUTPUT_OVMF_VARS OUTPUT_DIR" >&2
    exit 2
fi

source_vars=$(realpath "$1")
output_vars=$(realpath -m "$2")
output=$(realpath -m "$3")
source_reference=${ATTESTOS_FEDORA_IMAGE_REFERENCE:?missing immutable image reference}
policy='lockdown=confidentiality module.sig_enforce=1'
owner_guid='9d4f4ef8-5f6d-4a73-9b2c-90c8e6c2e6f1'
work=$(mktemp -d -p /tmp attestos-pcr12-addon.XXXXXX)
mkdir -p "$output" "$(dirname "$output_vars")"

for command in jq objcopy objdump openssl podman sbverify sha256sum virt-fw-vars; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT

openssl req -new -newkey rsa:2048 -nodes -x509 -sha256 -days 1 \
    -subj '/CN=attestos PCR12 disposable canary/' \
    -keyout "$work/addon.key" \
    -out "$work/addon.pem" >/dev/null 2>&1

sudo podman run \
    --rm \
    --network=none \
    -e "ATTESTOS_POLICY=$policy" \
    -v "$work:/work:rw,Z" \
    "$source_reference" \
    sh -eu -c '
        ukify=$(command -v ukify || true)
        if test -z "$ukify"; then
            ukify=/usr/lib/systemd/ukify
        fi
        test -x "$ukify"
        exec "$ukify" build \
            --secureboot-private-key=/work/addon.key \
            --secureboot-certificate=/work/addon.pem \
            --cmdline="$ATTESTOS_POLICY" \
            --sbat="sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
attestos-addon,1,attestos PCR12 canary,attestos-addon,1,https://github.com/plunder707/attestos" \
            --output=/work/10-attestos-policy.addon.efi
    '
sudo chown -R "$(id -u):$(id -g)" "$work"

addon="$work/10-attestos-policy.addon.efi"
test -s "$addon"
sbverify --cert "$work/addon.pem" "$addon" >/dev/null
if objdump -h "$addon" | awk '$2 == ".linux" {found=1} END {exit !found}'; then
    echo "cmdline addon unexpectedly contains a .linux section" >&2
    exit 1
fi
if ! objdump -h "$addon" | awk '$2 == ".sbat" {found=1} END {exit !found}'; then
    echo "cmdline addon does not contain the required .sbat section" >&2
    exit 1
fi
objcopy --dump-section .cmdline="$work/addon.cmdline" "$addon"
python3 - "$work/addon.cmdline" "$policy" <<'PY'
import sys
from pathlib import Path

actual = Path(sys.argv[1]).read_bytes().rstrip(b"\0").decode("utf-8")
if actual != sys.argv[2]:
    raise SystemExit(f"addon command line mismatch: {actual!r}")
PY

python3 scripts/mutate_pe_cmdline.py \
    --input "$addon" \
    --output "$work/10-attestos-policy.tampered.addon.efi" \
    --receipt "$work/addon-mutation.json" >/dev/null
if sbverify --cert "$work/addon.pem" "$work/10-attestos-policy.tampered.addon.efi" \
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
    "$work/10-attestos-policy.tampered.addon.efi" \
    "$output/10-attestos-policy.tampered.addon.efi"
install -m 0644 "$work/addon.pem" "$output/addon-public.pem"
install -m 0644 "$work/addon-mutation.json" "$output/addon-mutation.json"
rm -f "$work/addon.key"

jq -n \
    --arg source_reference "$source_reference" \
    --arg policy "$policy" \
    --arg owner_guid "$owner_guid" \
    --arg addon_sha256 "$(sha256sum "$addon" | cut -d' ' -f1)" \
    --argjson addon_size "$(stat -c %s "$addon")" \
    --arg tampered_sha256 "$(sha256sum "$work/10-attestos-policy.tampered.addon.efi" | cut -d' ' -f1)" \
    --arg certificate_sha256 "$cert_sha256" \
    --arg source_vars_sha256 "$(sha256sum "$source_vars" | cut -d' ' -f1)" \
    --arg extended_vars_sha256 "$(sha256sum "$output_vars" | cut -d' ' -f1)" \
    --argjson original_certificate_count "$(wc -l < "$work/original-cert-hashes")" \
    --argjson extended_certificate_count "$(wc -l < "$work/extended-cert-hashes")" \
    --slurpfile mutation "$work/addon-mutation.json" \
    '{
      format: "attestos.fedora_pcr12_addon_static/v1",
      purpose: "disposable_pcr12_addon_harness_only",
      source_reference: $source_reference,
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

test ! -e "$output/addon.key"

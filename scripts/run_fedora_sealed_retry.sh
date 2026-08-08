#!/usr/bin/env bash
# Retry a receipt-less TCG timeout once while preserving every boot attempt.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 DISK_QCOW2 OUTPUT_DIR" >&2
    exit 2
fi

disk=$(realpath "$1")
output=$(realpath -m "$2")
runner=${ATTESTOS_FEDORA_BOOT_RUNNER:-scripts/run_fedora_sealed_positive_control.sh}
max_attempts=2
source_sha256=$(sha256sum "$disk" | cut -d' ' -f1)
attempts_dir="$output/attempts"
records="$output/.boot-attempts.jsonl"
rm -rf "$attempts_dir"
mkdir -p "$attempts_dir"
rm -f \
    "$output/boot-attempts.json" \
    "$output/boot-input.json" \
    "$output/guest-evidence.json" \
    "$output/serial.log" \
    "$output/console-driver.log" \
    "$output/debugfs.log"
: > "$records"

write_manifest() {
    local selected=$1
    jq -s \
        --arg source_disk_sha256 "$source_sha256" \
        --argjson selected_attempt "$selected" \
        --argjson max_attempts "$max_attempts" \
        '{
          format: "attestos.fedora_sealed_boot_attempts/v1",
          source_disk_sha256: $source_disk_sha256,
          max_attempts: $max_attempts,
          selected_attempt: $selected_attempt,
          attempts: .,
          manufacturer_trusted: false,
          policy_trusted: false,
          production_trusted: false
        }' "$records" > "$output/boot-attempts.json"
}

promote_attempt() {
    local attempt_dir=$1
    for name in boot-input.json guest-evidence.json serial.log console-driver.log debugfs.log; do
        [[ -f "$attempt_dir/$name" ]] && cp "$attempt_dir/$name" "$output/$name"
    done
    return 0
}

last_rc=1
for attempt in $(seq 1 "$max_attempts"); do
    attempt_dir="$attempts_dir/attempt-$attempt"
    attempt_disk="$output/.attempt-$attempt.qcow2"
    mkdir -p "$attempt_dir"
    cp --reflink=auto --sparse=always "$disk" "$attempt_disk"
    copied_sha256=$(sha256sum "$attempt_disk" | cut -d' ' -f1)
    [[ "$copied_sha256" == "$source_sha256" ]] || {
        echo "attempt disk copy changed immutable input" >&2
        exit 1
    }

    set +e
    bash "$runner" "$attempt_disk" "$attempt_dir"
    rc=$?
    set -e
    rm -f "$attempt_disk"
    receipt=false
    [[ -s "$attempt_dir/guest-evidence.json" ]] && receipt=true
    retry_eligible=false
    [[ $rc -eq 124 && "$receipt" == false ]] && retry_eligible=true
    jq -n \
        --argjson attempt "$attempt" \
        --argjson exit_status "$rc" \
        --argjson guest_receipt_present "$receipt" \
        --argjson retry_eligible "$retry_eligible" \
        --arg disk_sha256 "$copied_sha256" \
        '{
          attempt: $attempt,
          exit_status: $exit_status,
          guest_receipt_present: $guest_receipt_present,
          retry_eligible: $retry_eligible,
          disk_sha256_before_boot: $disk_sha256
        }' >> "$records"

    if [[ $rc -eq 0 ]]; then
        [[ "$receipt" == true ]] || {
            echo "successful QEMU exit produced no guest receipt" >&2
            write_manifest null
            exit 1
        }
        promote_attempt "$attempt_dir"
        write_manifest "$attempt"
        rm -f "$records"
        exit 0
    fi

    last_rc=$rc
    if [[ "$retry_eligible" != true || $attempt -eq $max_attempts ]]; then
        write_manifest null
        rm -f "$records"
        exit "$last_rc"
    fi
    echo "receipt-less TCG timeout; preserving attempt $attempt and retrying once" >&2
done

write_manifest null
rm -f "$records"
exit "$last_rc"

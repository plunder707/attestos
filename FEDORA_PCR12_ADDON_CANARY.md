# Fedora PCR 12 Signed Add-on Canary

Status: replicated harness pass. It grants no attestation trust, installation
authority, or publication authority.

## Question

Can the unchanged upstream-signed Fedora UKI load one separately signed
command-line add-on, apply `lockdown=confidentiality module.sig_enforce=1`, and
measure it into SHA-256 PCR 12 without changing the UKI or PCR 11?

systemd v259 documents `/loader/addons/*.addon.efi` as signed PE companion
files. `systemd-stub` verifies accepted add-ons against UEFI DB, Shim DB, or
MOK, appends their `.cmdline` sections after the UKI command line, and measures
the add-on parameters into PCR 12. The v259.5 source sets
`StubPcrKernelParameters` only when its aggregate parameter-measurement state
is positive; the variable is not a unique receipt for one add-on measurement.

The add-on is assembled with the digest-pinned Fedora v259.5 `ukify` and stub,
then signed by a SHA-pinned Fedora v259.5 `systemd-sbsign` inside a disposable
signer image built from a digest-pinned Fedora base. The signer runs without
network access while the private key is mounted. Signing happens exactly once
in the early preflight; the private key is deleted before image construction,
and the exact validated public artifacts are carried into all later gates. A
complete, in-bounds PE certificate table is required before the signed artifact
or its byte-bounded tamper negative can enter any boot arm.

## Frozen Arms

Every arm uses the same immutable Fedora source and installer, the same
byte-identical upstream UKI, the same OVMF code, a copy of the same extended
OVMF variable store, a fresh swtpm, TCG acceleration, and no guest network.

| Arm | ESP add-ons | Expected result |
| --- | --- | --- |
| baseline | none | UKI boots; PCR 11 nonzero; PCR 12 zero; parameter EFI variable unset |
| signed-1 | one valid signed add-on | policy present; PCR 12 equals the exact load-options replay |
| signed-2 | the identical valid add-on | same PCR 11 and PCR 12 as signed-1 |
| tampered | same file with `.cmdline` bytes changed after signing | UKI boots; add-on remains on disk but is ignored; baseline PCR 12 and policy |

The run-local public certificate is added to a disposable copy of UEFI DB for
all four arms. The preparer proves the original certificates remain present,
the new certificate appears exactly once, and no private key is persisted or
uploaded.

The add-on is authored with Fedora's exact `systemd-ukify-259.5-1.fc44` and
matching `systemd-boot-unsigned-259.5-1.fc44` add-on stub. Both RPMs and both
extracted files are SHA-256 pinned before key generation. This avoids assuming
that the immutable runtime image also contains build tooling.

The signer is a separate toolchain boundary because the immutable Silverblue
runtime's signer produced a truncated small-PE output during development even
though it successfully signed the full UKI control. Its Fedora base, exact
`systemd` and `systemd-shared` RPMs, and `systemd-sbsign` binary are all pinned
and recorded. The signed add-on must also survive strict PE parsing, static
signature verification, firmware admission, and a post-signature tamper
negative; signer exit status alone is never evidence of a valid artifact.
The bind-mounted signing workspace is created beside the eventual evidence
output so the signer and host parser observe the same filesystem; a runner
`/tmp` handoff that produced an inconsistent small signed PE during development
is excluded from the frozen path. A second signer invocation is also excluded:
the artifact that passes preflight is the artifact installed in both signed
arms.

Section inspection is performed on a scratch copy. GNU `objcopy
--dump-section` may rewrite a PE input in place and discard its Authenticode
overlay when no output path is supplied; the validated signed add-on is never
passed to that operation directly.

## Admission Gates

All gates must pass:

1. the upstream UKI remains byte-identical in every arm;
2. all four guests boot through Secure Boot, systemd-boot, and systemd-stub;
3. PCR 11 is nonzero and byte-identical across all arms;
4. baseline has no add-on, no policy tokens, no parameter EFI variable, and
   zero PCR 12;
5. both signed arms contain the exact statically inspected add-on;
6. both signed arms report each policy token exactly once;
7. both signed-arm PCR 12 values exactly equal the TPM replay of systemd-stub's
   UTF-16LE/NUL-terminated load-options measurement;
8. signed-arm PCR 12 is nonzero and byte-identical across two fresh TPM boots;
9. the tampered file is the exact statically rejected mutation;
10. the tampered guest still boots the unchanged UKI but does not apply or
    measure the add-on; and
11. manufacturer, policy, and production trust remain explicitly false.

Each boot may retry once only after exit `124` when no bounded guest receipt can
be extracted. The retry uses a byte-identical disposable copy of the same arm
disk, a fresh swtpm state, and a fresh copy of the same firmware variables. All
attempt logs and the retry decision remain in the artifact. Firmware rejection,
other failures, and any completed receipt are never retried.

The tampered add-on is rejected by `systemd-stub`, not by firmware as a boot
target. Requiring the whole boot to fail would test the wrong component.

## Stop Rules

- If PCR 11 differs between arms, stop: the add-on is not additive under this
  harness. Do not tune around the result.
- If the tampered add-on affects the command line or PCR 12, stop: signature
  enforcement failed.
- If the signed arms disagree on PCR 12, stop: the measurement is not stable
  enough for an exact policy.
- Missing or conflicting evidence is a failed gate, never a semantic pass.

Run `31230053715` reached every arm but failed the original
`StubPcrKernelParameters=12` gate. Its receipts showed both policy tokens
exactly once and the same nonzero PCR 12 in both signed boots, while the
tampered arm was rejected and returned to the baseline. Source inspection then
showed that the EFI variable reports aggregate parameter-measurement state,
not the individual add-on event. The replacement gate is stricter and directly
replays the measured bytes:

```text
SHA256(32 zero bytes ||
       SHA256(UTF-16LE("lockdown=confidentiality module.sig_enforce=1" + NUL)))
= ca62dd5f79fa336fadc40c4b2f6ef3b1870d58d271fd01b6f96a758f25cda8f5
```

The EFI variable remains in every guest receipt as a diagnostic. This checker
correction does not retroactively turn run `31230053715` green; a fresh run and
same-head replication are required.

## Result

The corrected contract passed on both
[attempt 1](https://github.com/plunder707/attestos/actions/runs/31234464516/attempts/1)
and
[attempt 2](https://github.com/plunder707/attestos/actions/runs/31234464516/attempts/2)
from branch commit `e897e51`. All 21 gates passed in both attempts, with no
infrastructure retry selected in either one.

Stable causal evidence across attempts:

```text
loaded UKI  6fe6684e9f3ad09008e84e63424bfa4faf2ec2d40214f7bd314c8fb9b9130b50
PCR 11      44792fb514e1c22a77758a89bd1459727a80534e7963a708c6574f8d895ed6d4
baseline 12 0000000000000000000000000000000000000000000000000000000000000000
signed 12   ca62dd5f79fa336fadc40c4b2f6ef3b1870d58d271fd01b6f96a758f25cda8f5
tampered 12 0000000000000000000000000000000000000000000000000000000000000000
```

The run-local certificate changed between attempts, so the signed add-on file
hash changed. That is expected. The policy bytes and exact PCR 12 replay did
not change. Receipt SHA-256 values were
`dd82647ff52c3abcb424f629f9ec1b64fa8908a347f6e2def81d4024f543bfae`
and `c5e822aa3a7ca4c99d2a8fb52ee5c2dc559f15f3f2c1620fdcbb658c1e7676c8`.

## Boundary

This canary uses a software TPM and a run-local key enrolled into a disposable
firmware store. Guest observations are not an externally verified quote or
event-log replay. Add-on filenames are not protected by the PE signature;
ordering changes must therefore be detected by an expected PCR 12 policy.

Even a green result establishes only that this mechanism works in the bounded
harness. Hardware provenance, manufacturer trust, key enrollment UX,
revocation, update and rollback policy, privacy, transport binding, and vendor
acceptance remain separate gates.

# UKI Base Decision

Date: 2026-08-07

Decision status: Fedora sealed Atomic is the current UKI harness substrate.
No production or gaming distribution base has been selected.

## Decision

Do not advance standard Bluefin LTS as the positive UKI candidate. Retain it
as a measured negative control. Use the digest-pinned Fedora sealed Silverblue
artifact only to test loaded-UKI, Secure Boot, PCR 11, and signed PCR 12 add-on
contracts.

This is an evidence-harness decision, not a distribution decision. Bazzite
remains the gaming product hypothesis and remains held from policy admission.

## Evidence

The Bluefin experiment verified its immutable OCI provenance and found a
signed UKI-shaped artifact during static inspection. The booted guest then
proved that firmware selected shim/GRUB and loaded separate kernel and initramfs
artifacts instead of that UKI. Package presence and static signature success
therefore did not satisfy loaded-artifact identity.

The Fedora sealed Atomic positive control subsequently proved the missing
joins on one frozen input:

1. immutable source and version-matched installer provenance;
2. exactly one statically inspected upstream-signed UKI;
3. firmware-selected path and loaded-file SHA-256 equality;
4. Secure Boot rejection after an unsigned `.cmdline` mutation; and
5. a nonzero PCR 11 from the loaded UKI.

The control is documented in
[`FEDORA_SEALED_POSITIVE_CONTROL.md`](FEDORA_SEALED_POSITIVE_CONTROL.md). It
keeps manufacturer, policy, and production trust false.

## Policy Mechanism Control

The replicated bounded experiment leaves the upstream Fedora UKI byte-identical
and installs one separately signed systemd command-line add-on. systemd-stub
authenticates the add-on, appends its policy, and measures the load options into
PCR 12. Baseline, two signed boots, and a post-signature tamper negative are
specified in [`FEDORA_PCR12_ADDON_CANARY.md`](FEDORA_PCR12_ADDON_CANARY.md).
It passed twice in run `31234464516` while all trust flags remained false.

This mechanism avoids rebuilding the upstream UKI merely to add attestos policy.
It does not resolve how an end-user system enrolls, rotates, revokes, or recovers
the add-on signing key.

## Why Bazzite Is Held

Bazzite's build excludes the UKI kernel packages and the booted mechanics
canary exposed no systemd-stub identity. Its intended policy arguments were
absent, and PCRs 11 and 15 remained zero. The source layer therefore produces
valid raw TPM mechanics but no admitted operating-system policy.

Retrofitting another boot path would create a security-critical divergence
from the gaming image being evaluated. That work should start only after the
Fedora harness has frozen the evidence contract and a relying party has stated
which key hierarchy and residual risks it would accept.

## Remaining Admission Gates

A policy-capable candidate still needs all of the following:

1. the attestos agent integrated before the sealed image is produced;
2. an externally verified quote over the frozen PCR selection;
3. event-log replay joined to the quoted snapshot;
4. signed update, rollback, revocation, and minimum-version policy;
5. hardware EK/manufacturer validation;
6. relay resistance and privacy; and
7. explicit relying-party acceptance.

Until those checks pass, `manufacturer_trusted=false`, `policy_trusted=false`,
and `production_trusted=false` remain mandatory.

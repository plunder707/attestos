# Fedora Sealed UKI Positive Control

Status: development-only harness experiment. It grants no attestation trust.

## Question

Can the existing admission harness distinguish a real systemd-boot UKI boot
from the Bazzite and standard Bluefin shim/GRUB negative controls without
rewriting or substituting the upstream signed boot artifact?

The canary passes only if one immutable Fedora sealed image produces all of
these joined observations:

1. the source OCI manifest verifies against the pinned upstream Cosign key;
2. the version-matched installer OCI manifest verifies against that key;
3. the installed ESP contains systemd-boot and exactly one UKI;
4. the original UKI verifies against the pinned upstream development Secure
   Boot key before any section inspection;
5. changing only its embedded `.cmdline` bytes, while preserving its PE
   certificate table and file size, causes Secure Boot firmware to reject a
   throwaway copy;
6. the unchanged upstream-signed guest reports both `systemd-boot` and
   `systemd-stub` EFI variables;
7. `StubImageIdentifier` names the same upstream-signed UKI inspected
   before boot;
8. the loaded file's SHA-256 equals the preboot SHA-256; and
9. systemd-stub declares PCR 11 and the guest reads a nonzero SHA-256 PCR 11.

File presence, package presence, a nonzero PCR by itself, or a matching hash
without the loaded-path identity join cannot pass.

## Frozen Inputs

- Upstream source commit:
  `a5daa80297a062e2ffa8f018264de3594842fac4`
- Successful upstream build run:
  `24482575655`
- Fedora 44 Silverblue sealed image:
  `quay.io/fedora-atomic-desktops-sealed/silverblue@sha256:d0e34c45cb33adbeee3ada65b33addbb30297eb938bdb7af35c67b63b7028eb7`
- Installer image: the same immutable Silverblue sealed image and digest above.
- Upstream Secure Boot PK PEM SHA-256:
  `ebb379ce8b02d49ba1969935793b282e01e0c208b769d06a0674164a972e0bab`
- Upstream Secure Boot KEK PEM SHA-256:
  `c264c2d7b9de792e778ba4cd8541ffb51d7c664e7b1f785fde9b613ae54f0537`
- Upstream key-owner GUID SHA-256:
  `94d712c748d49cfcd62ed3f8e1eb519fb0c8009340d30a29f26f80e75bc433f9`
- Fedora 44 EDK2 NVR current at the image creation timestamp:
  `edk2-20260213-4.fc44`
- Fedora Koji `edk2-ovmf` RPM SHA-256:
  `09aaf8eea949070e864233d09480a7e88cb3b51f58c8adb9bb2e2176bddb0083`
- Upstream Fedora-generated OVMF variable store SHA-256:
  `07029be230ad284b910e94e16dbd05f5b495f194dea90629bfdf94cb390b853b`
- Vendored Cosign public key SHA-256:
  `454e4bc8d59d3c356d193a006d2dbf98a2cbdac6db7e3320da2c57590b6e3ba4`
- Vendored Secure Boot DB certificate SHA-256:
  `c23207f1db85578cb0a5f56fd3ca7ca1082f7a85f924ac85ac1cb9da7e2c176a`

The pinned image was created at `2026-04-15T23:00:51.271335521Z` inside the
successful upstream run above. The registry tag history, image creation time,
run source commit, Secure Boot PK/KEK/db certificates, owner GUID, and Cosign
key form the frozen provenance packet. The workflow verifies the image manifest
and signature again before installation.

The upstream variable store was generated against Fedora's EDK2 build and must
not be mixed with another distribution's OVMF code. A failed run proved that an
Ubuntu code/template pair still rejected this unusually large composefs UKI
despite containing the exact upstream db certificate. The canary therefore
extracts the exact Fedora 44 `edk2-ovmf` build that was current in Koji when the
image was created and pairs its firmware code with the upstream project's own
frozen Fedora-generated variable store. The workflow extracts that store to
verify all three PK/KEK/db DER fingerprints before boot. The RPM, firmware code,
source variable store, and converted raw-store hashes are preserved in the
receipt.

Earlier runs appeared to show the matched firmware rejecting the original UKI.
That result is invalidated by a harness mutation: GNU `objcopy --dump-section`
rewrites its input when no output PE is supplied. The static inspector verified
the signature, then truncated 7,344 bytes containing the certificate table
while extracting `.cmdline`; firmware correctly rejected the damaged file.
Every dump-only inspection now operates on a disposable copy. The negative arm
mutates `.cmdline` bytes in place with a PE-aware parser and proves that the
certificate table and total file size remain unchanged. No run-local signing
key, replacement UKI, or modified firmware trust store exists in the active
canary.

This historical candidate replaces the August 3 image after three fail-closed
runs proved that image internally inconsistent for installation. Its UKI
contained composefs digest `6bd4...f996b43`, while both its own bootc and the
exact tools image used during its build computed storage-ingest digest
`1df3...f839de`. Matching the bootc version was therefore tested and disproved
as a sufficient repair. This is the upstream directory-walk versus
storage-ingest defect tracked in `bootc-dev/bootc#2194` and related format work
in `bootc-dev/bootc#2334`; no digest check is bypassed here.

The April candidate predates that regression window and uses the same immutable
image for both source and installer. Its first canary completed the composefs
installation, then exposed a harness defect: the inspector searched only
`EFI/Linux/*.efi`, while this image's documented layout nests its composefs UKI
under `EFI/Linux/bootc/`. Discovery is now recursive below `EFI/Linux`; it still
requires exactly one UKI and never copies or substitutes one after installation.

The upstream `bcvk v0.10.0` disk path was also tested, but that version requires
`/dev/kvm` for its ephemeral installer VM and cannot run on a standard GitHub-
hosted runner. That infrastructure failure supplied no image or admission
evidence and is not used as a bypass.

## Isolation

- GitHub `contents: read` only;
- disposable Ubuntu runner;
- QEMU TCG, never KVM;
- fresh swtpm state;
- no guest NIC;
- no host or physical TPM;
- no package, OIDC, signing, or publication authority; and
- bounded logs and receipts, with the disk and TPM state excluded.

The disposable encrypted root uses the intentionally public passphrase in
`canary/fedora-sealed/public-luks-passphrase.txt`. Disk creation and the QMP
console driver consume that same file. It exists only to cross the interactive
initramfs boundary in CI and provides no confidentiality or trust claim.

The evidence probe is carried on a second block device. A tracked one-shot unit
and the probe script are installed in the machine-local mutable `/etc` only
after static UKI inspection; they never enter the sealed `/usr` tree or alter
the signed UKI whose identity is measured into PCR 11. The unit reads EFI
variables, hashes the firmware-identified UKI, reads PCR 11 directly from the
guest TPM device, writes one receipt back to the probe disk, and powers off.
The unit and script hashes are preserved in a separate instrumentation receipt.

## Non-authority

Even a green result proves only that the harness can observe a positive UKI
case. The upstream key is public development material with no manufacturer or
policy authority. The upstream image masks several systemd TPM
measurement services, and does not embed the attestos policy. The validator
requires `manufacturer_trusted=false`, `policy_trusted=false`, and
`production_trusted=false` in every input and output.

The next policy experiment may start only after this control passes. It must
build the attestos agent and policy before sealing a new UKI, use ephemeral
keys, replay the relevant event logs, and keep every production authority gate
closed.

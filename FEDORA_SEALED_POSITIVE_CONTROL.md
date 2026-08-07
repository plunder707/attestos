# Fedora Sealed UKI Positive Control

Status: development-only harness experiment. It grants no attestation trust.

## Question

Can the existing admission harness distinguish a real systemd-boot UKI boot
from the Bazzite and standard Bluefin shim/GRUB negative controls?

The canary passes only if one immutable Fedora sealed image produces all of
these joined observations:

1. the source OCI manifest verifies against the pinned upstream Cosign key;
2. the version-matched installer OCI manifest verifies against that key;
3. the installed ESP contains systemd-boot and exactly one UKI;
4. that UKI verifies against the pinned upstream development Secure Boot key;
5. changing its embedded `.cmdline` invalidates the PE signature;
6. the booted guest reports both `systemd-boot` and `systemd-stub` EFI variables;
7. `StubImageIdentifier` names the same UKI inspected before boot;
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
- Disk builder: upstream-tested `bcvk v0.10.0`, release asset SHA-256
  `444e54422cac41447d2a95cc5c64794070b9eb6e42ef0c9d1f7582e29e94e341`.
- Upstream OVMF variable store SHA-256:
  `07029be230ad284b910e94e16dbd05f5b495f194dea90629bfdf94cb390b853b`
- Vendored Cosign public key SHA-256:
  `454e4bc8d59d3c356d193a006d2dbf98a2cbdac6db7e3320da2c57590b6e3ba4`
- Vendored Secure Boot DB certificate SHA-256:
  `c23207f1db85578cb0a5f56fd3ca7ca1082f7a85f924ac85ac1cb9da7e2c176a`

The pinned image was created at `2026-04-15T23:00:51.271335521Z` inside the
successful upstream run above. The registry tag history, image creation time,
run source commit, OVMF variable-store digest, Secure Boot certificate, and
Cosign key form the frozen provenance packet. The workflow verifies the image
manifest and signature again before installation.

This historical candidate replaces the August 3 image after three fail-closed
runs proved that image internally inconsistent for installation. Its UKI
contained composefs digest `6bd4...f996b43`, while both its own bootc and the
exact tools image used during its build computed storage-ingest digest
`1df3...f839de`. Matching the bootc version was therefore tested and disproved
as a sufficient repair. This is the upstream directory-walk versus
storage-ingest defect tracked in `bootc-dev/bootc#2194` and related format work
in `bootc-dev/bootc#2334`; no digest check is bypassed here.

The April candidate predates that regression window and uses the same immutable
image for both source and installer. A first canary proved the composefs install
completed, but our hand-built `to-filesystem --skip-finalize` wrapper left no UKI
on the ESP. That was a harness defect: the frozen upstream README documents
`bcvk v0.10.0` and `bcvk to-disk` as its tested disk path. The canary now uses
that exact checksum-pinned release and command contract. If bcvk cannot place
the signed UKI, the experiment fails closed again; it never copies a UKI into
the ESP after installation.

## Isolation

- GitHub `contents: read` only;
- disposable Ubuntu runner;
- QEMU TCG, never KVM;
- fresh swtpm state;
- no guest NIC;
- no host or physical TPM;
- no package, OIDC, signing, or publication authority; and
- bounded logs and receipts, with the disk and TPM state excluded.

The evidence probe is carried on a second block device and invoked through the
debug console already enabled by the upstream development image. It reads EFI
variables, hashes the firmware-identified UKI, reads PCR 11 directly from the
guest TPM device, writes one receipt back to the probe disk, and powers off. It
does not install an agent or alter the sealed root.

## Non-authority

Even a green result proves only that the harness can observe a positive UKI
case. The upstream image uses development keys, masks several systemd TPM
measurement services, and does not embed the attestos policy. The validator
requires `manufacturer_trusted=false`, `policy_trusted=false`, and
`production_trusted=false` in every input and output.

The next policy experiment may start only after this control passes. It must
build the attestos agent and policy before sealing a new UKI, use ephemeral
keys, replay the relevant event logs, and keep every production authority gate
closed.

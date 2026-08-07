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
  `cbe45816bb166c9df97c0714014f3ea7bdffcdac`
- Fedora 44 Silverblue sealed image:
  `quay.io/fedora-atomic-desktops-sealed/silverblue@sha256:d60c9ab5f847858f3b316465ae2138e3080f3102ed69b13ffe8cf8f09e98608c`
- Fedora 44 tools image used to compute the sealed UKI's composefs digest:
  `quay.io/fedora-atomic-desktops-sealed/tools@sha256:927be1bd8673369c940305341764bdbb140c3a39d8546fd3891cb460affbcdc6`
- Upstream OVMF variable store SHA-256:
  `07029be230ad284b910e94e16dbd05f5b495f194dea90629bfdf94cb390b853b`
- Vendored Cosign public key SHA-256:
  `454e4bc8d59d3c356d193a006d2dbf98a2cbdac6db7e3320da2c57590b6e3ba4`
- Vendored Secure Boot DB certificate SHA-256:
  `c23207f1db85578cb0a5f56fd3ca7ca1082f7a85f924ac85ac1cb9da7e2c176a`

The upstream QCOW2 publication workflow has not produced this versioned disk:
its August 3 run stopped during `bcvk to-disk` before the ORAS push. This
repository therefore installs the pinned container into a fresh 20 GiB QCOW2
using the upstream partition and `bootc install to-filesystem` contract.

The August 3 upstream build computed the UKI digest with the separately built
tools image above (`bootc` build `202607302110.g73b4639e8`). The final image
contains Fedora `bootc` 1.16.6, which computes a different composefs digest and
correctly refuses that UKI. The canary therefore runs the install with the
exact signed tools image that created the digest. Both image references are
immutable, independently verified, and joined in the receipt; no digest check
is disabled.

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

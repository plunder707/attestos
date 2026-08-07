# attestos

**SOURCE MECHANICS PREVIEW. THE CURRENT BAZZITE CANARY BOOTED NO UKI AND
LEFT PCRS 11 AND 15 AT ZERO; THIS DOES NOT ATTEST THE OPERATING SYSTEM.**

Bazzite with a TPM boot attestation layer on top, so an anti-cheat vendor can
verify what the machine actually booted instead of checking whether the distro
name is on a list.

The mechanism, the threat model, and the vendor specification live in
[plunder707/attested-gaming](https://github.com/plunder707/attested-gaming).
This repository is the image that produces the evidence.

---

> ## STATUS: SOURCE MECHANICS PREVIEW. UKI/POLICY TRUST BLOCKED.
>
> GitHub Actions runs
> [31157890393](https://github.com/plunder707/attestos/actions/runs/31157890393)
> and [31159951490](https://github.com/plunder707/attestos/actions/runs/31159951490)
> built a Bazzite-derived QCOW2, booted it under QEMU/OVMF with swtpm and no
> guest network, provisioned persistent EK/AK handles, and verified a raw quote
> over SHA-256 PCRs 7, 11, 12, and 15 from inside the guest. Its bounded receipt
> has SHA-256 `ad5ef12592cb5f4d1dfa8f0da88148931d48f0e6018924b2de4c766e1523ddaf`.
> A separate verifier workflow
> [31160003873](https://github.com/plunder707/attested-gaming/actions/runs/31160003873)
> exercised this repository's final agent commit `b918392` against an isolated
> software TPM and passed AK enrollment, raw quote verification, replay
> rejection, signature-tamper rejection, and QEMU/OVMF TPM wiring.
>
> The booted result also confirms the Bazzite policy blocker: no UKI file or
> systemd-stub signal was present, the intended lockdown arguments were absent,
> and PCRs 11 and 15 remained zero. PCR 12 was also zero, but that is not an
> independent failure: the embedded UKI command line belongs to PCR 11, while
> PCR 12 records external command-line inputs and may correctly remain zero
> when none are supplied. Secure Boot key enrollment, UKI-backed command-line
> measurement, hardware provenance, event-log replay, transport binding, and
> boot-policy admission remain unsolved. Neither green run establishes a
> functioning production attestation system.
>
> This source is available for review and reproducible emulation. No GHCR
> image is published and it is not an installable trusted distribution.
>
> The separate standard Bluefin LTS experiment reached a stronger negative
> result in [run 31170696765](https://github.com/plunder707/attestos/actions/runs/31170696765):
> Secure Boot was enabled and a UKI candidate existed on disk, but firmware
> booted shim/GRUB plus a separate kernel and initramfs. No UKI was identified
> as loaded, PCRs 11 and 15 remained zero, and the policy command line was
> absent. Standard Bluefin LTS is therefore held rather than selected.

The completed Bazzite experiment is specified in
[`BOOTED_IMAGE_CANARY.md`](BOOTED_IMAGE_CANARY.md). Reproduction and source
build instructions are in [`BUILDING.md`](BUILDING.md). The next UKI
engineering candidate and its independent admission criteria are recorded in
[`UKI_BASE_DECISION.md`](UKI_BASE_DECISION.md).
The executable candidate contract is
[`UKI_ADMISSION_CANARY.md`](UKI_ADMISSION_CANARY.md).
The milestone order and stop rules are tracked in [`ROADMAP.md`](ROADMAP.md).

---

## What this adds to Bazzite

Nothing is removed and nothing is patched. Four things go in on top:

1. **`tpm2-tools` and `tpm2-tss`**, which the agent needs at runtime.
2. **A kernel command line** at `/usr/lib/attestos/cmdline` carrying
   `lockdown=confidentiality` and `module.sig_enforce=1`.
3. **`attestos-provision`**, a one-shot unit that creates distinct persistent
   RSA EK and AK identities inside the TPM and reads the endorsement
   certificate out of NV storage when one exists.
4. **`attestos-agent`**, socket-activated on loopback, which answers a
   strict `attestos.tpm/v1` identity, activation, or quote challenge with raw
   TPM evidence. The agent never returns a trust verdict.

## Why the base is Bazzite

Bazzite is Fedora-derived, and the Fedora family is what anti-cheat whitelists
currently block. Proving attestation works here is the case worth proving.
Building on SteamOS would demonstrate nothing, because SteamOS is already
allowed through, so a successful demo there would earn access it already has.

Bazzite is also designed to be layered. It is an OCI image, so this repo is a
Containerfile and a GitHub Action rather than a distribution with mirrors and
installers behind it.

## The command line has to be sealed inside the UKI

This is the part that decides whether any of it means anything.
`lockdown=confidentiality` blocks `/dev/mem`, kprobes against a running
kernel, and unsigned module loading. That guarantee is worth nothing if the
command line lives in a bootloader config the user can edit, because then a
cheater deletes the argument, boots a kernel whose measurement has not
changed, and attests perfectly clean while loading whatever they want.

A Unified Kernel Image binds kernel, initrd, and command line into one signed
PE binary measured into PCR 11, so changing any part moves the measurement.

**Bazzite does not do UKI, and this is now confirmed rather than suspected.**
Its Containerfile actively excludes the UKI kernel packages:

```
dnf5 -y config-manager setopt "*fedora*".exclude="mesa-* kernel-core-* \
    kernel-modules-* kernel-uki-virt-* steam"
```

`systemd-ukify` appears nowhere in the repository. So the `cmdline` file this
image ships is currently a declaration of intent and nothing more: without a
UKI there is nothing sealing it, a user can edit it at the bootloader, and
PCR 11 does not measure what the design assumes it measures.

Fixing this is not a line in `build.sh`. It means installing `systemd-ukify`,
generating and signing a UKI, and redirecting the boot path away from the
kernel handling Bazzite already does, against a base that excludes the UKI
packages on purpose. That is a change to how the image boots, not a layer on
top of it.

The source investigation now narrows the practical choices:

1. Do the UKI work on Bazzite anyway and accept the divergence from the base.
2. Move to a CentOS bootc-derived base that carries a prebuilt UKI. Bluefin
   LTS is the leading engineering candidate because its current build
   explicitly installs `kernel-uki-virt`, and upstream bootc has landed sealed
   UKI/composefs machinery. This is a candidate, not a trust result.
3. Find a measurement that does not depend on a UKI. Harder, because the
   whole point of the UKI is that it seals a command line the user would
   otherwise be able to edit.

## The Secure Boot problem, unsolved

A third-party kernel is not signed by Microsoft's UEFI CA, so PCR 7 will not
say what it says on a stock distribution. The options are:

- **MOK enrollment**, where the user enrols a Machine Owner Key through a blue
  firmware screen on first boot. Universal Blue already does this for
  out-of-tree kernel modules, so the machinery exists, but it changes the
  claim from "Microsoft vouches for this kernel" to "the user explicitly
  trusts this key", and a vendor has to decide whether that is acceptable.
- **A Microsoft-signed shim**, which is the path a real distribution takes and
  is a review process rather than a form.
- **User-owned PK and KEK**, which gives full control and almost no adoption.

There is no good answer here yet. It is the most likely place the whole plan
stalls, and it is a question for a vendor before it is a question for an
engineer.

## Installing it

There is no supported installation command yet. In particular,
`ghcr.io/plunder707/attestos:latest` is not published. The current preview is
for source review and isolated QEMU/swtpm reproduction only. See
[`BUILDING.md`](BUILDING.md).

## Layout

```
Containerfile            base image and the single RUN that calls build.sh
build_files/build.sh     the attestation layer
system_files/            agent, provisioning script, systemd units
image-template.env       image name and registry organisation
.github/workflows/       build-only and isolated evidence canaries
Justfile                 local build and test targets
```

Everything outside `build_files/` and `system_files/` came from
[ublue-os/image-template](https://github.com/ublue-os/image-template) and is
their work.

## What still has to be answered

- Does the image build at all. Confirmed for commit `14e3a21` by GitHub Actions
  run `31143048491`; the build emitted two non-fatal DNF-state lint warnings.
- How a verifier turns the agent's runtime `bootc status` deployment claim
  into verified image identity. The claim is metadata, not signed authority;
  on systems without `bootc` it is explicitly `unavailable`.
- The Bazzite-derived QCOW2 passes the isolated mechanics canary, but its
  negative UKI and lockdown observations hold it from policy admission.
- Whether Bluefin LTS/CentOS bootc actually boots the intended signed UKI with
  the attestos command line embedded and measured. Package presence alone is
  insufficient.
- Is PCR 15 populated the way the design assumes on a bootc root.
- Does MOK enrollment produce a PCR 7 value stable enough to write a policy
  against.
- Would a vendor accept a MOK-enrolled key hierarchy at all.

The runtime measurement questions require QEMU with OVMF and swtpm, which
needs no additional hardware. The wiring and raw TPM protocol mechanics have
now passed there, but booting the built image and validating its event log and
policy remain separate experiments. Vendor acceptance requires a vendor
conversation.

## Licence

Apache-2.0, matching the template this is built from.

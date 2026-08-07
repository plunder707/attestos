# attestos

Bazzite with a TPM boot attestation layer on top, so an anti-cheat vendor can
verify what the machine actually booted instead of checking whether the distro
name is on a list.

The mechanism, the threat model, and the vendor specification live in
[plunder707/attested-gaming](https://github.com/plunder707/attested-gaming).
This repository is the image that produces the evidence.

---

> ## STATUS: CONTAINER BUILD VERIFIED. NOTHING HAS BOOTED.
>
> GitHub Actions run
> [31143048491](https://github.com/plunder707/attestos/actions/runs/31143048491)
> built and rechunked commit `14e3a21` successfully against the Bazzite base.
> The resulting image has never been booted, and no quote has ever been
> produced by the agent it installs. Secure Boot key enrollment and UKI-backed
> command-line measurement remain unsolved (see below), so a successful
> container build does not establish a functioning attestation system.
>
> Treat this as a work in progress, not a distribution.

---

## What this adds to Bazzite

Nothing is removed and nothing is patched. Four things go in on top:

1. **`tpm2-tools` and `tpm2-tss`**, which the agent needs at runtime.
2. **A kernel command line** at `/usr/lib/attestos/cmdline` carrying
   `lockdown=confidentiality` and `module.sig_enforce=1`.
3. **`attestos-provision`**, a one-shot unit that creates an attestation key
   inside the TPM at first boot and persists it, and reads the endorsement
   certificate out of NV storage.
4. **`attestos-agent`**, socket-activated on loopback, which answers a
   challenge with a TPM quote, the PCR values, and the TCG event log.

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

Three ways forward, none of them chosen yet:

1. Do the UKI work on Bazzite anyway and accept the divergence from the base.
2. Move to a base that already supports UKI. The bootc ecosystem does deal
   with `ukify`; Bazzite specifically does not.
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

Once there is a build worth installing, on an existing bootc system:

```
bootc switch ghcr.io/plunder707/attestos:latest
systemctl reboot
```

No ISO and no USB stick. The system pulls the delta, stages the new image, and
switches on reboot. `bootc rollback` returns you to the previous image.

## Layout

```
Containerfile            base image and the single RUN that calls build.sh
build_files/build.sh     the attestation layer
system_files/            agent, provisioning script, systemd units
image-template.env       image name and registry organisation
.github/workflows/       build, sign with cosign, push to GHCR
Justfile                 local build and test targets
```

Everything outside `build_files/` and `system_files/` came from
[ublue-os/image-template](https://github.com/ublue-os/image-template) and is
their work.

## What still has to be answered

- Does the image build at all. Confirmed for commit `14e3a21` by GitHub Actions
  run `31143048491`; the build emitted two non-fatal DNF-state lint warnings.
- How the running agent obtains a verified deployed-image identity. The current
  build writes `unknown` because an OCI image cannot embed its own final digest
  while it is being constructed.
- Which of the three UKI routes to take, given Bazzite excludes UKI kernels.
- Is PCR 15 populated the way the design assumes on a bootc root.
- Does MOK enrollment produce a PCR 7 value stable enough to write a policy
  against.
- Would a vendor accept a MOK-enrolled key hierarchy at all.

The runtime measurement questions require QEMU with OVMF and swtpm, which
needs no additional hardware. Vendor acceptance requires a vendor conversation.

## Licence

Apache-2.0, matching the template this is built from.

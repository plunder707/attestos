# Building and Reproducing Attestos

Attestos is currently a source mechanics preview. These instructions reproduce
the tested container and boot canaries; they do not create manufacturer,
boot-policy, relay, privacy, anti-cheat, or production trust.

## Recommended: GitHub disposable runner

The authoritative reproduction runs on a disposable GitHub-hosted runner. It
does not use KVM, the host TPM, or guest networking, and it does not publish an
image.

1. Fork this repository on GitHub.
2. Open **Actions > Booted image evidence canary**.
3. Choose **Run workflow** on the commit you want to test.
4. Inspect the job summary and download the bounded `receipt.json` and
   `serial.log` artifact.

A valid mechanics run must report exactly one guest marker, an EFI boot, a
fresh swtpm, persistent EK/AK handles, a valid raw quote over SHA-256 PCRs 7,
11, 12, and 15, and all trust flags set to `false`.

The current reference runs are:

- booted image: [31159951490](https://github.com/plunder707/attestos/actions/runs/31159951490)
- raw protocol seam: [31160003873](https://github.com/plunder707/attested-gaming/actions/runs/31160003873)

## Local source tests

Requirements: Python 3.10 or newer and `pytest`.

```bash
git clone https://github.com/plunder707/attestos.git
cd attestos
python3 -m pytest -q
bash -n \
  build_files/build.sh \
  scripts/run_booted_image_canary.sh \
  system_files/usr/bin/attestos-provision
```

The verifier is tested separately:

```bash
git clone https://github.com/plunder707/attested-gaming.git
cd attested-gaming
python3 -m pytest -q
```

The two repositories must carry byte-identical `protocol/v1/SPEC.md` and
`protocol/v1/attestation.schema.json` files. The verifier CI pins the exact
attestos commit and enforces that join.

## Local container build

Use a disposable Linux host or VM with Podman and `just`. The large bootc base
can consume tens of gigabytes of storage. WSL2 Docker may hit overlay-layer
limits with this base, so the GitHub runner is the supported reproduction path.

```bash
just check
just build attestos mechanics-preview
```

This creates a local OCI image only. It does not boot the image or prove TPM
evidence.

## Local QCOW2 build

This path requires rootful Podman, substantial free disk space, QEMU/OVMF,
swtpm, and the bootc image builder. Do not pass through a physical TPM.

```bash
just build-qcow2 localhost/attestos mechanics-preview
bash scripts/run_booted_image_canary.sh \
  output/qcow2/disk.qcow2 \
  canary-output
```

The runner uses QEMU TCG and `-nic none`. It copies OVMF variable state and
creates a fresh software TPM state directory for every invocation.

## What not to do

- Do not install this on a primary gaming machine.
- Do not pass a host TPM into the canary.
- Do not treat `quote_valid` or `same_tpm_ak` as boot-policy trust.
- Do not claim that any anti-cheat vendor accepts this protocol.
- Do not publish an image under `latest` until the signed-UKI and policy gates
  in `ROADMAP.md` pass.

The current Bazzite receipt is intentionally negative for policy admission:
there was no booted UKI signal, the lockdown arguments were absent, and PCRs
11, 12, and 15 were zero.

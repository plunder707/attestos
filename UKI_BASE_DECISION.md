# UKI Base Decision

Date: 2026-08-06

Decision status: selected for the next UKI engineering canary; not selected as
a production or gaming distribution base.

## Selection

Use `ghcr.io/projectbluefin/bluefin:lts` as the first UKI-capable desktop
candidate.

The choice is based on current source, not branding:

- Bluefin LTS derives from `quay.io/centos-bootc/centos-bootc`.
- Its kernel swap explicitly installs `kernel-uki-virt` alongside the kernel.
- The CentOS Stream kernel describes that package as a prebuilt default UKI
  for virtual machines.
- Upstream bootc has landed the UKI cleanup and sealed UKI/composefs build
  machinery that was previously only a tracker proposal.
- It remains a desktop-oriented bootc image, making it a closer engineering
  comparison than a minimal server image.

Primary source references:

- [Bluefin LTS Containerfile](https://github.com/projectbluefin/bluefin-lts/blob/main/Containerfile)
- [Bluefin LTS kernel swap](https://github.com/projectbluefin/bluefin-lts/blob/main/build_scripts/scripts/kernel-swap.sh)
- [bootc UKI cleanup, merged](https://github.com/bootc-dev/bootc/pull/2200)
- [bootc sealed-image design](https://github.com/bootc-dev/bootc/blob/main/docs/src/experimental-composefs.md)
- [CentOS Stream kernel UKI package](https://gitlab.com/redhat/centos-stream/rpms/kernel/-/blob/c10s/kernel.spec)

The former draft reference `ghcr.io/ublue-os/bluefin-lts:stable` is not the
published image location. The workflow resolves the `projectbluefin` tag to a
signed immutable multi-architecture index, verifies its exact GitHub Actions
OIDC identity, and then binds the build to the sole Linux/amd64 child digest in
that verified index.

Bluefin's published supply-chain page describes LTS as key-based. The exact
live `bluefin:lts` index resolved by the canary instead carried a Fulcio
certificate for the Bluefin LTS GitHub workflow and passed exact-identity OIDC
verification; the vendored repository key did not verify that object. This is
an observed documentation/artifact mismatch, so the canary binds to the exact
live index signature and preserves the signer identity rather than forcing the
documented mode. OCI provenance, index-to-child membership, PE signature,
booted Secure Boot state, and systemd-stub evidence remain separate gates.

## Why Bazzite is held

Bazzite remains the product hypothesis because gaming support is the point of
the project. It is held as the UKI implementation base because its build
explicitly excludes `kernel-uki-virt`. Retrofitting a different boot path would
create a security-critical fork from the behavior being evaluated.

## Admission test

Package presence is not sufficient. The Bluefin LTS candidate advances only
if a separately built and booted artifact proves:

1. the firmware booted the intended UKI;
2. the UKI signature chains to the canary's pinned test key;
3. `.cmdline` contains the exact approved arguments;
4. PCR and event-log evidence reflects that UKI;
5. a command-line or UKI substitution is rejected; and
6. update and rollback preserve the same invariants.

Until those checks pass, `policy_trusted=false` and the attestos base remains
unchanged.

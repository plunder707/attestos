# Booted Image Evidence Canary

Status: isolated experiment. No hardware, policy, or production authority.

This canary answers one bounded question: can a Bazzite-derived attestos QCOW2
boot under OVMF with an attached software TPM and produce internally
consistent, verifier-checkable evidence from inside the guest?

It deliberately does not answer whether that boot should be trusted.

## Execution boundary

The workflow `.github/workflows/booted-image-evidence-canary.yml`:

1. resolves the current Bazzite tag to an immutable OCI digest;
2. builds the normal attestos image without publishing it;
3. creates a local-only derivative that enables the otherwise-disabled probe;
4. converts that derivative to QCOW2 with the pinned bootc image builder;
5. boots it with QEMU TCG, OVMF, no network, and a fresh swtpm state directory;
6. validates exactly one bounded serial receipt; and
7. uploads only the receipt and serial log for 14 days.

The job uses a disposable GitHub-hosted runner. It requests only
`contents: read`, uses no secrets or OIDC, does not use KVM, does not publish a
container or disk image, and does not execute QEMU or swtpm on the developer's
machine.

## Required evidence

The canary passes only when the guest proves all of these observations:

- `/dev/tpmrm0` exists;
- the one-shot provisioner is active;
- persistent EK and AK handles are readable;
- required public state exists;
- the installed agent creates a raw quote that `tpm2_checkquote` verifies;
- the quote carries exactly SHA-256 PCRs 7, 11, 12, and 15;
- the TCG firmware event log is present and non-empty;
- `bootc status --json` identifies a booted deployment; and
- the guest booted through EFI.

The receipt records possible UKI signals and whether the intended lockdown
arguments appear in the running kernel command line. Those are observations,
not admission criteria for this first boot canary.

## Non-authorities

Even a green receipt must retain:

```text
manufacturer_trusted=false
policy_trusted=false
production_trusted=false
```

swtpm has no manufacturer provenance. A self-consistent event log is not an
event-log replay policy. An EFI boot is not proof that a signed UKI was used.
The current Bazzite-derived image is expected not to seal the attestos command
line in a UKI.

## UKI-capable base decision

The leading next candidate is a CentOS bootc-derived image such as Bluefin LTS,
not because its name grants trust, but because its current build explicitly
installs `kernel-uki-virt` and upstream bootc now contains the sealed UKI and
composefs machinery. This is only source-backed candidacy.

A base switch requires a separate canary proving all of the following from the
booted artifact:

1. the firmware booted the intended signed UKI;
2. the UKI embeds the exact approved command line;
3. changing the command line changes the measured policy evidence;
4. the image deployment identity is bound to signed or verified metadata;
5. update and rollback preserve those properties; and
6. the key hierarchy is acceptable to the eventual relying party.

Until then, Bazzite remains the product hypothesis and Bluefin LTS/CentOS bootc
remains the UKI engineering candidate.

The candidate selection and its admission test are frozen in
[`UKI_BASE_DECISION.md`](UKI_BASE_DECISION.md).

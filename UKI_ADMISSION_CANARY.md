# Bluefin LTS UKI Admission Canary

Status: development canary. It has no production, publication, graph, or
anti-cheat authority.

## Frozen candidate

The candidate is `ghcr.io/projectbluefin/bluefin:lts`, resolved to an immutable
multi-architecture index digest at run time. The workflow verifies that index
with the exact GitHub Actions OIDC identity currently recorded on the upstream
signature, then selects the sole Linux/amd64 child digest from that verified
index. Both immutable references are preserved in the audit artifact. A signed
index cannot authorize a child that is not a member of that index.

Bluefin's public documentation currently describes LTS signing as key-based,
but the resolved live index carried a GitHub OIDC certificate and did not
verify with the repository public key. The workflow follows the signed object
it actually resolves and pins the certificate identity exactly. A future mode
change fails closed and requires a reviewed contract update.

This is not a base-selection decision. It is the first executable test of the
claim that the CentOS bootc lineage provides a usable signed UKI path.

## Causal questions

1. Does the immutable base contain a UKI rather than only a package name?
2. Does the exact UKI selected at boot have a PE signature verifiable under a
   certificate carried by the independently signed base?
3. Does changing its `.cmdline` section invalidate that signature?
4. Can OVMF boot the disk with Secure Boot enabled?
5. Does the running guest expose systemd-stub evidence for the selected UKI?
6. Does the loaded UKI carry the exact attestos command line and produce the
   same policy arguments at runtime?
7. Can the firmware event log reproduce quoted PCR 7?
8. Is the systemd userspace event log present in the same locked quote
   snapshot?

## Admission gates

All gates in `scripts/validate_uki_admission.py` must pass. Static properties
are joined by the exact loaded-UKI SHA-256 digest; a signed decoy elsewhere in
the image cannot authorize a different loaded UKI. The first version
deliberately leaves full userspace event-log replay and update/rollback
invariants closed. A green base build or a signed file therefore cannot admit
the candidate by itself.

The workflow uploads static inspection, boot receipt, serial log, and admission
report even when the final admission gate fails. Negative results are durable
evidence, not workflow noise.

## Standard Bluefin LTS result

Run
[`31172682511`](https://github.com/plunder707/attestos/actions/runs/31172682511)
built and booted the immutable standard Bluefin LTS candidate with Secure Boot
enabled, then correctly stopped at the final admission gate. Firmware followed
shim and GRUB into a separate kernel and initramfs. The guest exposed no
`LoaderImageIdentifier` or systemd-stub variables, PCR 11 and PCR 15 remained
zero, and neither the embedded nor runtime command line contained the attestos
policy arguments. PCR 12 also remained zero, which is a valid baseline when no
external command-line input is supplied.

A `kernel-uki-virt` file existed in both the container and installed guest, but
it was not the loaded image. Their hashes also differed across the image-build
boundary. The admission report therefore distinguishes container candidates,
guest filesystem candidates, and firmware-loaded UKIs; candidate presence is
not boot evidence. Static inspection found a PE signature but did not validate
it against a carried certificate, so the signature and tamper gates remained
closed.

An earlier run's firmware log replay reported a mismatch because the checker
converted `tpm2_eventlog`'s unquoted YAML hexadecimal integer to decimal text.
The final sealed run uses strict integer normalization and reproduces quoted
PCR 7 from the exact 35,024-byte artifact. The repair does not change the base
HOLD because the loaded-UKI and policy gates remain false.

## Isolation

- disposable GitHub runner;
- QEMU TCG, no KVM;
- fresh swtpm state;
- guest network disabled;
- no host or physical TPM;
- no image or package publication; and
- `contents: read` workflow permission only.

The OCI signature establishes upstream image provenance. It does not establish
the PE/UKI signature chain or boot-policy trust; those remain independent
admission gates.

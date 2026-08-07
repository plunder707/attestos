# Bluefin LTS UKI Admission Canary

Status: development canary. It has no production, publication, graph, or
anti-cheat authority.

## Frozen candidate

The candidate is `ghcr.io/projectbluefin/bluefin:lts`, resolved to an immutable
digest at run time and verified with the public key vendored from the
`projectbluefin/bluefin-lts` source repository.

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

## Isolation

- disposable GitHub runner;
- QEMU TCG, no KVM;
- fresh swtpm state;
- guest network disabled;
- no host or physical TPM;
- no image or package publication; and
- `contents: read` workflow permission only.

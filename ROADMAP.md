# Attestos Roadmap

This roadmap records engineering gates, not release dates. A later stage may
start only when the previous stage has a reproducible artifact and its named
stop rules pass. Git history is authoritative; external reviews and memory
systems may point here but cannot advance a gate.

## 0. Raw TPM protocol mechanics - passed

- Freeze `attestos.tpm/v1` and its JSON Schema.
- Prove MakeCredential/ActivateCredential same-TPM AK enrollment.
- Verify raw quote, PCR selection, nonce, replay rejection, and tamper
  rejection against swtpm.
- Keep manufacturer, policy, and production trust false.

Evidence: `plunder707/attested-gaming` run `31146444974`.

## 1. Booted Bazzite mechanics - passed, policy held

- Build a digest-pinned Bazzite derivative and QCOW2 without publishing it.
- Boot with QEMU/OVMF, TCG, swtpm, and no guest network.
- Run the installed provisioner and agent inside the guest.
- Emit and independently validate one bounded evidence receipt.

Evidence: run `31157890393`, receipt SHA-256
`ad5ef12592cb5f4d1dfa8f0da88148931d48f0e6018924b2de4c766e1523ddaf`.

Hold: Bazzite produced no UKI signal, no sealed lockdown command line, no
systemd TPM event log, and zero-valued PCRs 11, 12, and 15.

## 2. UKI-capable base admission - next

- Build and boot the pinned Bluefin LTS/CentOS bootc candidate.
- Prove the firmware selected the intended signed UKI.
- Parse the UKI and match its embedded command line to the approved policy.
- Reproduce PCR/event-log evidence from the booted artifact.
- Add substitution negatives for the UKI and command line.
- Verify update and rollback preserve the same invariants.

Stop if package presence is the only UKI evidence, the signature chain is
unverified, event-log replay cannot reproduce the quote, or a substitution
negative passes.

Executable contract: [`UKI_ADMISSION_CANARY.md`](UKI_ADMISSION_CANARY.md) and
`.github/workflows/uki-base-admission-canary.yml`. The initial development
version is expected to hold until userspace event-log replay and two-deployment
update/rollback checks are implemented; those are explicit false gates rather
than TODOs interpreted as success.

## 3. Policy verifier

- Replay the firmware and systemd event logs against the quoted PCR snapshot.
- Hold the systemd event-log shared lock while taking the quote and snapshot.
- Bind deployment identity to verified signed metadata rather than trusting a
  self-reported `bootc status` claim.
- Define versioned policy, revocation, update, rollback, and minimum-SVN rules.

Stop on any race, ambiguous event, unbound deployment claim, or incomplete
provenance chain.

## 4. Hardware and manufacturer admission

- Validate EK certificate chains against pinned manufacturer roots.
- Repeat enrollment and quote flows on representative physical TPMs.
- Keep emulator and hardware evidence classes cryptographically distinct.
- Measure firmware/update stability and recovery behavior.

No software-TPM result may satisfy this gate.

## 5. Transport and privacy

- Design relay resistance around a non-exportable binding derived by the
  attested endpoint; caller-provided channel identifiers remain forbidden.
- Define unlinkability requirements before deploying hardware-backed tokens.
- Compare group signatures, privacy-CA, and platform support with an explicit
  relying-party threat model.

Stop if a clean second machine can relay a quote or if the token becomes an
unavoidable permanent cross-account identifier.

## 6. Relying-party pilot

- Write the one-page vendor integration contract around independently reported
  mechanics, same-TPM, manufacturer, and policy stages.
- Ask a tournament operator or anti-cheat vendor which evidence and residual
  risks they would actually accept.
- Run a bounded pilot before building distribution or fleet infrastructure.

No public compatibility, anti-cheat, or production-trust claim exists until a
relying party accepts a named policy and the preceding gates remain green.

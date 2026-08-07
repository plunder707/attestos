# Build Canary

This pull request exists only to exercise the inherited Universal Blue
container build on GitHub Actions.

The first canary was manually dispatched at the `build-test` ref. Publication
is gated on the default branch, so the registry login, push, Cosign install,
and signing steps were all skipped.

Passing this canary means only that:

- the Containerfile and added files assemble on the hosted runner;
- the inherited `just check` step succeeds;
- `bootc container lint` accepts the resulting container.

It does not establish that the image boots, produces a valid TPM quote, seals
its kernel command line in a UKI, validates an AK/EK trust chain, or is ready to
publish. Automatic push and schedule triggers remain disabled; this run did
not enter the package-publishing path.

## First result

- Result: pass
- Run: https://github.com/plunder707/attestos/actions/runs/31143048491
- Commit: `14e3a21f4c6bcbc438a591cc6f487049de49389b`
- Duration: 15m46s
- Verified: `just check`, container assembly, `bootc container lint`, and
  rpm-ostree rechunking
- Lint: 11 checks passed, 1 skipped, 2 non-fatal DNF-state warnings
- Published artifacts: none; all registry and signing steps skipped

The build also demonstrated that the baked `/usr/lib/attestos/image-digest`
value is `unknown`. Deployed-image identity must be obtained and verified at
runtime or bound by an external manifest; this canary does not solve that
protocol requirement.

## Raw TPM protocol result

The verifier repository later ran this image agent at commit
`040e28d1f59d9297c2a712ed3929c2e18de78e34` against an isolated software TPM:

- Result: pass
- Run: https://github.com/plunder707/attested-gaming/actions/runs/31146444974
- Verifier commit: `69221f2572a201b5bc480c977bb4a5cf3e0dbdd6`
- Receipt SHA-256:
  `bc7566238d0bb64587a98cdc3dbed7e622c0939d4a04f103bb4b257d751555ae`
- Passed: MakeCredential/ActivateCredential, raw Quote/CheckQuote, challenge
  replay rejection, signature-tamper rejection, and QEMU/OVMF/swtpm wiring
- Explicitly false: manufacturer trust, boot-policy trust, and production trust

That workflow did not boot the built Bazzite image. It proves that the
provisioner, agent, wire schema, and verifier interoperate at the TPM mechanics
layer. Hardware certificate validation, transport channel binding, event-log
replay, UKI measurement, and policy admission remain closed.

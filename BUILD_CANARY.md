# Build Canary

This pull request exists only to exercise the inherited Universal Blue
container build on GitHub Actions.

Passing this canary means only that:

- the Containerfile and added files assemble on the hosted runner;
- the inherited `just check` step succeeds;
- `bootc container lint` accepts the resulting container.

It does not establish that the image boots, produces a valid TPM quote, seals
its kernel command line in a UKI, validates an AK/EK trust chain, or is ready to
publish. Push, schedule, and package-publishing triggers remain disabled.

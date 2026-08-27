# MAST root stability check

Deployed accounts and notes commit to the MAST roots of the code they were created with. If a patch changes a root, code built against it computes a different commitment than the deployed one. The check compares the roots produced by the working tree against those of the latest release and fails if any of them changed.

Only runs when the new version is a Cargo-compatible upgrade, eg. a patch release: `0.15.3 -> 0.15.4` is checked, `0.15.3 -> 0.16.0` is not. It also skips if the version is a pre-release.

Scripts: `check-masm-root-stability.sh` and `check-masm-export-digests.rs` that are run by the `workspace-release` action.

## What is checked

The baseline is the latest release tag and it is compared against the version about to be released. For both sides:

- Every exported procedure digest of the `ProtocolLib`, transaction kernel, `StandardsLib` and agglayer packages.
- The kernel commitment and the two kernel programs (they cover the prologue, epilogue and procedure ordering, which the package exports do not).
- The agglayer bridge code commitment, which no package export covers.
- Per account component: each procedure root, plus a commitment over its whole procedure set.

A changed or removed root fails. An added procedure is only a warning, but an addition to the kernel or to a component still fails because it changes the corresponding commitment.

## Escape-hatch

There is an escape-hatch for when the root change is intended: set the `SKIP_MASM_ROOT_CHECK_FOR_VERSION` repository variable to the version being released, eg. `0.16.1`. The check is skipped only while the workspace version matches it, so a value that is left behind goes stale instead of disabling the check for every later release. A stale value is reported as a warning in the check output.

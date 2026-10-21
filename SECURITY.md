# Security Policy

The Miden protocol implementation is currently in alpha, has not been audited, and is not ready for
production use. Security reports are still valuable, especially when they identify issues that could
affect transaction validity, asset conservation, account authorization, or the integrity of published
crates.

## Supported Versions

Security fixes are prioritized for the current active development branch and the most recent release
line.

| Version | Supported |
| ------- | --------- |
| `next` | Yes |
| Latest published release | Best effort |
| Older releases | No guarantee |

Because the project is in alpha, APIs and internals may change between releases. Users should plan
to upgrade to the latest release after a security fix is published.

## Reporting a Vulnerability

Please do not open a public issue, discussion, or pull request for an undisclosed vulnerability.
Report vulnerabilities through GitHub's private vulnerability reporting flow:

<https://github.com/0xMiden/protocol/security/advisories/new>

Use a public GitHub issue only for ordinary bugs that do not create a security risk.

## What to Include

Please set a high bar for security submissions. Reports are most actionable when they include:

- A clear description of the vulnerability and its security impact.
- The affected crate, component, version, commit, or branch.
- A minimal proof of concept or reproducible test case.
- A proposed fix patch, where possible.
- A regression test that fails before the fix and passes after it, where possible.
- Any relevant environment details, configuration, feature flags, inputs, or assumptions.
- Whether the issue has been disclosed anywhere else.

Incomplete reports may still be useful, but maintainers may ask for a proof of concept, a patch, or
a regression test before triage can be completed.

## Scope

Security-relevant reports include:

- Proof soundness or verification bugs that let invalid transactions, batches, or blocks be accepted.
- Bugs in protocol kernels or standard contracts that bypass account authorization or violate asset
  conservation.
- Bugs that allow notes to be consumed more than once or bypass note inclusion checks.
- Vulnerabilities in serialization, deserialization, or validation of protocol objects.
- Memory-safety issues, panics, or resource exhaustion with a plausible security impact.
- Supply-chain, release, CI, or signing issues that could affect published artifacts.

General correctness bugs, documentation issues, feature requests, and performance problems without a
plausible security impact should be reported through the normal public issue tracker.

## Disclosure

Maintainers will use GitHub security advisories to coordinate investigation, fixes, credits, and
public disclosure. Please give maintainers a reasonable opportunity to investigate and release a fix
before disclosing the issue publicly.

When testing, act in good faith. Do not access data that is not yours, disrupt services, or use the
vulnerability beyond what is necessary to demonstrate impact.

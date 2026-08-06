---
name: concise-changelog-entries
description: Keep CHANGELOG.md entries to a single concise sentence. Use when adding or editing entries in CHANGELOG.md.
---

# Concise CHANGELOG Entries

## Rule

A CHANGELOG entry is one sentence: what changed, at a glance. Most of the time the
first sentence of the description is enough — drop the rest.

Do NOT put in the CHANGELOG:

- The mechanism / how it works (which flag, which procedure, the algorithm).
- Consequences, edge cases, and downstream effects.
- Rationale or motivation.

Those belong in the PR description and the commit message, which the entry's link
points to. The reader gets "what changed" from the CHANGELOG and one click away for
the details.

When trimming, don't drop:

- The trailing PR/issue link, e.g. `([#3310](https://github.com/0xMiden/protocol/issues/3310))`.
- A leading `[BREAKING]` tag if one is already there. Condensing an entry must not silently
  change whether it's marked breaking.

The `[BREAKING]` tag is not about verbosity — it belongs only on changes that actually break
users of a prior version (removed/renamed/behavior-changed public APIs). Purely additive changes
(new APIs, new features) get no tag, however large. Add or remove the tag based on the change
itself, never as a side effect of shortening the sentence.

## Examples

**Avoid** (verbose — mechanism + consequences inline):

```markdown
- [BREAKING] Unified the two account-origin authenticators in the transaction kernel's `api.masm` into a single `authenticate_account_origin` procedure that conditionally tracks the call: a kernel procedure call is recorded (via the `was_called` flag) only when the active account is the native account and the account's authentication procedure is not currently executing. As a result the read-only introspection procedures (`account_has_procedure`, ...) are now tracked in the native context, and `account_upgrade` is now gated by the authenticator ([#3310](https://github.com/0xMiden/protocol/issues/3310)).
```

**Good** (first sentence only):

```markdown
- [BREAKING] Unified the two account-origin authenticators in `api.masm` into a single `authenticate_account_origin` procedure that conditionally tracks the call ([#3310](https://github.com/0xMiden/protocol/issues/3310)).
```

---

**Avoid:**

```markdown
- [BREAKING] Transaction fees are now paid by the authentication procedure creating a public TX_FEE note before the transaction summary is created, so the fee payment is covered by the signature (`miden::standards::fee`). The payment asset and conversion rate are committed to via the auth args (see `FeeConversionInfo`); on zero-base-fee chains no note is created ([#2899](https://github.com/0xMiden/protocol/discussions/2899)).
```

**Good:**

```markdown
- [BREAKING] Transaction fees are now paid by the authentication procedure creating a public TX_FEE note covered by the signature ([#2899](https://github.com/0xMiden/protocol/discussions/2899)).
```

## When a second sentence is warranted

Rarely — only when a single sentence would leave a user unable to react to the change
(e.g. a migration note they must act on). Even then, keep it to one short clause, not a
paragraph. When in doubt, cut it.

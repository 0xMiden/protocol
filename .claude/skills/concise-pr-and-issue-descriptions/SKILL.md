---
name: concise-pr-and-issue-descriptions
description: Keep PR and issue descriptions short and decision-focused. Use when writing or editing a pull request body or a GitHub issue.
---

# Concise PR and Issue Descriptions

## The shared rule

A PR or issue body answers why it exists, what it covers, and what the reader has to
decide. Then it stops. Aim for under ~400 words.

Cut anything the reader can already get from the diff, from CI, or from a link:

- Test plans and verification checklists. CI reports what passed; a green checklist
  pasted by the author proves nothing a reviewer can act on.
- Command transcripts, test counts, timing.
- Process narration: approaches tried and abandoned, how the rebase went, which review
  round changed what.
- File-by-file enumeration, and long code blocks a permalink would cover.
- Mechanism the linked code already shows.
- The same link repeated. Link an issue or a file once.

Use commit-pinned permalinks (`/blob/<full-sha>/path#L123`), never branch refs - branch
line numbers rot, and a stale link costs the reader more than the paragraph saved.

## Pull requests

Sections, in this order. Drop any that would be empty.

1. `## Summary` - `Closes #N`, then one or two short paragraphs: the problem, and why
   this change is the answer. State the motivation, do not restate the diff.
2. `## Changes` - three to five bullets. Each says what changed and folds the reason into
   the same sentence. Close with a one-line sweep of cross-cutting facts (what stayed the
   same, which commitments or IDs change, which crates are untouched).
3. `## Open questions` - numbered, only for decisions the reviewer must actually make.
   Two sentences each.

The one exception to "no process narration": a force-push that replaced a materially
different approach earns a single sentence, so a reviewer comparing revisions is not left
guessing.

### Example

**Avoid** (verification noise, process narration, per-file detail):

```markdown
## Summary
This PR removes the AggLayer faucet component. See below for details.

## Changes
- Deleted `crates/miden-agglayer/asm/components/faucet/faucet.masm`
- Deleted `crates/miden-agglayer/asm/agglayer/faucet/mod.masm`
- Deleted `crates/miden-agglayer/src/faucet.rs` (318 lines)
- Updated `crates/miden-agglayer/build.rs` lines 235-255 to drop the faucet branch
- Updated 24 call sites across bridge_in.rs, bridge_out.rs, ...

## Note on the approach
An earlier revision added a builder-returning variant to miden-standards, but after
rebasing onto #3486 that no longer worked, so I reverted it and started over.

## Test plan
- [x] Full suite: 1841 passed, 0 failed
- [x] `cargo test -p bench-transaction --release`: 28 passed
- [x] `make clippy`, `make check-no-std`, `make build-no-std`, `make doc`
```

**Good** (motivation, effect, open decisions):

```markdown
## Summary

Closes [#2585](https://github.com/0xMiden/protocol/issues/2585).

The `agglayer::faucet` component was vestigial: it re-exported three procedures from the
standards library, a strict subset of what the standard `FungibleFaucet` component exports.
The re-exports resolve to the same standards procedures, so the mint/burn MAST roots are
unchanged by the swap.

The functional gap was the token name: `AggLayerFaucet::new` fabricated it from the symbol,
leaving the metadata hash preimage `abi.encode(name, symbol, decimals)` unrecoverable from
faucet storage. #2586 needs it to verify the registered hash on-chain.

## Changes

- Removed the `miden-agglayer-faucet` MASM package, `src/faucet.rs` and the generated
  `FAUCET_CODE_COMMITMENT`. Faucet identity now comes from `FungibleFaucet::try_from(&Account)`,
  which checks the interface instead of a commitment that had to hand-mirror the component stack.
- The builders take a token name, and `MetadataHash::from_fungible_faucet` derives the
  registered hash from faucet storage so the two cannot drift.

The component stack is otherwise unchanged. The faucet code commitment changes, as do faucet
account IDs. `miden-standards` is untouched.

## Open questions

1. `TokenName::MAX_BYTES` is 32, a policy cap below the 55-byte encoding capacity. #2586 turns
   the current workaround into a hard ceiling on foreign token names, so it is worth settling
   before that work starts.
```

## Issues

Same discipline, different shape. An issue makes the case that something should change and
gives whoever picks it up enough to start.

1. Title - the problem or the wanted outcome, not a summary of the fix.
2. Opening paragraph - what is wrong or missing, stated as fact, with a permalink to the
   code. No preamble.
3. Impact - what breaks, who is affected, or what it blocks. This is what earns the issue
   its priority, so do not leave it implicit.
4. Proposed direction (optional) - a few bullets naming the approach. Not a design doc and
   not an implementation plan; the PR does that.
5. Prerequisites and related issues, as a short trailing list.

Additionally leave out of issues:

- Step-by-step implementation plans and per-file edit lists.
- Exploration narrative ("I first tried X, then Y").
- Speculation about causes you have not checked. Say what you observed and mark what is
  unverified.

Quote code only when the excerpt is the point (a wrong line, a confusing signature), and
keep it to a few lines. Otherwise link it.

### Example

**Avoid** (fix plan in place of a problem statement):

```markdown
### Proposed Solution

We should refactor `get_size_hint` to avoid the temporary allocation. Steps:
1. Add a `serialized_size()` method to `MastForest` in `miden-core`
2. Change `AccountCode::get_size_hint` at line 301 to call it
3. Update the tests in `mod.rs` lines 890-940
4. Run `cargo test -p miden-protocol`
...followed by the full diff, inline.
```

**Good** (problem, evidence, impact, direction):

```markdown
`AccountCode::get_size_hint` measures the encoded size by serializing the whole `MastForest`
into a throwaway `Vec<u8>` and reading its length
([code](https://github.com/0xMiden/protocol/blob/a95dc00a/crates/miden-protocol/src/account/code/mod.rs#L301-L315)).

Every `AccountCode::to_bytes()` therefore serializes the forest twice: once to size the
buffer, once to fill it, with a heap allocation in between that is immediately dropped.
Account code is serialized on every account update, so this is on a hot path.

Fix direction: give `MastForest` a size calculation that does not build the buffer, and have
`get_size_hint` call it. The existing `TODO` at that line anticipates this.
```

## What earns extra length

Only what the reader needs and cannot get elsewhere:

- A security or correctness argument for why a change is safe.
- A protocol-level consequence: a commitment that changes, an account ID that moves, a
  storage layout that shifts.
- A deliberate deviation from a convention, with its reason.
- For issues, a genuine design question put to the team - the trade-offs, the options, and
  what you need decided. These are discussions, and being terse costs more than it saves.

Depth in these is fine. Everything else gets cut.

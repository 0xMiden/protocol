<!--
SUPERSEDED. This document specifies fee approach "A" (fee-in-note, priced by the
network account, pulled by a transaction-kernel note prologue).

It was superseded by the decision to adopt approach "C" (sponsorship note +
account estimates) in discussion #2968:
  https://github.com/0xMiden/protocol/discussions/2968#discussioncomment-17545587

It is retained because its analysis of why the kernel path is hard remains valid
and is itself an argument for C. In particular: `active_note::get_assets` reads a
note's assets from the advice map keyed by ASSETS_COMMITMENT, not from kernel
memory, so a kernel prologue cannot simply decrement a note's asset in place --
see issue #3242.
-->

# Refinement: kernel-driven pay-fee, schedule-only `FeeManager`

This is a proposed revision of this issue, not a rewrite. The problem statement, the
schedule-as-account-state idea, and the note-script change list all stand. What changes is *who runs
pay-fee*: the transaction kernel, via a per-note prologue, rather than a
`call.fee_manager::pay_fee` prepended to each note script. That kernel work is specced separately in
the companion issue (Deliverable B); this issue shrinks to the schedule and its admin interface.

Every claim about existing behaviour below is cited. Note that
[#2899](https://github.com/0xMiden/protocol/discussions/2899),
[#2551](https://github.com/0xMiden/protocol/discussions/2551) and
[#2968](https://github.com/0xMiden/protocol/discussions/2968) are Discussions, not Issues.

## What the original proposal got right

- Pricing lives in account state, keyed by note script root. Unchanged.
- The same script root needs distinct prices for distinct behaviours. Unchanged, and CLAIM L1 vs L2
  is still the motivating case.
- Each schedule entry pins one `fee_asset`, and the user cannot pick it. Unchanged in spirit,
  tightened below.
- Routing is an indirection: vault credit today, `FeeNote` under
  [#2899](https://github.com/0xMiden/protocol/discussions/2899). Unchanged.
- Admin ops guarded by the account's authority. Unchanged, and `authority::assert_authorized` now
  actually exists (`crates/miden-standards/asm/standards/access/authority.masm:75`, with
  `policy_manager.masm:329` as the calling precedent), so this is no longer hypothetical.

## What changes

1. `pay_fee` leaves the component. The kernel owns runtime dispatch. `FeeManager` becomes schedule
   state plus `set_fee` / `remove_fee` / `get_fee`, and touches no assets at runtime.
2. `variant_tag` comes back, and is derived by the kernel from the note's structure rather than
   written by the script.
3. The nested map flattens. `Map<script_root, Map<variant_tag, entry>>` is not expressible.
4. `fee_asset` stops being stored per entry, and is pinned to the protocol fee token.

## Reversing the `variant_tag` decision

We dropped `variant_tag` earlier on the grounds that
["A given fee policy procedure should examine the active note to estimate how much fees it should pay - no additional input should be necessary."](https://github.com/0xMiden/protocol/issues/2901)
That is correct for an account procedure, and false for a kernel prologue. The reason is mechanical.

`NoteStorage` is committed as a flat sequential hash over all N elements. There is no per-element
opening. To read `storage[i]` soundly, you must pull all N felts from the advice map and re-hash them
against `NOTE_STORAGE_COMMITMENT` (`crates/miden-protocol/asm/protocol/src/active_note.masm:322-349`,
which asserts both `ERR_NOTE_INVALID_NUMBER_OF_STORAGE_ITEMS` and
`ERR_NOTE_DATA_DOES_NOT_MATCH_COMMITMENT`). There is no caching: if a prologue materialises storage
and the script then calls `get_storage`, the script re-materialises and re-hashes from scratch. For
CLAIM that is 569 felts hashed twice, on every note.

So a procedure running inside the note script can afford to examine the active note, because it was
going to read storage anyway. A kernel prologue running before the script cannot. The only note
property the kernel gets for free is the storage item count, `num_storage_items`, a plain memory load
at `crates/miden-protocol/asm/kernels/transaction-core/src/memory.masm:1562`.

`variant_tag` is the price of moving enforcement into the kernel. In exchange, no note script can
skip `pay_fee`, reorder it, or declare a variant that disagrees with the branch it then takes.

## Variant derivation

```
variant_tag := num_storage_items
```

That is the whole rule. Three properties make it work.

It is free. `memory::get_input_note_num_storage_items` (`memory.masm:1562`) reads one felt from the
note's memory region, written during the transaction prologue
(`prologue.masm:639-652`, `process_note_num_storage_items`). No advice access, no hashing.

It is authenticated. The count is bound through `STORAGE_COMMITMENT` into `RECIPIENT`
(`prologue.masm:770-789`), into the note details commitment, and finally asserted against
`INPUT_NOTES_COMMITMENT` (`prologue.masm:1018`, `ERR_PROLOGUE_INPUT_NOTES_COMMITMENT_MISMATCH`).
A different element count produces a different note ID. Nobody can lie about it.

It is already MINT's real dispatch key. `mint_fungible.masm:127-128` does
`u32assert2 ... u32gte.FUNGIBLE_MIN_NUM_STORAGE_ITEMS_PUBLIC` where private is exactly 13 and public
is 20 or more; `mint_non_fungible.masm:116-117` does the same with 9 and 16.

### The constraint this imposes, stated plainly

The kernel's derivation only closes the lying gap if it computes *the same predicate the script
dispatches on*. `NoteStorage` is chosen by the note creator, not the script. If the kernel prices on
element count while the script branches on something else, a creator picks the cheap count and runs
the expensive path.

So the rule is: **any behavioural split an operator wants to price differently must be a function of
`num_storage_items`.** This is checkable by reading the script, and it is checked once, at `set_fee`
time, because the schedule is itself an allowlist. It is the single remaining note-authoring
convention.

### Unbounded counts

MINT's public variants have no upper bound on the count (20 plus the embedded output note's storage).
An operator cannot enumerate an entry per count. The schedule therefore supports a per-script
wildcard: lookup tries the exact `variant_tag` first, then `VARIANT_WILDCARD`, then falls through to
`default_deny`. Exact entries are overrides on a per-script default.

`VARIANT_WILDCARD` is any sentinel above `MAX_NOTE_STORAGE_ITEMS` (1024, `crates/miden-protocol/src/constants.rs:18`,
enforced at `prologue.masm:645-646`), so it can never collide with a real count.

A note whose count lands in a nonsensical range (say 14 on a fungible faucet) hits the wildcard, gets
priced, and is then rejected by the script's own assertion. The transaction reverts as a whole, so a
mispriced note is never a profitable one. The failure mode is closed.

## Storage schema

Two slots, both protocol-reserved names. There is direct precedent for the protocol reserving a slot
name that a standards component populates: `miden::protocol::faucet::callback::on_before_asset_added_to_account`
is defined in `crates/miden-protocol/src/asset/asset_callbacks.rs:10-17` and installed by
`TokenPolicyManager` (`crates/miden-standards/src/account/policies/manager.rs:638-644`).

The kernel needs the slot IDs as compile-time constants, because `StorageSlotId` is the first two
felts of `blake3(slot_name)` (`crates/miden-protocol/src/account/storage/slot/slot_id.rs:16-46`) and
the kernel cannot hash a string at runtime.

```
miden::protocol::fees::fee_schedule   -> StorageSlot::Map
miden::protocol::fees::fee_config     -> StorageSlot::Value
```

### `fee_schedule` (map)

```
KEY   = poseidon2::hash_words(SCRIPT_ROOT, [variant_tag, 0, 0, 0])
VALUE = [amount, flags, 0, 0]
```

`flags` bit 0 is `enabled`. Bits 1 and above are reserved and must be zero. The two trailing felts
are reserved and must be zero. The kernel asserts both; an old kernel meeting a new entry reverts
rather than misreading it.

Three notes on why this shape and not the original one.

A `StorageMap` value is exactly one `Word`, and its key is exactly one `Word`
(`crates/miden-protocol/src/account/storage/map/mod.rs:44-53`, `map/key.rs:26`). A map value cannot
be another map, so `Map<script_root, Map<variant_tag, entry>>` has no encoding. `SCRIPT_ROOT` already
occupies all four felts, so `variant_tag` cannot be packed beside it the way every existing compound
key in the tree does (`create_status_key` at
`crates/miden-standards/asm/standards/faucets/non_fungible.masm:66-72` pads two ID felts with zeros;
`build_blocked_accounts_map_key` at `.../policies/transfer/blocklist/mod.masm:152-156` is the same
pattern). Hashing the pair is the only option. `poseidon2::hash_words` is the two-word-to-digest
primitive already used by `claim.masm`, and the kernel hashes the resulting key once more internally
(`hash_map_key`, `account.masm:1792-1795`).

`enabled` is load-bearing, not decorative. There is no `find_map_item`: `get_map_item`
(`account.masm:495`) returns `EMPTY_WORD` for an absent key. Requiring `enabled = 1` on every live
entry makes `EMPTY_WORD` unambiguously mean "absent", which is what lets a genuinely free note be
expressed as `[0, 1, 0, 0]` rather than being indistinguishable from a missing one.

`fee_asset` is absent because it is pinned. The schedule's asset is the block's fee faucet, which the
kernel already holds at `FEE_FAUCET_ID_SUFFIX_PTR` / `FEE_FAUCET_ID_PREFIX_PTR` (834 and 835,
`memory.masm:156-157`). Removing it from the entry is exactly what buys us a four-felt value. The
network account never holds fee-token liquidity to reimburse users with, and never eats FX risk.

### `fee_config` (value)

```
VALUE = [default_deny, dry_run, 0, 0]
```

Read with `find_item` (`account.masm:330`), which returns `[is_found, VALUE]` and does not panic.

### Growing to multi-asset

A `Word` value cannot grow, so the original "reserved slots avoid a migration" story does not hold as
written. The migration-free path is a sibling slot: [#2551](https://github.com/0xMiden/protocol/discussions/2551)
adds `miden::protocol::fees::fee_schedule_assets`, keyed identically, whose presence is signalled by a
reserved `flags` bit. Existing entries never move. Adding a slot to a component is not a migration of
its data, because slots are name-addressed and sorted by hash, not by index
(`crates/miden-protocol/src/account/storage/mod.rs:39-55`).

## Procedures

All three are `@account_procedure`. `set_fee` and `remove_fee` are admin-guarded by
`authority::assert_authorized`.

```
set_fee(SCRIPT_ROOT, variant_tag, amount, enabled) -> []
remove_fee(SCRIPT_ROOT, variant_tag)               -> []
get_fee(SCRIPT_ROOT, variant_tag)                  -> [amount, flags]
```

`set_fee` asserts `variant_tag <= MAX_NOTE_STORAGE_ITEMS` or `variant_tag == VARIANT_WILDCARD`, and
asserts `enabled` is boolean. Setting an entry with `enabled = 0` prices the note as denied without
deleting the row, which is the per-entry kill switch.

`get_fee` is read-only and must remain **FPI-callable**. This is load-bearing rather than a client
convenience. The bridge-to-faucet case raised on this thread needs one network account to price a
note for *another* network account before that note exists. A kernel prologue cannot serve that
question, because there is no active note to derive a `variant_tag` from. So the caller supplies both
`SCRIPT_ROOT` and the `variant_tag` it intends to build (that is, the storage length of the note it
is about to create), and reads the price out of the target's schedule. This preserves the intent of
the `compute_fee`-over-FPI design without keeping a policy procedure.

`get_fee` returns `[0, 0]` for an absent entry rather than panicking, so client probing stays
panic-free.

## Rollout knobs

`enabled`, per entry. Clears a single price without removing the row.

`default_deny`, per account. Decides what a schedule miss means:

- `default_deny = 1` (default): a note whose `(script_root, variant_tag)` has no entry and no wildcard
  reverts the transaction.
- `default_deny = 0`: it is free.

This reconciles rather than overrides the position reached on this thread. `default_deny = 0` *is*
"allowlisted but unpriced is free", exactly as agreed. Making it a flag rather than a hardcoded
semantic means an operator can start permissive and tighten, and means the fail-closed default is
available to accounts that want it.

Note that `default_deny = 1` turns the fee schedule into a second, earlier allowlist. It runs during
note processing, whereas `AuthNetworkAccount`'s note allowlist runs in the epilogue's auth procedure
(`epilogue.masm:194-207`), after every note script has already executed. Consuming an unpriced script
now fails before its script runs rather than after.

## Required note-script changes

The `call.fee_manager::pay_fee` prepend is removed from every note. Nothing is prepended in its place.
What each note owes instead is a `NoteStorage` shape whose element count separates the variants the
operator wants to price apart.

`NetworkAccountTarget` grows a fee field, per the sketch in
[#2968](https://github.com/0xMiden/protocol/discussions/2968):

```rust
pub struct NetworkAccountTarget {
    target_id: AccountId,
    exec_hint: NoteExecutionHint,
    fee: FungibleAsset,      // the note creator's max_fee
}
```

It is a single-word attachment today, with felt 3 entirely zero
(`crates/miden-standards/src/note/network_account_target.rs:13-20`). A `FungibleAsset` is a full word,
so it becomes a two-word attachment. Limits are not a concern: four attachments per note, 256 words
each. Attachments are authenticated through `NOTE_METADATA_COMMITMENT` (`prologue.masm:605-625`), and
locating one costs nothing beyond the metadata word the kernel already holds
(`active_note.masm:450-459`). This is the right carrier because note args are explicitly *not*
authenticated (`prologue.masm:584-603`: "The note's ARGS are not authenticated, these are optional
arguments the user can provide when consuming the note") and the consumer is the ntx builder, which
is precisely the party `max_fee` exists to constrain.

Per script:

- **BURN** (`crates/miden-standards/asm/standards/notes/burn.masm`). Reads no storage; dispatches on
  account-side `CodeInspection` reflection, which the per-account schedule already disambiguates. One
  variant, `variant_tag = 0`, or a wildcard entry. Still needs the explicit-burn-amount rework from
  [#2343](https://github.com/0xMiden/protocol/issues/2343), because the fee asset and the burn asset
  may share a faucet and `receive_and_burn` currently assumes the note holds exactly one asset.
- **CLAIM** (`crates/miden-agglayer/asm/note_scripts/claim.masm`). Needs restructuring, and it is
  worth doing on its own merits. Today L1 and L2 claims both carry 569 elements and are told apart by
  the `mainnetFlag` bit inside `globalIndex`, branched on at
  `crates/miden-agglayer/asm/agglayer/bridge/bridge_in.masm:565-568`. But
  `SMT_PROOF_ROLLUP_EXIT_ROOT_PTR` (elements 256 through 511, 256 felts) is read in exactly one place,
  `bridge_in.masm:632`, inside the rollup branch. It is dead data on every L1 claim. Dropping it gives
  L1 CLAIM 313 elements and L2 CLAIM 569, and stops L1 claimants paying to commit 256 felts of zeros.
  The script then branches on the count and asserts `mainnetFlag` agrees with it, which is exactly the
  invariant the kernel relies on. Note that `claim.masm:89` currently drops the count without checking
  it, so nothing requires 569 today. Concretely this shifts `PROOF_DATA_SIZE`, `LEAF_DATA_START_PTR`
  and `FAUCET_MINT_AMOUNT` (`claim.masm:9-16`) and `CLAIM_PROOF_DATA_WORD_LEN`, `GLOBAL_INDEX_PTR`,
  `EXIT_ROOTS_PTR` and `CLAIM_LEAF_DATA_START_PTR` (`bridge_in.masm:53-118`) into two constant sets.
- **B2AGG** (6 elements, asserted). No change. Its reclaim-versus-bridge-out split is decided by
  sender equals consuming account (`b2agg.masm:61-71`), which no count can see, but it does not need
  to: on the reclaim path the consuming account is the *user's own* account, which has no
  `fee_schedule` slot, so the kernel prologue never fires. Bridge-out is consumed by the bridge, which
  does. The component gate separates them for free. The one collision is a network account reclaiming
  a chained note it authored itself, where sender and consumer are both fee-managed; that case is
  charged, which is the fail-closed direction.
- **UPDATE_GER** (8 elements, asserted). No change.
- **CONFIG_AGG_BRIDGE** (18 elements, asserted). No change.
- **Bridge component** (`crates/miden-agglayer/asm/components/bridge.masm`). No longer re-exports
  `pay_fee`, because there is nothing to re-export. It composes `FeeManager` for the schedule and its
  admin procedures only.

## Interactions

[#2899](https://github.com/0xMiden/protocol/discussions/2899). The kernel accumulates pulled fees
across all notes in the transaction and the epilogue emits a single `FeeNote`
([#3117](https://github.com/0xMiden/protocol/issues/3117)) carrying the total. One note per
transaction, not per input note. Per that discussion the `FeeNote` is payable to nobody and consumable
by anyone, so the batch builder picks it up during batch construction. `FeeManager` needs to know none
of this.

[#2551](https://github.com/0xMiden/protocol/discussions/2551). A sibling map slot, as above. Note that
[#2952](https://github.com/0xMiden/protocol/issues/2952) will replace `FeeParameters::fee_faucet_id`
with a `fee_asset_key`; the pinned-asset rule above should be written against whichever lands.

[#2765](https://github.com/0xMiden/protocol/issues/2765) and
[#3183](https://github.com/0xMiden/protocol/issues/3183). Both say a max fee must be bound into the
signed transaction summary before fees are reintroduced. The `max_fee` in the attachment is a
*note-level* ceiling protecting the note creator from schedule drift between creation and consumption.
It does not discharge those issues, which concern the *transaction-level* fee bound. They remain
prerequisites.

## Not covered here

The kernel prologue and epilogue, their insertion points, the asset-pull mechanics, the trust model
and the dry-run rollout are specced in the companion issue. That issue also names a prerequisite this
one does not: input note assets are currently immutable, so pulling a fee out of a note requires
[#3242](https://github.com/0xMiden/protocol/issues/3242).

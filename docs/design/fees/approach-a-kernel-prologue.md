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

# kernels: per-note fee prologue and epilogue for `FeeManager` accounts

Companion to [#2901](https://github.com/0xMiden/protocol/issues/2901). That issue defines the fee
schedule an account carries. This one proposes that the transaction kernel, not the note script, reads
that schedule and pulls the fee.

## Problem

Under [#2901](https://github.com/0xMiden/protocol/issues/2901) as originally written, every network
note script prepends `call.fee_manager::pay_fee`. That places the fee entirely in the hands of the
note author. A script can omit the call, place it after the business logic, take an early-return path
that skips it, or declare one variant to `pay_fee` and then execute another. None of that is
detectable by the account, and all of it is profitable.

The fee schedule is an allowlist, so scripts are reviewed before they are priced. But "reviewed" is
not "enforced", and the review burden grows with every script and every branch inside it. We would
rather the kernel guarantee the property.

Two pieces of context matter.

The kernel currently debits no fee at all. [#3108](https://github.com/0xMiden/protocol/pull/3108)
removed `compute_and_remove_fee`, `create_fee_asset`, `memory::get_fee_faucet_id`, the fee from
`TransactionOutputs` / `TransactionId` / `TransactionHeader`, and the pre/post-fee delta split. What
survives is `tx::compute_fee`
(`crates/miden-protocol/asm/kernels/transaction-core/src/tx.masm:233`, exported as
`miden::protocol::tx::compute_fee` by [#3212](https://github.com/0xMiden/protocol/pull/3212)), which
nothing in the transaction lifecycle calls. `docs/src/fees.md:7` still claims the fee is "computed and
charged automatically by the transaction kernel during the epilogue"; that documentation is stale.
This proposal is therefore a *reintroduction* of kernel-side fee movement, scoped to network accounts.

[#2765](https://github.com/0xMiden/protocol/issues/2765) and
[#3183](https://github.com/0xMiden/protocol/issues/3183) both conclude that a max fee must be bound
into the signed transaction summary, and the tx script root committed to, before fees are reintroduced
at all. They are prerequisites, not blockers on the design below.

## Insertion points

The note-processing loop is `crates/miden-protocol/asm/kernels/transaction/bin/main.masm:100-123`:

```
while.true
    emit.NOTE_EXECUTION_START_EVENT

    exec.note::prepare_note        # :104  => [note_script_root_ptr, NOTE_ARGS, pad(11), pad(16)]
                                   #  <-- prologue goes here
    dyncall                        # :108  run the note's script

    dropw dropw dropw dropw        # :112  clear up to 4 words the script left
                                   #  <-- epilogue goes here
    exec.note::increment_active_input_note_ptr   # :115

    loc_load.0 neq
    emit.NOTE_EXECUTION_END_EVENT
end
exec.note::note_processing_teardown              # :125
```

There is no per-note hook today. The only account-level hook is the single auth `dyncall` in the
transaction epilogue (`epilogue.masm:194-207`).

Both insertion points are viable. The active-note pointer is set once in the transaction prologue
(`prologue.masm:1022-1025`) and cleared only after the loop (`note::note_processing_teardown`,
`note.masm:58-62`), so every `active_note` accessor works in both positions.

One constraint. `note::prepare_note` (`note.masm:74-86`) deliberately leaves the stack as
`[note_script_root_ptr, NOTE_ARGS, pad(11)]`, exactly what `dyncall` expects. A prologue inserted
after it must restore that shape byte for byte. Cleanest is to run the prologue *before*
`prepare_note` and read the note pointer directly via `memory::get_active_input_note_ptr`.

## What the kernel can read for free

Everything the prologue needs is already in kernel memory, written and validated during the
transaction prologue. Offsets from `note_ptr` (`memory.masm:249-261`):

- `INPUT_NOTE_SCRIPT_ROOT_OFFSET = 8`, authenticated: folded into `RECIPIENT`
  (`prologue.masm:770-789`) and asserted against `INPUT_NOTES_COMMITMENT` (`prologue.masm:1018`).
- `INPUT_NOTE_METADATA_OFFSET = 20`, authenticated via `NOTE_METADATA_COMMITMENT`
  (`prologue.masm:605-625`). Carries the four attachment scheme markers in felt 3.
- `INPUT_NOTE_NUM_STORAGE_ITEMS_OFFSET = 36`, authenticated transitively through
  `STORAGE_COMMITMENT`.
- `INPUT_NOTE_ASSETS_OFFSET = 44`, materialised and verified against `ASSETS_COMMITMENT`
  (`prologue.masm:667-704`).

Note *storage contents* are deliberately not in that list. They live in the advice map keyed by
`NOTE_STORAGE_COMMITMENT` and cost a full materialise-and-rehash of all N felts to read soundly
(`active_note.masm:322-349`). The prologue never touches them. This is why the variant is derived from
the storage *count* rather than from a tag element inside it; see
[#2901](https://github.com/0xMiden/protocol/issues/2901).

Reading the `NetworkAccountTarget` attachment costs two advice-map lookups: one to pipe the
per-attachment commitment list, one for the attachment itself, each verified against its commitment
(`note.masm:98-125`, `note.masm:142-168`). Locating it is free (metadata word only,
`active_note.masm:450-459`).

## Component-id dispatch

The prologue must run only for accounts that expose `FeeManager`, and the trigger must be something
the kernel recognises structurally, not a metadata flag and not a duck-typed probe of arbitrary
procedures.

Account storage slots are name-addressed. `StorageSlotId` is the first two field elements of
`blake3(slot_name)` (`crates/miden-protocol/src/account/storage/slot/slot_id.rs:16-46`), slots are
sorted by that ID, and the kernel resolves them by binary search
(`account.masm:1597-1611`). Crucially, `has_storage_slot` (`account.masm:363-374`) answers "does the
active account have a slot with this ID?" without panicking.

So the component id is a **protocol-reserved storage slot ID**, held by the kernel as a compile-time
constant:

```
FEE_SCHEDULE_SLOT_ID = word("miden::protocol::fees::fee_schedule")[0..2]
FEE_CONFIG_SLOT_ID   = word("miden::protocol::fees::fee_config")[0..2]
```

Precedent is exact. `miden::protocol::faucet::callback::on_before_asset_added_to_account` is a slot
name defined in the protocol crate (`crates/miden-protocol/src/asset/asset_callbacks.rs:10-17`) and
populated by a standards component, `TokenPolicyManager`
(`crates/miden-standards/src/account/policies/manager.rs:638-644`). The fee schedule is the same
arrangement.

The kernel cannot hash a string at runtime, so the name must be fixed at kernel build time. That is
the one coupling this introduces, and it is the same coupling asset callbacks already accept.

## Prologue

Runs before `prepare_note`, once per input note.

```
proc note_fee_prologue                      # [] -> []
    if !has_storage_slot(FEE_CONFIG_SLOT_ID):
        return                              # not a FeeManager account; no fee path at all

    note_ptr     := memory::get_active_input_note_ptr()
    SCRIPT_ROOT  := memory::get_input_note_script_root(note_ptr)
    variant_tag  := memory::get_input_note_num_storage_items(note_ptr)

    # ---- resolve the price -------------------------------------------------
    ENTRY := get_map_item(FEE_SCHEDULE_SLOT_ID,
                          poseidon2::hash_words(SCRIPT_ROOT, [variant_tag, 0, 0, 0]))
    if ENTRY == EMPTY_WORD:
        ENTRY := get_map_item(FEE_SCHEDULE_SLOT_ID,
                              poseidon2::hash_words(SCRIPT_ROOT, [VARIANT_WILDCARD, 0, 0, 0]))

    [_, default_deny, dry_run, _, _] := find_item(FEE_CONFIG_SLOT_ID)

    if ENTRY == EMPTY_WORD:
        assert(default_deny == 0, ERR_FEE_NO_SCHEDULE_ENTRY)
        return                              # unpriced and permitted; free

    [amount, flags, r0, r1] := ENTRY
    assert(r0 == 0 && r1 == 0, ERR_FEE_ENTRY_RESERVED_NOT_ZERO)
    assert(flags & 1 == 1,     ERR_FEE_ENTRY_DISABLED)
    assert(flags >> 1 == 0,    ERR_FEE_ENTRY_RESERVED_NOT_ZERO)

    # ---- check the creator's ceiling ---------------------------------------
    (found, MAX_FEE_ASSET) := find_attachment(NETWORK_ACCOUNT_TARGET_SCHEME).word[1]
    assert(found,                                       ERR_FEE_NO_TARGET_ATTACHMENT)
    assert(MAX_FEE_ASSET.faucet_id == fee_faucet_id(),  ERR_FEE_MAX_FEE_WRONG_FAUCET)
    assert(amount <= MAX_FEE_ASSET.amount,              ERR_FEE_EXCEEDS_MAX_FEE)

    if amount == 0:
        return

    # ---- pull exactly `amount` ---------------------------------------------
    (found, asset_ptr) := find_note_asset(note_ptr, fee_faucet_id())
    assert(found,                                       ERR_FEE_ASSET_NOT_IN_NOTE)
    assert(mem[asset_ptr].amount >= amount,             ERR_FEE_INSUFFICIENT_NOTE_BALANCE)

    if dry_run == 0:
        mem[asset_ptr].amount -= amount                 # requires #3242
        memory::add_tx_fee_accumulator(amount)
    else:
        emit.FEE_PROLOGUE_DRY_RUN_EVENT                 # host observes; nothing is moved
end
```

`fee_faucet_id()` reads `FEE_FAUCET_ID_SUFFIX_PTR` / `FEE_FAUCET_ID_PREFIX_PTR` (834 and 835,
`memory.masm:156-157`). The memory region survived [#3108](https://github.com/0xMiden/protocol/pull/3108);
its accessor did not, and must be restored. That is one procedure.

### Revert conditions

- `ERR_FEE_NO_SCHEDULE_ENTRY` - no exact entry, no wildcard, `default_deny = 1`.
- `ERR_FEE_ENTRY_DISABLED` - entry exists with `enabled = 0`.
- `ERR_FEE_ENTRY_RESERVED_NOT_ZERO` - reserved felts or reserved flag bits are nonzero. Forward
  compatibility: an old kernel meeting a schema it does not understand reverts rather than misreading.
- `ERR_FEE_NO_TARGET_ATTACHMENT` - a priced note carries no `NetworkAccountTarget`.
- `ERR_FEE_MAX_FEE_WRONG_FAUCET` - the ceiling names an asset that is not the protocol fee token.
- `ERR_FEE_EXCEEDS_MAX_FEE` - the schedule outgrew the creator's ceiling between note creation and
  consumption. This is the in-flight-note protection.
- `ERR_FEE_ASSET_NOT_IN_NOTE` / `ERR_FEE_INSUFFICIENT_NOTE_BALANCE` - the note did not fund itself.

Every one of these aborts the whole transaction, so no partial fee is ever retained.

### Why `EMPTY_WORD` is safe to overload

There is no `find_map_item`. `get_map_item` (`account.masm:495`) returns `EMPTY_WORD` for an absent
key, indistinguishable from a stored `[0,0,0,0]`. Requiring `enabled = 1` on every live entry closes
this: a genuinely free note is stored as `[0, 1, 0, 0]`, and `EMPTY_WORD` unambiguously means absent.

## Epilogue

The per-note epilogue is small. Its job is to confirm the prologue's route survived the script, and
nothing else.

```
proc note_fee_epilogue                      # [] -> []
    if !has_storage_slot(FEE_CONFIG_SLOT_ID): return
    assert(memory::get_tx_fee_accumulator() == expected_after_this_note,
           ERR_FEE_ACCUMULATOR_TAMPERED)
end
```

The transaction-level handoff happens once, in `epilogue::finalize_transaction`
(`epilogue.masm:249`), before the asset-preservation check:

```
    total := memory::get_tx_fee_accumulator()
    if total > 0:
        emit_fee_note(FungibleAsset(fee_faucet_id(), total))   # #3117
```

Per [#2899](https://github.com/0xMiden/protocol/discussions/2899), the `FeeNote` is payable to nobody
and consumable by anyone, so the batch builder collects it during batch construction. One note per
transaction, not per input note.

### Excess needs no refund

Asset preservation is a global multiset check, not a per-note emptiness check:
`input_vault_root == output_vault_root` at `epilogue.masm:262-264`
(`ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME`). The input vault was built in the
transaction prologue from every input note's full assets (`prologue.masm:713-756`). The output vault is
the account's final vault plus every output note's assets (`build_output_vault`, `epilogue.masm:100-177`).

So the fee leaves via the `FeeNote` and the remainder leaves via whatever the note script did with it.
The books balance without anybody emptying anything. This dissolves the "dangling balance" objection
raised on [#2901](https://github.com/0xMiden/protocol/issues/2901): a note that overpays simply keeps
the surplus in its own asset list, and the script disposes of it exactly as it would have without fees.

## Prerequisite: input note assets must become mutable

`mem[asset_ptr].amount -= amount` has no equivalent today. Input note assets are written once in
`process_note_assets` (`prologue.masm:667-704`) and never mutated; the only setter is
`set_input_note_num_assets`. `active_note::get_assets` (`active_note.masm:40-66`) reads that same
memory.

This matters, and skipping it is not an option. If the prologue credits the fee to the accumulator but
leaves the note's asset list untouched, the script's `get_assets` still reports the full amount, sweeps
it into the account, and the fee is counted twice. The output vault then exceeds the input vault and
`ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME` fires. Every priced note would break.

That mutation is [#3242](https://github.com/0xMiden/protocol/issues/3242), "Make input note assets
stateful". This issue depends on it, and needs only a subset:

- decrement the amount of one fungible asset, identified by faucet ID, in one input note's asset region
- if the amount reaches zero, either leave a zero-amount entry or compact the list and decrement
  `num_assets`; the choice must match whatever `#3242` settles on, since `get_assets` and
  `ASSETS_COMMITMENT` recomputation both depend on it

Worth noting: this is the mechanical root of the "infectious fees" objection raised in
[#2968](https://github.com/0xMiden/protocol/discussions/2968), that a fee-aware note can no longer call
`active_note::get_assets` directly. The kernel prologue *solves* that problem rather than pushing it
onto note authors. By the time a script runs, the fee is already gone from the note it can see, and
`add_assets_to_account` does the right thing unchanged.

## Trust model

What the kernel guarantees, unconditionally, for any note consumed by a `FeeManager` account:

- Pay-fee runs. It is not a call the script makes, so it cannot be skipped, reordered, or branched
  around.
- `script_root` is authentic. Kernel-provided from note memory, folded into `RECIPIENT`, asserted
  against `INPUT_NOTES_COMMITMENT`.
- `variant_tag` is structural and authenticated. It is the note's storage element count, bound through
  `STORAGE_COMMITMENT` into the note ID. Neither the script nor the creator can present a different
  count for the same note.
- `max_fee` is authenticated. It rides in an attachment bound into `NOTE_METADATA_COMMITMENT`, not in
  note args, which the prologue itself documents as unauthenticated (`prologue.masm:584-603`).
- The fee asset is the protocol fee token. Taken from the block header, never from the schedule.
- The fee reaches the batch builder or the transaction reverts.

What remains a note-authoring convention. Exactly one item:

> A priced script's fee-relevant dispatch must be a function of `num_storage_items`.

If a script branches on something the count cannot see, and the operator wants those branches priced
differently, the derivation is blind to it and both branches carry the same price. This is checkable by
reading the script, and it is checked once, at `set_fee` time, because the schedule is an allowlist.

Two observations on how narrow this is in practice. MINT already dispatches exactly this way
(`mint_fungible.masm:127-128`). And B2AGG's reclaim-versus-bridge-out split, which the count cannot see
(`b2agg.masm:61-71`), does not need it: reclaim is consumed by the user's own account, which has no
`fee_schedule` slot, so the prologue never fires. The component gate separates them for free.

## Test plan

Unit tests, one per revert path, in `crates/miden-testing/src/kernel_tests/tx/`:

- account without the fee slots: prologue is a no-op, note consumes as today
- schedule miss with `default_deny = 1`: `ERR_FEE_NO_SCHEDULE_ENTRY`
- schedule miss with `default_deny = 0`: note is free, nothing accumulates
- exact entry shadows a wildcard entry
- wildcard entry catches an unbounded count (MINT public, counts 20 and 40)
- `enabled = 0`: `ERR_FEE_ENTRY_DISABLED`
- nonzero reserved felt, and nonzero reserved flag bit: `ERR_FEE_ENTRY_RESERVED_NOT_ZERO`
- priced note with no `NetworkAccountTarget`: `ERR_FEE_NO_TARGET_ATTACHMENT`
- `max_fee` denominated in a non-fee faucet: `ERR_FEE_MAX_FEE_WRONG_FAUCET`
- `amount > max_fee`: `ERR_FEE_EXCEEDS_MAX_FEE`
- note carries no fee asset: `ERR_FEE_ASSET_NOT_IN_NOTE`
- note carries too little: `ERR_FEE_INSUFFICIENT_NOTE_BALANCE`
- `amount == 0` with an enabled entry: no accumulation, no note-asset mutation
- `dry_run = 1`: event emitted, accumulator and note assets unchanged
- two priced notes in one transaction: accumulator sums, exactly one `FeeNote` is emitted

Per the repo convention, each of these asserts on its specific error code rather than on "it panicked".

Integration tests, exercising the full loop with a `FeeManager`-bearing network account:

- BURN, fee asset distinct from the burn asset
- BURN, fee asset and burn asset sharing a faucet (the single-combined-asset case), which is the
  interaction [#2343](https://github.com/0xMiden/protocol/issues/2343) has to land for
- CLAIM L1 (313 storage elements) and CLAIM L2 (569), priced differently, each asserting the other's
  price is not charged
- CLAIM with a count that disagrees with its `mainnetFlag`: script-side assertion, transaction reverts
- UPDATE_GER, CONFIG_AGG_BRIDGE
- B2AGG bridge-out (priced) and B2AGG reclaim by the sender's own account (prologue never fires)
- a chained network transaction: B2AGG funds the bridge, the bridge's output note funds the faucet,
  and the fee budget travels down the chain inside the notes

Reuse the existing fixtures in `crates/miden-testing` rather than hand-rolling accounts and notes.

## Rollout

`dry_run` is a bit in the account's `fee_config` slot, not a global kernel flag. With it set, the
prologue performs every lookup and every assertion, emits a host event carrying the resolved
`(script_root, variant_tag, amount)`, and moves nothing. Failures still revert, so an operator learns
about missing schedule entries before the first real charge rather than after.

Making it per-account rather than per-kernel matters. Accounts opt in independently, on their own
schedule, with no kernel redeploy and no coordinated flag day. The bridge can run dry for a week while
the faucet is already live.

Sequence:

1. [#3242](https://github.com/0xMiden/protocol/issues/3242), or the subset above, lands. Restore the
   fee-faucet getter removed by [#3108](https://github.com/0xMiden/protocol/pull/3108).
2. Kernel prologue and epilogue land behind `has_storage_slot`, so accounts without the slots are
   byte-for-byte unaffected.
3. `FeeManager` component and Rust builders land ([#2901](https://github.com/0xMiden/protocol/issues/2901)).
4. Network accounts install it with `dry_run = 1`, `default_deny = 0`. Nothing changes.
5. Operators populate schedules. Dry-run events confirm coverage.
6. Flip `dry_run = 0`, then `default_deny = 1`, per account.
7. Swap accumulator-to-`FeeNote` in for whatever [#2899](https://github.com/0xMiden/protocol/discussions/2899)
   lands on. No note script and no component changes.

## Open questions

The fee schedule becomes a second, earlier allowlist. `AuthNetworkAccount`'s note allowlist runs in
the transaction epilogue's auth procedure (`epilogue.masm:194-207`), after every note script has
already run. With `default_deny = 1`, an unpriced script now fails before its script executes. That is
strictly better, but it means two allowlists can disagree, and nothing validates them against each
other. `AccountBuilder` has no cross-component validation hook, so this has to be a higher-level
wrapper's job.

`NOTE_EXECUTION_START_EVENT` (`main.masm:101`) currently brackets exactly the note script. Should the
prologue run inside or outside the bracket? Hosts observing note execution will see the boundary move.

`compute_fee` is `clk`-based (`tx.masm:233-266`). Prologue cycles are charged to the user as protocol
fee, on top of the network-account fee the prologue just pulled. That is arguably correct, and worth
being deliberate about.

Whether the kernel may depend on a standards-defined slot name. Asset callbacks already set this
precedent, but the fee schedule makes the protocol crate aware of a fee *policy* concept, not just a
callback hook.

Whether [#2968](https://github.com/0xMiden/protocol/discussions/2968)'s `NetworkSponsorshipNote` moots
this design. That thread is unresolved, and at least one maintainer prefers the multi-note shape on
separation-of-concerns grounds. The strongest argument this design has against it is the one in the
prerequisite section: the kernel prologue removes the "infectious fees" problem that motivates the
sponsorship note, by making the fee invisible to the script that runs after it.

Whether `variant_tag` should be `num_storage_items` or a saturating function of it. A saturating clamp
would remove the need for `VARIANT_WILDCARD`, but it collides distinct large-storage variants of the
same script into one price, which CLAIM's 313 and 569 make immediately fatal. Wildcard it is, but the
asymmetry is worth naming.

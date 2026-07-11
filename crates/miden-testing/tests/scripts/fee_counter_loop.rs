//! End-to-end test of a self-perpetuating network state machine under the sponsorship fee model.
//!
//! A counter account consumes an increment note plus its sponsorship. The increment note bumps the
//! count and -- while the sponsored budget left after its own fee covers another hop -- spawns the
//! next increment note, targeted back at the same account. The account's auth procedure funds a
//! fresh sponsorship for the spawned note with the entire remainder. The loop feeds itself until
//! the budget runs out, at which point the terminal hop simply stops spawning.

use std::collections::BTreeSet;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::auth::AuthNetworkAccountWithFees;
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP;
use miden_standards::note::{FeeNote, NetworkSponsorshipNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

const APP_FEE: u64 = 30;
const PROTOCOL_FEE: u64 = 12;
const HOP_FEE: u64 = APP_FEE + PROTOCOL_FEE;

fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, amount)?.into())
}

/// The counter component. The increment note stays thin; the spawn decision consults the fee
/// manager through `active_note_remainder`, which shares its formula with `settle_fees`, so a
/// note-time decision to spawn is always funded at auth time.
const COUNTER_COMPONENT_CODE: &str = r#"
    use miden::core::crypto::hashes::poseidon2
    use miden::protocol::active_account
    use miden::protocol::active_note
    use miden::protocol::native_account
    use miden::protocol::note
    use miden::protocol::output_note
    use {NOTE_TYPE_PUBLIC} from miden::protocol::note
    use {ALWAYS} from miden::standards::note::execution_hint
    use miden::standards::attachments::network_account_target
    use miden::standards::fees::fee_manager

    #! The storage slot holding the count as [count, 0, 0, 0].
    const COUNT_SLOT = word("test::counter::count")

    #! Local memory offset passed as the (empty) note storage region of the spawned note.
    const CHILD_NOTE_STORAGE_LOC = 0

    #! Increments the count, then spawns the next increment note -- same script, targeted at this
    #! account -- iff the sponsorship budget left after this note's own fee covers the next hop.
    #!
    #! Inputs:  [pad(16)]
    #! Outputs: [pad(16)]
    #!
    #! Invocation: call
    @locals(4)
    @account_procedure
    pub proc increment_and_maybe_respawn
        push.COUNT_SLOT[0..2] exec.active_account::get_item
        # => [count, 0, 0, 0, pad(16)]

        add.1
        # => [new_count, 0, 0, 0, pad(16)]

        push.COUNT_SLOT[0..2] exec.native_account::set_item dropw
        # => [pad(16)]

        exec.fee_manager::active_note_remainder
        # => [remainder, pad(16)]

        # the next hop runs the same script, so it costs the same schedule entry
        exec.active_note::get_script_root exec.fee_manager::fee_total
        # => [next_fee, remainder, pad(16)]

        gte
        # => [remainder >= next_fee, pad(16)]

        if.true
            exec.active_note::get_script_root
            # => [SCRIPT_ROOT, pad(16)]

            # serial: hash-chained from the parent serial, so every hop's serial is distinct
            padw exec.active_note::get_serial_number
            # => [PARENT_SERIAL, ZERO_WORD, SCRIPT_ROOT, pad(16)]

            exec.poseidon2::merge
            # => [CHILD_SERIAL, SCRIPT_ROOT, pad(16)]

            push.0 locaddr.CHILD_NOTE_STORAGE_LOC
            # => [storage_ptr, num_storage_items, CHILD_SERIAL, SCRIPT_ROOT, pad(16)]

            exec.note::compute_and_store_recipient
            # => [RECIPIENT, pad(16)]

            push.NOTE_TYPE_PUBLIC push.0
            # => [tag, note_type, RECIPIENT, pad(16)]

            exec.output_note::create
            # => [note_idx, pad(16)]

            # route the next hop at ourselves: the loop feeds itself
            push.ALWAYS exec.active_account::get_id
            # => [id_suffix, id_prefix, exec_hint_tag, note_idx, pad(16)]

            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT, note_idx, pad(16)]

            exec.output_note::add_word_attachment
            # => [pad(16)]
        end
    end
"#;

/// The increment note: entirely fee-unaware in shape, it just calls into the account.
const INCREMENT_NOTE_CODE: &str = r#"
    use test::counter

    @note_script
    pub proc main
        dropw
        # => [pad(16)]

        call.counter::increment_and_maybe_respawn
        # => [pad(16)]
    end
"#;

struct Fixture {
    mock_chain: MockChain,
    account: Account,
    incr_note: Note,
    sponsorship_note: Note,
    incr_script: NoteScript,
    count_slot: StorageSlotName,
}

/// Builds the counter account, the first increment note, and one sponsorship carrying `budget`.
fn setup(budget: u64) -> anyhow::Result<Fixture> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let component_code =
        CodeBuilder::default().compile_component_code("test::counter", COUNTER_COMPONENT_CODE)?;
    let incr_script = CodeBuilder::default()
        .with_linked_module("test::counter", COUNTER_COMPONENT_CODE)?
        .compile_note_script(INCREMENT_NOTE_CODE)?;
    let incr_root = incr_script.root();

    // The increment note is priced like any feature note, and declared as spawning itself.
    let fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?
        .with_fee(incr_root, FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?)
        .with_spawn(incr_root, incr_root);

    let auth = AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from([incr_root]))?;

    let count_slot = StorageSlotName::new("test::counter::count")?;
    let counter_component = AccountComponent::new(
        component_code,
        vec![StorageSlot::with_value(count_slot.clone(), Word::empty())],
        AccountComponentMetadata::new("test::counter"),
    )?;

    let account = AccountBuilder::new([21u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .with_component(counter_component)
        .build_existing()?;
    builder.add_account(account.clone())?;

    let incr_note = NoteBuilder::new(sponsor.id(), &mut rng)
        .note_type(miden_protocol::note::NoteType::Public)
        .script(incr_script.clone())
        .build()?;
    builder.add_output_note(RawOutputNote::Full(incr_note.clone()));

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(account.id())?
            .feature_note_id(incr_note.id())
            .asset(fee_asset(budget)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    Ok(Fixture {
        mock_chain: builder.build()?,
        account,
        incr_note,
        sponsorship_note,
        incr_script,
        count_slot,
    })
}

/// The state machine increments once per hop and stops by itself when the budget runs dry.
///
/// With `budget = hops * HOP_FEE + dust` (dust < HOP_FEE), the loop runs exactly `hops` times:
/// each hop keeps its application fee, forwards its protocol fee in a FEE note, and passes the
/// entire remainder into the next hop's sponsorship. The terminal hop finds the remainder below
/// the next fee, spawns nothing, and the dust stays with the account.
#[rstest]
#[case::uneven_budget(3 * HOP_FEE + 24, 24)]
#[case::exact_budget(3 * HOP_FEE, 0)]
#[tokio::test]
async fn counter_increments_until_the_budget_runs_out(
    #[case] budget: u64,
    #[case] dust: u64,
) -> anyhow::Result<()> {
    const HOPS: u64 = 3;
    let f = setup(budget)?;
    let incr_root = f.incr_script.root();

    let mut mock_chain = f.mock_chain;
    let mut account = f.account;
    let (mut sponsorship_id, mut incr_id) = (f.sponsorship_note.id(), f.incr_note.id());
    let mut remaining = budget;
    let mut protocol_total = 0u64;

    for hop in 1..=HOPS {
        let executed = mock_chain
            .build_tx_context(account.id(), &[sponsorship_id, incr_id], &[])?
            .add_note_script(f.incr_script.clone())
            .add_note_script(NetworkSponsorshipNote::script())
            .add_note_script(FeeNote::script())
            .build()?
            .execute()
            .await?;

        account.apply_patch(executed.account_patch())?;
        let expected_count = Word::new([Felt::new(hop)?, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        assert_eq!(account.storage().get_item(&f.count_slot)?, expected_count);

        let find = |root: NoteScriptRoot| {
            executed.output_notes().iter().find(|note| {
                note.recipient().expect("public note exposes its recipient").script().root() == root
            })
        };

        let fee_note = find(FeeNote::script_root()).expect("every hop emits a FEE note");
        assert_eq!(fee_note.assets().iter().next().copied(), Some(fee_asset(PROTOCOL_FEE)?));
        protocol_total += PROTOCOL_FEE;

        remaining -= HOP_FEE;
        if remaining >= HOP_FEE {
            assert_eq!(
                executed.output_notes().num_notes(),
                3,
                "a funded hop spawns the next increment note and its sponsorship",
            );
            let next_incr = find(incr_root).expect("the next increment note is spawned");
            let next_sponsorship = find(NetworkSponsorshipNote::script_root())
                .expect("the next sponsorship is minted");
            assert_eq!(
                next_sponsorship.assets().iter().next().copied(),
                Some(fee_asset(remaining)?),
                "the entire remainder travels into the next hop",
            );
            (sponsorship_id, incr_id) = (next_sponsorship.id(), next_incr.id());
        } else {
            assert_eq!(
                executed.output_notes().num_notes(),
                1,
                "the terminal hop emits only its FEE note",
            );
        }

        mock_chain.add_pending_executed_transaction(&executed)?;
        mock_chain.prove_next_block()?;
    }

    // Conservation: the budget split into per-hop application fees, the dust, and the FEE notes.
    assert_eq!(account.vault().get_balance(fee_asset(0)?.id())?.as_u64(), HOPS * APP_FEE + dust,);
    assert_eq!(protocol_total, HOPS * PROTOCOL_FEE);
    assert_eq!(HOPS * APP_FEE + dust + protocol_total, budget);

    Ok(())
}

/// A first hop that cannot even cover its own fee is rejected outright.
#[tokio::test]
async fn underfunded_first_hop_is_rejected() -> anyhow::Result<()> {
    let f = setup(HOP_FEE - 1)?;

    let result = f
        .mock_chain
        .build_tx_context(f.account.id(), &[f.sponsorship_note.id(), f.incr_note.id()], &[])?
        .add_note_script(f.incr_script.clone())
        .add_note_script(NetworkSponsorshipNote::script())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}

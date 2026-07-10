//! Tests for the `FeeManager` account component.

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{AccessControl, Authority};
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_ENABLED_NOT_BOOLEAN,
    ERR_FEE_MANAGER_FEE_EXCEEDS_MAX_ASSET_AMOUNT,
    ERR_FEE_MANAGER_SCRIPT_NOT_PRICED,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{FeeNote, NetworkSponsorshipNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use rstest::rstest;

const APP_FEE: u64 = 30;
const PROTOCOL_FEE: u64 = 12;

/// Adds a public account carrying `FeeManager` + `Authority` + `BasicWallet`, pricing the FEE note
/// script at `APP_FEE` / `PROTOCOL_FEE`.
fn add_fee_managed_account(builder: &mut MockChainBuilder, seed: u8) -> anyhow::Result<Account> {
    let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let fee_manager = FeeManager::new(fee_faucet)?
        .with_fee(FeeNote::script_root(), FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?);

    let account_builder = AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Returns the ASSET_ID word of the fee asset used throughout these tests.
fn fee_asset_id_word() -> anyhow::Result<Word> {
    let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    Ok(FungibleAsset::new(fee_faucet, 0)?.to_id_word())
}

/// `estimate_note_fee` returns `app_fee + protocol_fee`, denominated in the account's fee asset.
///
/// The estimator ignores the storage and attachments commitments and the timeframe, but takes them
/// so that a richer estimator can replace it without changing any caller.
#[tokio::test]
async fn estimate_note_fee_returns_the_scheduled_total() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 1)?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            push.0
            padw
            padw
            push.{script_root}
            # => [SCRIPT_ROOT, STORAGE_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, pad(3)]

            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]

            push.{fee_asset_id}
            assert_eqw.err="estimate_note_fee returned the wrong fee asset"
            # => [FEE_ASSET_VALUE, pad(8)]

            push.{expected_total}
            assert_eq.err="estimate_note_fee returned the wrong fee amount"
            # => [0, 0, 0, pad(8)]

            exec.sys::truncate_stack
        end
        "#,
        script_root = NoteScriptRoot::as_word(&FeeNote::script_root()),
        fee_asset_id = fee_asset_id_word()?,
        expected_total = APP_FEE + PROTOCOL_FEE,
    ))?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `get_fee_asset_id` tells a note creator which asset to put in the sponsorship note.
#[tokio::test]
async fn get_fee_asset_id_returns_the_accepted_asset() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 5)?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            call.fee_manager::get_fee_asset_id
            # => [FEE_ASSET_ID, pad(12)]

            push.{fee_asset_id}
            assert_eqw.err="get_fee_asset_id returned the wrong asset"

            exec.sys::truncate_stack
        end
        "#,
        fee_asset_id = fee_asset_id_word()?,
    ))?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// An unpriced script root is rejected rather than treated as free.
#[tokio::test]
async fn estimate_note_fee_rejects_an_unpriced_script() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 2)?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            push.0
            padw
            padw
            push.{unpriced_root}
            call.fee_manager::estimate_note_fee
            exec.sys::truncate_stack
        end
        "#,
        // The sponsorship note's own script is never priced: it is not a feature note.
        unpriced_root = NoteScriptRoot::as_word(&NetworkSponsorshipNote::script_root()),
    ))?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SCRIPT_NOT_PRICED);

    Ok(())
}

/// `estimate_note_fee` is reachable over a foreign procedure invocation.
///
/// This is what makes chained network transactions work: an upstream network account can price a
/// note it is about to spawn against the downstream account that will consume it, before that note
/// exists, and without the upstream account fronting any liquidity.
#[tokio::test]
async fn estimate_note_fee_is_callable_over_fpi() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let downstream = add_fee_managed_account(&mut builder, 3)?;
    let upstream = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # inputs of the foreign procedure, deepest first
            push.0
            padw
            padw
            push.{script_root}
            # => [SCRIPT_ROOT, STORAGE_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe]

            push.{estimate_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_id_suffix, foreign_id_prefix, FOREIGN_PROC_ROOT, inputs...]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, ...]

            push.{fee_asset_id}
            assert_eqw.err="foreign estimate returned the wrong fee asset"

            push.{expected_total}
            assert_eq.err="foreign estimate returned the wrong fee amount"

            exec.sys::truncate_stack
        end
        "#,
        script_root = NoteScriptRoot::as_word(&FeeNote::script_root()),
        estimate_root = FeeManager::estimate_note_fee_root().as_word(),
        foreign_prefix = downstream.id().prefix().as_felt(),
        foreign_suffix = downstream.id().suffix(),
        fee_asset_id = fee_asset_id_word()?,
        expected_total = APP_FEE + PROTOCOL_FEE,
    ))?;

    let foreign_inputs = mock_chain.get_foreign_account_inputs(downstream.id())?;

    mock_chain
        .build_tx_context(upstream.id(), &[], &[])?
        .foreign_accounts(vec![foreign_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `set_fee` prices a script, and `remove_fee` unprices it again.
#[tokio::test]
async fn set_fee_and_remove_fee_round_trip() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 4)?;
    let mock_chain = builder.build()?;

    // Price the sponsorship script root, then read it back through `estimate_note_fee`.
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            push.1 push.{protocol_fee} push.{app_fee}
            push.{target_root}
            # => [SCRIPT_ROOT, app_fee, protocol_fee, enabled, pad(9)]
            call.fee_manager::set_fee
            dropw dropw dropw dropw

            push.0 padw padw push.{target_root}
            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
            dropw
            push.{expected_total}
            assert_eq.err="set_fee did not take effect"
            dropw dropw dropw

            push.{target_root}
            call.fee_manager::remove_fee
            exec.sys::truncate_stack
        end
        "#,
        target_root = NoteScriptRoot::as_word(&NetworkSponsorshipNote::script_root()),
        app_fee = 7u64,
        protocol_fee = 5u64,
        expected_total = 12u64,
    ))?;

    let executed = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    // The removal must be visible in the final account state.
    let mut account = account;
    account.apply_patch(executed.account_patch())?;
    let entry = account.storage().get_map_item(
        FeeManager::fee_schedule_slot(),
        StorageMapKey::new(NoteScriptRoot::as_word(&NetworkSponsorshipNote::script_root())),
    )?;
    assert_eq!(entry, Word::from([Felt::ZERO; 4]), "remove_fee should clear the entry");

    Ok(())
}

/// Compiles a tx script that prices the sponsorship script root with the provided raw entry.
fn set_fee_tx_script(
    app_fee: u64,
    protocol_fee: u64,
    enabled: u64,
) -> anyhow::Result<miden_protocol::transaction::TransactionScript> {
    Ok(CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::fees::fee_manager

        @transaction_script
        pub proc main
            push.{enabled} push.{protocol_fee} push.{app_fee}
            push.{target_root}
            # => [SCRIPT_ROOT, app_fee, protocol_fee, enabled, pad(9)]
            call.fee_manager::set_fee
            exec.sys::truncate_stack
        end
        "#,
        target_root = NoteScriptRoot::as_word(&NetworkSponsorshipNote::script_root()),
    ))?)
}

/// `set_fee` only accepts 0 or 1 for the enabled flag.
#[tokio::test]
async fn set_fee_rejects_a_non_boolean_enabled_flag() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 6)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(set_fee_tx_script(7, 5, 2)?)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_ENABLED_NOT_BOOLEAN);

    Ok(())
}

/// `set_fee` bounds the portions by the maximum fungible asset amount, individually and summed,
/// mirroring the Rust-side validation in `FeeScheduleEntry::new`.
#[rstest]
#[case::app_fee_too_large(u64::from(FungibleAsset::MAX_AMOUNT) + 1, 0)]
#[case::protocol_fee_too_large(0, u64::from(FungibleAsset::MAX_AMOUNT) + 1)]
#[case::sum_too_large(u64::from(FungibleAsset::MAX_AMOUNT), 1)]
#[tokio::test]
async fn set_fee_rejects_portions_exceeding_the_max_asset_amount(
    #[case] app_fee: u64,
    #[case] protocol_fee: u64,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_fee_managed_account(&mut builder, 7)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(set_fee_tx_script(app_fee, protocol_fee, 1)?)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_FEE_EXCEEDS_MAX_ASSET_AMOUNT);

    Ok(())
}

/// `set_fee` is gated by the installed `Authority`: under `Ownable2Step`, a note from a non-owner
/// sender cannot reprice the schedule.
#[tokio::test]
async fn set_fee_rejects_an_unauthorized_sender() -> anyhow::Result<()> {
    let owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([11; 32]);
    let non_owner = AccountId::builder()
        .account_type(AccountType::Private)
        .build_with_seed([99; 32]);

    let fee_faucet = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;
    let fee_manager = FeeManager::new(fee_faucet)?
        .with_fee(FeeNote::script_root(), FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?);

    let mut builder = MockChain::builder();
    let account_builder = AccountBuilder::new([8; 32])
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(fee_manager);
    let account =
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?;

    let seed: [u32; 4] = rand::random();
    let mut rng = RandomCoin::new(Word::from(seed));
    let attacker_note = NoteBuilder::new(non_owner, &mut rng)
        .note_type(NoteType::Private)
        .code(format!(
            r#"
            use miden::standards::fees::fee_manager

            @note_script
            pub proc main
                repeat.16 push.0 end
                push.1 push.5 push.7
                push.{target_root}
                call.fee_manager::set_fee
                dropw dropw dropw dropw
            end
            "#,
            target_root = NoteScriptRoot::as_word(&NetworkSponsorshipNote::script_root()),
        ))
        .build()?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(account.id(), &[attacker_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

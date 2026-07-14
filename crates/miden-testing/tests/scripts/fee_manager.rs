extern crate alloc;

use miden_protocol::account::{AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::FeeManager;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder};
use rstest::rstest;

// HELPERS
// ================================================================================================

/// The fee scheduled for [`priced_root`] in these tests.
const FEE_AMOUNT: u64 = 500;

fn fee_faucet_id() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)
}

/// The note script root priced in the fee schedule.
fn priced_root() -> NoteScriptRoot {
    NoteScriptRoot::from_array([1, 2, 3, 4])
}

/// Builds a `FeeManager` accepting fees in the test faucet's asset and charging [`FEE_AMOUNT`]
/// for notes with the [`priced_root`] script root.
fn fee_manager() -> anyhow::Result<FeeManager> {
    Ok(FeeManager::new(fee_faucet_id()?).with_fee(priced_root(), AssetAmount::new(FEE_AMOUNT)?))
}

/// Returns the asset value word `[fee_amount, 0, 0, 0]` for the given amount.
fn fee_value_word(amount: u64) -> anyhow::Result<Word> {
    Ok(Word::new([
        AssetAmount::new(amount)?.into(),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ]))
}

// TESTS
// ================================================================================================

/// `FeeManager::estimate_note_fee`, invoked via `call` from a transaction script, returns the
/// account's fee asset ID and the fee amount scheduled for the queried note script root. Roots
/// without a schedule entry estimate to an amount of 0. A wrong result aborts the transaction,
/// so successful execution proves the returned fee asset.
#[rstest]
#[case::priced_root(priced_root(), FEE_AMOUNT)]
#[case::unknown_root(NoteScriptRoot::from_array([5, 6, 7, 8]), 0)]
#[tokio::test]
async fn estimate_note_fee_returns_scheduled_fee(
    #[case] queried_root: NoteScriptRoot,
    #[case] expected_amount: u64,
) -> anyhow::Result<()> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_component(fee_manager()?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The tx script argument is placed on top of the initial operand stack, so the script starts
    // with `[NOTE_SCRIPT_ROOT, pad(12)]` - exactly the `estimate_note_fee` inputs with the
    // reserved commitments zeroed.
    let tx_script_code = format!(
        r#"
        use miden::standards::components::fees::fee_manager

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]
            call.fee_manager::estimate_note_fee
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]

            push.{expected_fee_asset_id}
            assert_eqw.err="estimate_note_fee should return the account's fee asset ID"
            # => [FEE_ASSET_VALUE, pad(12)]

            push.{expected_fee_value}
            assert_eqw.err="estimate_note_fee should return the scheduled fee amount"
            # => [pad(16)]
        end
        "#,
        expected_fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word(),
        expected_fee_value = fee_value_word(expected_amount)?,
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(FeeManager::code())?
        .compile_tx_script(tx_script_code)?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(queried_root.as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `FeeManager::estimate_note_fee` invoked on a foreign account via FPI
/// (`tx::execute_foreign_procedure`), mirroring how the authentication component of an account
/// that creates a note targeted at a network account estimates the note's fee.
#[tokio::test]
async fn estimate_note_fee_via_fpi() -> anyhow::Result<()> {
    let foreign_account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_component(fee_manager()?)
        .build_existing()?;

    let native_account = AccountBuilder::new([2; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;

    let mut mock_chain =
        MockChainBuilder::with_accounts([native_account.clone(), foreign_account.clone()])?
            .build()?;
    mock_chain.prove_next_block()?;

    // The tx script argument supplies NOTE_SCRIPT_ROOT on top of the initial operand stack; the
    // zeros below it serve as the reserved commitments, forming the full 16-felt
    // `estimate_note_fee` inputs. The procedure root is interpolated directly so the foreign
    // library does not need to be linked.
    let tx_script_code = format!(
        r#"
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # => [NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]

            # push the estimate_note_fee procedure root and the foreign account ID
            push.{estimate_note_fee_root}
            push.{foreign_prefix} push.{foreign_suffix}
            # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
            #     NOTE_SCRIPT_ROOT, STORAGE_COMMITMENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT]

            exec.tx::execute_foreign_procedure
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]

            push.{expected_fee_asset_id}
            assert_eqw.err="foreign fee estimation should return the fee asset ID"
            # => [FEE_ASSET_VALUE, pad(12)]

            push.{expected_fee_value}
            assert_eqw.err="foreign fee estimation should return the scheduled fee amount"
            # => [pad(16)]
        end
        "#,
        estimate_note_fee_root = FeeManager::estimate_note_fee_root().mast_root(),
        foreign_prefix = foreign_account.id().prefix().as_felt(),
        foreign_suffix = foreign_account.id().suffix(),
        expected_fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word(),
        expected_fee_value = fee_value_word(FEE_AMOUNT)?,
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(foreign_account.id())?;

    mock_chain
        .build_tx_context(native_account.id(), &[], &[])?
        .foreign_accounts([foreign_account_inputs])
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
        .build()?
        .execute()
        .await?;

    Ok(())
}

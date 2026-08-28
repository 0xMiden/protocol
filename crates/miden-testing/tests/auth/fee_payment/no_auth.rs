use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::TxFeeNote;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::MockChain;

use super::VERIFICATION_BASE_FEE;

// HELPER FUNCTIONS
// ================================================================================================

/// Executes a transaction against a no-auth wallet holding `assets`, on a chain charging
/// `verification_base_fee`, and returns the account together with the raw execution result.
///
/// When `input_note` is given, the note is consumed by the transaction (needed on zero-fee
/// chains, where a note-less transaction would be rejected as a no-op).
async fn execute_no_auth_tx(
    verification_base_fee: u32,
    assets: impl IntoIterator<Item = Asset>,
    input_note: Option<Note>,
) -> anyhow::Result<(Account, Result<ExecutedTransaction, miden_tx::TransactionExecutorError>)> {
    let account = AccountBuilder::new([11; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_assets(assets)
        .account_type(AccountType::Public)
        .build_existing()?;

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    builder.add_account(account.clone())?;
    if let Some(note) = &input_note {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mock_chain = builder.build()?;

    let notes: Vec<Note> = input_note.into_iter().collect();
    let result = mock_chain
        .build_transaction(account.id())
        .unauthenticated_input_notes(notes)
        .build()?
        .execute()
        .await;

    Ok((account, result))
}

// TESTS
// ================================================================================================

/// The no-auth procedure pays the transaction fee by creating a TX_FEE note funded from the
/// account's own vault in the native fee asset, covering the computed fee.
#[tokio::test]
async fn no_auth_pays_fee_note() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let (_, result) = execute_no_auth_tx(VERIFICATION_BASE_FEE, [fee_asset], None).await?;
    let executed_transaction = result?;

    // exactly one output note is created: the fee note
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);
    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);

    // the note carries the native fee asset, covering the computed fee
    let assets = output_note.assets();
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let paid_asset = asset.unwrap_fungible();
    assert_eq!(paid_asset.faucet_id(), fee_faucet_id);
    assert!(paid_asset.amount() >= executed_transaction.compute_fee());

    Ok(())
}

/// On a chain with a zero verification base fee, a no-auth account creates no fee note. The
/// transaction consumes a note so it is not a no-op.
#[tokio::test]
async fn no_auth_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();
    let input_note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?;

    let (_, result) = execute_no_auth_tx(0, [fee_asset], Some(input_note)).await?;
    let executed_transaction = result?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    Ok(())
}

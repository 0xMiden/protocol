use std::collections::BTreeSet;

use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW;
use miden_protocol::note::{Note, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{NetworkAccountConfigNote, TxFeeNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::VERIFICATION_BASE_FEE;

// NETWORK ACCOUNT FEE PAYMENT
// ================================================================================================

/// Executes a transaction against a network-authenticated wallet holding `assets`, on a chain
/// charging `verification_base_fee`, and returns the account together with the raw execution
/// result.
///
/// When `input_note` is given, its script root is allowlisted and the note is consumed by the
/// transaction (needed on zero-fee chains, where a note-less transaction would be rejected as a
/// no-op); otherwise the transaction is empty and a placeholder root is allowlisted.
async fn execute_network_account_tx(
    verification_base_fee: u32,
    assets: impl IntoIterator<Item = Asset>,
    input_note: Option<Note>,
) -> anyhow::Result<(Account, Result<ExecutedTransaction, miden_tx::TransactionExecutorError>)> {
    let allowed_root = input_note
        .as_ref()
        .map(|note| note.script().root())
        .unwrap_or_else(|| NoteScriptRoot::from_array([1, 0, 0, 0]));
    let allowed_notes = BTreeSet::from([allowed_root]);

    // a zero-fee FeePolicyManager gives the network account the active fee policy that
    // collect_sponsored_fees requires; a constant policy aborts fee estimation for note scripts
    // without a schedule entry, so schedule an explicit 0 fee for every allowlisted note to keep
    // collection a no-op here
    let mut basic_constant_fee_policy = BasicConstantFeePolicy::new();
    for note_script in &allowed_notes {
        basic_constant_fee_policy =
            basic_constant_fee_policy.with_fee(*note_script, AssetAmount::ZERO);
    }
    // `with_allowed_notes` always allowlists the config note, priced by the auth flow if consumed.
    basic_constant_fee_policy = basic_constant_fee_policy
        .with_fee(NetworkAccountConfigNote::script_root(), AssetAmount::ZERO);
    let fee_policy_manager = FeePolicyManager::builder()
        .active_fee_policy(basic_constant_fee_policy.into())
        .fee_faucet_id(ACCOUNT_ID_FEE_FAUCET.try_into()?)
        .build();

    let auth_component = AuthNetworkAccount::new(allowed_notes, fee_policy_manager)?;

    let account = AccountBuilder::new([9; 32])
        .with_components(auth_component)
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

/// The network auth procedure pays the transaction fee by creating a TX_FEE note funded from
/// the account's own vault in the native fee asset, paying exactly the estimated fee (change
/// stays in the vault) with a bounded overshoot, and the note is client-derivable.
#[tokio::test]
async fn network_account_pays_fee_note() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let (account, result) =
        execute_network_account_tx(VERIFICATION_BASE_FEE, [fee_asset], None).await?;
    let executed_transaction = result?;

    // exactly one output note is created: the fee note
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);
    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // the note carries exactly one asset: the native fee asset
    let assets = output_note.assets();
    assert_eq!(assets.num_assets(), 1);
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let Asset::Fungible(paid_asset) = asset else {
        panic!("fee note asset should be fungible");
    };
    assert_eq!(paid_asset.faucet_id(), fee_faucet_id);

    // the paid amount covers the fee required for the actual cycle count with a bounded
    // overshoot; the rest of the vault stays with the account as change
    let required_fee = executed_transaction.compute_fee();
    assert!(
        paid_asset.amount() >= required_fee,
        "paid fee {} should cover the required fee {required_fee}",
        paid_asset.amount()
    );
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        paid_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        paid_asset.amount()
    );

    // the note has the serial number derived by `TxFeeNote::derive_serial_number`
    let ref_block_num = executed_transaction.tx_inputs().block_header().block_num();
    let expected_note: Note = TxFeeNote::builder()
        .sender(account.id())
        .serial_number(TxFeeNote::derive_serial_number(
            account.id(),
            account.nonce(),
            ref_block_num,
        ))
        .asset(*asset)
        .build()?
        .into();
    assert_eq!(output_note.id(), expected_note.id());

    Ok(())
}

/// On a chain with a zero verification base fee, a network account creates no fee note and its
/// vault is left untouched. The transaction consumes an allowlisted note so it is not a no-op.
#[tokio::test]
async fn network_account_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();
    let input_note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?;

    let (_, result) = execute_network_account_tx(0, [fee_asset], Some(input_note)).await?;
    let executed_transaction = result?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);

    Ok(())
}

/// A network account whose vault holds none of the native fee asset fails fee payment with the
/// specific vault error.
#[tokio::test]
async fn network_account_fee_payment_fails_without_funds() -> anyhow::Result<()> {
    let (_, result) = execute_network_account_tx(VERIFICATION_BASE_FEE, [], None).await?;

    assert_transaction_executor_error!(
        result,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountBuilder, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_NONCE_CANNOT_BE_0;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::pass_through::PassThroughSweep;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_AUTH_PASS_THROUGH_ACCOUNT_STATE_CHANGED;
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::PassThroughSingleP2idTransactionScript;
use miden_testing::{AccountState, Auth, MockChain, assert_transaction_executor_error};

use crate::scripts::pass_through::pass_through_account;

// CONSTANTS
// ================================================================================================

const SERIAL_NUMBER: Word = Word::new([Felt::new_unchecked(9); 4]);

/// A non-zero verification base fee, so the chain charges for transactions.
const VERIFICATION_BASE_FEE: u32 = 500;

// TESTS
// ================================================================================================

/// A transaction that leaves the account holding what an input note deposited is rejected: the
/// commitment changed, and the pass-through auth procedure allows no change at all.
#[tokio::test]
async fn pass_through_auth_rejects_a_state_change() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;

    // a plain P2ID note deposits into the account, and nothing moves the assets back out
    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[FungibleAsset::mock(10)],
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_PASS_THROUGH_ACCOUNT_STATE_CHANGED);

    Ok(())
}

/// On a fee-charging chain the pass-through auth procedure creates no TX_FEE note, so the
/// transaction's only output is the P2ID note the script created and the account is left as the
/// transaction found it.
#[tokio::test]
async fn pass_through_auth_creates_no_fee_note_on_a_fee_charging_chain() -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_asset = FungibleAsset::mock(10);
    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[fee_asset])?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [fee_asset.id()],
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed.output_notes().num_notes(),
        1,
        "a pass-through transaction pays no fee, so the P2ID note is its only output",
    );
    assert_eq!(
        executed.output_notes().get_note(0).recipient_digest(),
        script.output_note_recipient().digest(),
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// The nonce is never incremented, so a transaction cannot create such an account: the kernel
/// rejects one that leaves the nonce at zero. A pass-through account has to be provisioned
/// out of band.
#[tokio::test]
async fn pass_through_auth_cannot_create_an_account() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_account_from_builder(
        Auth::PassThrough,
        AccountBuilder::new([45; 32])
            .account_type(AccountType::Public)
            .with_component(BasicWallet)
            .with_component(PassThroughSweep),
        AccountState::New,
    )?;
    // an asset-less note, so the transaction gets past the state-change assert and reaches the
    // kernel's nonce check
    let note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng()).build()?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mock_chain = builder.build()?;

    // a new account is passed by value, since the chain does not yet know it
    let result = mock_chain
        .build_transaction(account.clone())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_NONCE_CANNOT_BE_0);

    Ok(())
}

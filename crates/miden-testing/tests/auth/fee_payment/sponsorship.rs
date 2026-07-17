use std::collections::BTreeSet;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteScriptRoot, NoteTag, NoteType, PartialNote};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::{
    AuthNetworkAccount,
    FeeConversionInfo,
    commit_fee_conversion_info,
};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{
    FeeSponsorshipNote,
    NetworkAccountTarget,
    NoteExecutionHint,
    P2idNote,
    TxFeeNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain};

use super::VERIFICATION_BASE_FEE;

// CONSTANTS
// ================================================================================================

/// The fee a network account's fee policy charges for a sponsored feature note.
const FEE_AMOUNT: u64 = 500;

// HELPERS
// ================================================================================================

/// The faucet issuing the native fee asset, which is also the asset fees are charged in.
fn fee_faucet_id() -> anyhow::Result<AccountId> {
    Ok(ACCOUNT_ID_FEE_FAUCET.try_into()?)
}

/// A fungible asset of `amount` units of the native fee asset.
fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(fee_faucet_id()?, amount)?.into())
}

/// Builds an existing public network account (`AuthNetworkAccount` + `BasicWallet` + `FeeManager`)
/// that allowlists `allowed_notes`, prices each `(root, amount)` in `priced` through its active
/// `ConstantFeePolicy`, and holds `assets` in its vault.
fn network_account(
    seed: [u8; 32],
    allowed_notes: impl IntoIterator<Item = NoteScriptRoot>,
    priced: &[(NoteScriptRoot, u64)],
    assets: impl IntoIterator<Item = Asset>,
) -> anyhow::Result<Account> {
    let mut policy = ConstantFeePolicy::new(fee_faucet_id()?);
    for (root, amount) in priced {
        policy = policy.with_fee(*root, AssetAmount::new(*amount)?);
    }
    let fee_manager = FeeManager::builder().active_fee_policy(policy.into()).build();
    let auth = AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter(allowed_notes))?;

    Ok(AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_components(fee_manager)
        .with_assets(assets)
        .build_existing()?)
}

/// Returns the auth args and advice-map entry committing to the trivial (native, rate 1/1) fee
/// conversion info, for a signing account paying its own fee.
fn native_conversion_info() -> (Word, Vec<miden_protocol::Felt>) {
    commit_fee_conversion_info(
        FeeConversionInfo::trivial(ACCOUNT_ID_FEE_FAUCET.try_into().unwrap()),
        Word::from([9u32, 10, 11, 12]),
    )
}

/// Builds a public P2ID network note (a P2ID note carrying a `NetworkAccountTarget` attachment)
/// sent by `sender`, targeting and routed to `target`, and carrying `asset`.
fn p2id_network_note(
    sender: AccountId,
    target: AccountId,
    asset: Asset,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let attachment = NetworkAccountTarget::new(target, NoteExecutionHint::Always)?;
    Ok(P2idNote::builder()
        .sender(sender)
        .target(target)
        .asset(asset)
        .note_type(NoteType::Public)
        .attachment(attachment)
        .serial_number(rng.draw_word())
        .build()?
        .into())
}

// TESTS
// ================================================================================================

/// When a fee-paying account creates a network output note, `pay_fee` sponsors it: a
/// FEE_SPONSORSHIP note funded from the creator's vault is emitted alongside the network note,
/// carrying exactly the fee the target account's policy prices the note at. The sponsorship note
/// is created before the fee is computed, so the creator's own TX_FEE note still covers the fee
/// required for the (now larger) transaction.
#[tokio::test]
async fn pay_fee_sponsors_network_output_note() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::from([1u32, 2, 3, 4]));
    // a payload asset issued by a faucet other than the fee faucet, carried by the network note
    let payload_asset: Asset = FungibleAsset::mock(50);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);

    // the sponsor is a signing wallet holding the fee asset (for its own fee and the sponsorship)
    // and the payload asset
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [fee_asset(1_000_000)?, payload_asset],
    )?;

    // the target network account prices the P2ID script root at FEE_AMOUNT
    let target = network_account(
        [2; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [],
    )?;
    builder.add_account(target.clone())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // the sponsor creates the P2ID network note via a send-notes transaction script
    let network_note = p2id_network_note(sponsor.id(), target.id(), payload_asset, &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?
    .into();

    let (auth_args, advice_value) = native_conversion_info();
    let foreign_target = mock_chain.get_foreign_account_inputs(target.id())?;

    let executed = mock_chain
        .build_tx_context(sponsor.id(), &[], &[])?
        .foreign_accounts([foreign_target])
        .tx_script(tx_script)
        .auth_args(auth_args)
        .extend_advice_map([(auth_args, advice_value)])
        .extend_expected_output_notes(vec![RawOutputNote::Full(network_note.clone())])
        .build()?
        .execute()
        .await?;

    // three output notes: the network note, its sponsorship note, and the sponsor's fee note
    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 3);

    // the network note itself is present
    assert!(
        output_notes.iter().any(|note| note.id() == network_note.id()),
        "the created network note should be an output note",
    );

    // exactly one sponsorship note, funded with FEE_AMOUNT of the fee asset and tagged for the
    // target network account
    let sponsorship = output_notes
        .iter()
        .find(|note| {
            note.recipient().map(|recipient| recipient.script().root())
                == Some(FeeSponsorshipNote::script_root())
        })
        .expect("a sponsorship note should be created for the network note");
    let sponsorship_assets: Vec<Asset> = sponsorship.assets().iter().copied().collect();
    assert_eq!(sponsorship_assets, vec![fee_asset(FEE_AMOUNT)?]);
    assert_eq!(sponsorship.metadata().tag(), NoteTag::with_account_target(target.id()));

    // the sponsor still pays its own fee, and the paid amount covers the fee required for the
    // transaction including the sponsorship note it just created
    let fee_note = output_notes
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the sponsor should pay its own fee note");
    let fee_note_asset = fee_note.assets().iter().next().expect("fee note carries one asset");
    let &Asset::Fungible(paid) = fee_note_asset else {
        panic!("fee note asset should be fungible");
    };
    assert!(
        paid.amount() >= executed.compute_fee(),
        "paid fee {} should cover the required fee {}",
        paid.amount(),
        executed.compute_fee(),
    );

    Ok(())
}

/// Sponsoring a network output note prices it through the target account's fee policy via an FPI
/// call, so the target must be provisioned as a foreign account. Omitting it aborts the
/// transaction.
#[tokio::test]
async fn sponsoring_network_note_requires_target_foreign_account() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::from([1u32, 2, 3, 4]));
    let payload_asset: Asset = FungibleAsset::mock(50);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [fee_asset(1_000_000)?, payload_asset],
    )?;
    let target = network_account(
        [2; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [],
    )?;
    builder.add_account(target.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let network_note = p2id_network_note(sponsor.id(), target.id(), payload_asset, &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?
    .into();
    let (auth_args, advice_value) = native_conversion_info();

    // note: the target is NOT provided as a foreign account
    let result = mock_chain
        .build_tx_context(sponsor.id(), &[], &[])?
        .tx_script(tx_script)
        .auth_args(auth_args)
        .extend_advice_map([(auth_args, advice_value)])
        .extend_expected_output_notes(vec![RawOutputNote::Full(network_note)])
        .build()?
        .execute()
        .await;

    let error = result.expect_err("sponsoring without the target foreign account must abort");
    let error_chain = format!("{:#}", anyhow::Error::new(error));
    assert!(
        error_chain.contains("foreign account"),
        "expected a missing foreign account error, got: {error_chain}",
    );

    Ok(())
}

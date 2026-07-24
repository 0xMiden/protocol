use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountBuilder, AccountComponent, AccountStorage, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::testing::account_component::MockAccountComponent;
use miden_testing::{Auth, MockChain};

use super::super::singlesig_acl::{compile_call_set_item_script, mock_component_proc_roots};
use super::{
    FALCON_512_POSEIDON2_AUTH_CYCLES,
    PAY_FEE_CYCLES,
    VERIFICATION_BASE_FEE,
    assert_single_fee_note,
};

// TESTS
// ================================================================================================

/// The ACL auth procedure pays the transaction fee before signature verification when a
/// non-exempt procedure (the wallet's `receive_asset` via a P2ID note) forces authentication.
/// The exempt (no-signature) branch pays in the native fee asset instead, ignoring any committed
/// conversion info (see `acl_exempt_branch_pays_native_fee_note`).
#[tokio::test]
async fn singlesig_acl_pays_fee_note_on_signature_path() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset: Asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?.into();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        Auth::Acl {
            exempt_procedures: BTreeSet::new(),
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [fee_asset],
    )?;

    // consuming a P2ID note calls the non-exempt `receive_asset`, forcing the signature branch
    let p2id_note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[FungibleAsset::mock(100)],
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let executed_transaction = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(p2id_note.id())
        .auth_args(args)
        .extend_advice_map(args, advice_value)
        .build()?
        .execute()
        .await?;

    assert_single_fee_note(&executed_transaction)?;

    let measurements = executed_transaction.measurements();
    let auth_estimate = FALCON_512_POSEIDON2_AUTH_CYCLES + PAY_FEE_CYCLES;
    assert!(
        measurements.auth_procedure <= auth_estimate,
        "ACL signature-path auth procedure took {} cycles, exceeding the estimate of \
         {auth_estimate}",
        measurements.auth_procedure,
    );

    Ok(())
}

/// The ACL exempt (no-signature) branch pays the transaction fee in the native fee asset,
/// ignoring any conversion info committed via the auth args.
///
/// With no signature over the transaction summary there is no signer to authorize a
/// caller-supplied conversion rate, so the exempt branch pays plainly in the kernel-attested
/// native fee asset at rate 1/1 (mirroring the network account component); paying (rather than
/// skipping the fee) also means exempt transactions cannot evade fees. This test runs a
/// state-changing exempt procedure (`set_item`) on a fee-charging chain with no registered
/// authenticator, supplies an inflated conversion-rate commitment via the auth args, and asserts
/// a native fee note covering the computed fee is created at rate 1/1 (the inflated rate is
/// ignored).
#[tokio::test]
async fn acl_exempt_branch_pays_native_fee_note() -> anyhow::Result<()> {
    let (_get_item, set_item, _account_procedure_1) = mock_component_proc_roots();

    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset = FungibleAsset::new(fee_faucet_id, 1_000_000)?;

    // `set_item` is exempt, so calling it takes the no-signature branch while still changing state
    // (making the transaction valid without requiring a signature).
    let component: AccountComponent =
        MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()).into();
    let (auth_components, _authenticator) = Auth::Acl {
        exempt_procedures: BTreeSet::from([set_item]),
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    }
    .build_components();

    let account = AccountBuilder::new([0; 32])
        .with_components(auth_components)
        .with_component(component)
        .account_type(AccountType::Public)
        .with_assets([fee_asset.into()])
        .build_existing()?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // an inflated conversion rate that would double the paid amount if the exempt branch honored
    // the committed conversion info
    let conversion_info = FeeConversionInfo::new(fee_faucet_id, 2, 1)?;
    let (args, advice_value) =
        commit_fee_conversion_info(conversion_info, Word::from([9u32, 10, 11, 12]));

    // no authenticator is registered, so a successful execution proves the exempt (no-signature)
    // branch ran
    let executed = mock_chain
        .build_transaction(account.id())
        .tx_script(compile_call_set_item_script()?)
        .auth_args(args)
        .extend_advice_map(args, advice_value)
        .build()?
        .execute()
        .await?;

    // a public TX_FEE note carrying the native fee asset covering the computed fee is created
    let paid_asset = assert_single_fee_note(&executed)?;

    // the paid amount stays within a bounded overshoot of the required fee at rate 1/1; the
    // inflated 2/1 rate committed via the auth args was ignored (honoring it would have doubled
    // the amount, far exceeding the bound)
    let required_fee = executed.compute_fee();
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        paid_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        paid_asset.amount()
    );

    Ok(())
}

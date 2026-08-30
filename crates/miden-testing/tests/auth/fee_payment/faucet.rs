use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{Account, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, AssetId, AssetVault, FungibleAsset, TokenSymbol};
use miden_protocol::note::{NoteAssets, NoteTag, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    Approver,
    AuthSingleSig,
    FeeConversionInfo,
    commit_fee_conversion_info,
};
use miden_standards::account::faucets::{
    Description,
    FungibleFaucet,
    TokenName,
    create_multisig_user_fungible_faucet,
    create_singlesig_user_fungible_faucet,
};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::TxFeeNote;
use miden_standards::testing::faucet::user_faucet_multisig;
use miden_testing::MockChain;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

use super::super::multisig::setup_keys_and_authenticators_with_scheme;
use super::multisig::multisig_auth_estimate;
use super::{VERIFICATION_BASE_FEE, assert_single_fee_note};

/// The amount of the native fee asset the funding P2ID note carries.
const FUNDING_AMOUNT: u64 = 1_000_000;

/// The faucet definition shared by the tests in this module. Its parameters matter only in that
/// `max_supply` must leave room for `MINT_AMOUNT`; otherwise only the account's interface is under
/// test.
fn sample_faucet() -> anyhow::Result<FungibleFaucet> {
    Ok(FungibleFaucet::builder()
        .name(TokenName::new("polygon")?)
        .symbol(TokenSymbol::try_from("POL")?)
        .decimals(2)
        .max_supply(AssetAmount::new(1000)?)
        .description(Description::new("A polygon token")?)
        .build()?)
}

/// A policy manager that permits every operation, so that nothing a policy rejects can be mistaken
/// for the missing wallet interface these tests are about.
fn allow_all_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build()
}

/// Re-wraps a freshly built account as an existing one. The factories build a new account (nonce
/// 0, carrying a seed); `MockChain` genesis accounts must be existing (nonce != 0, no seed), so the
/// built code and storage are re-wrapped as such, with an empty vault.
///
/// Every test here starts the faucet unfunded, which is what makes the fee assertions exact.
fn as_existing_account(account: Account) -> anyhow::Result<Account> {
    Ok(Account::new(
        account.id(),
        AssetVault::new(&[])?,
        account.storage().clone(),
        account.code().clone(),
        Felt::ONE,
        None,
    )?)
}

/// Builds a singlesig user fungible faucet through the production factory, as an existing account.
fn existing_singlesig_user_faucet(
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, BasicAuthenticator)> {
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let sec_key = AuthSecretKey::with_scheme_and_rng(auth_scheme, &mut rng)?;
    let pub_key = sec_key.public_key().to_commitment();
    let authenticator = BasicAuthenticator::new(&[sec_key]);

    let account = create_singlesig_user_fungible_faucet(
        [42u8; 32],
        sample_faucet()?,
        AuthSingleSig::new(Approver::new(pub_key, auth_scheme)),
        allow_all_policy_manager(),
        AccountType::Public,
    )?;

    Ok((as_existing_account(account)?, authenticator))
}

/// Builds a multisig user fungible faucet through the production factory, as an existing account,
/// together with the signers of its `num_approvers`-of-`num_approvers` approver set.
fn existing_multisig_user_faucet(
    num_approvers: usize,
    auth_scheme: AuthScheme,
) -> anyhow::Result<(Account, Vec<(PublicKey, BasicAuthenticator)>)> {
    let (_secret_keys, auth_schemes, public_keys, authenticators) =
        setup_keys_and_authenticators_with_scheme(num_approvers, num_approvers, auth_scheme)?;

    let approvers = public_keys
        .iter()
        .zip(auth_schemes.iter())
        .map(|(public_key, auth_scheme)| (public_key.to_commitment(), *auth_scheme))
        .collect();

    let account = create_multisig_user_fungible_faucet(
        [42u8; 32],
        sample_faucet()?,
        user_faucet_multisig(approvers, u32::try_from(num_approvers)?)?,
        allow_all_policy_manager(),
        AccountType::Public,
    )?;

    let signers = public_keys.into_iter().zip(authenticators).collect();

    Ok((as_existing_account(account)?, signers))
}

/// Asserts the faucet paid exactly one fee note and kept the rest of what the funding note
/// delivered. Callers assert the vault started empty, which is what makes the remainder exact.
fn assert_paid_fee_and_kept_remainder(
    faucet_account: Account,
    executed_transaction: &ExecutedTransaction,
) -> anyhow::Result<()> {
    let fee_asset = assert_single_fee_note(executed_transaction)?;

    // The faucet keeps whatever the funding note delivered beyond the fee it just paid, so it is
    // now able to transact again without being re-funded.
    let mut updated_account = faucet_account;
    updated_account.apply_patch(executed_transaction.account_patch())?;

    // `checked_sub` rather than `-`: were the fee ever to exceed the funding amount, an overflow
    // panic here would bury the reason under an arithmetic error.
    let expected_remainder = FUNDING_AMOUNT
        .checked_sub(fee_asset.amount().as_u64())
        .ok_or_else(|| anyhow::anyhow!("fee {} exceeded the funding amount", fee_asset.amount()))?;

    let remaining = updated_account
        .vault()
        .get_balance(AssetId::new_fungible(ACCOUNT_ID_FEE_FAUCET.try_into()?))?;
    assert_eq!(
        remaining,
        AssetAmount::new(expected_remainder)?,
        "the faucet should hold the funding amount less the fee it paid",
    );

    Ok(())
}

/// A user fungible faucet built by the production factory can be funded from an empty vault and
/// pay its own transaction fee on a fee-charging chain.
///
/// This is the end-to-end justification for bundling `BasicWallet` into the user faucet factories.
/// The faucet starts with an empty vault, so the P2ID note is its only source of the native fee
/// asset, and consuming a P2ID note calls `receive_asset` — a procedure the faucet only exports
/// because of that bundling. Without it this transaction cannot execute at all, which on a
/// fee-charging chain leaves the faucet permanently unable to transact.
#[rstest]
#[case::falcon(AuthScheme::Falcon512Poseidon2)]
#[case::ecdsa(AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn user_faucet_is_funded_by_p2id_and_pays_its_own_fee(
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset_id = AssetId::new_fungible(fee_faucet_id);
    let (faucet_account, authenticator) = existing_singlesig_user_faucet(auth_scheme)?;

    assert_eq!(
        faucet_account.vault().get_balance(fee_asset_id)?,
        AssetAmount::ZERO,
        "the faucet must start with no fee asset for this test to prove anything",
    );

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(faucet_account.clone())?;
    let funding_note = builder.add_p2id_note_with_fee(faucet_account.id(), FUNDING_AMOUNT)?;
    let mock_chain = builder.build()?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let executed_transaction = mock_chain
        .build_transaction(faucet_account.id())
        .authenticated_input_note(funding_note.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .authenticator(Some(authenticator))
        .build()?
        .execute()
        .await?;

    assert_paid_fee_and_kept_remainder(faucet_account, &executed_transaction)?;

    Ok(())
}

/// The same end-to-end funding and fee payment against the multisig factory.
///
/// Covering multisig separately matters for a reason the singlesig case cannot reach: the multisig
/// auth procedure scans every one of the account's procedures when it computes the transaction
/// threshold, so its cost grows with the procedure count, while the constant that is supposed to
/// cover that scan (`MULTISIG_AUTH_BASE_CYCLES`) is fixed. A user faucet is by some margin the
/// largest-interface account that uses this auth component, so it is where the estimate is
/// tightest.
///
/// The bound asserted below holds only for **two or more approvers**, which is why this test fixes
/// `NUM_APPROVERS = 2` rather than parameterizing. Measured on this transaction, the auth
/// procedure takes 104_083 cycles at n = 1, 174_493 at n = 2 and 244_903 at n = 3, against
/// estimates of `80_000 * n + 16_384`. Each Falcon signer therefore measures 70_410 against the
/// 80_000 estimated, buying 9_590 cycles of slack per signer against a fixed shortfall in the base
/// term: the margin is exactly `9_590 * n - 17_289`, which only turns positive at n = 2. At n = 1
/// the procedure overruns its estimate by 7_699 cycles.
///
/// That n = 1 overrun is **pre-existing, not introduced here**. A controlled A/B — two faucets
/// identical but for `BasicWallet`, both on a pre-funded transaction with no input note, so the
/// absolute numbers are ~480 cycles below this test's — measures 102_289 without the component and
/// 103_603 with it, against the same 96_384 estimate. It overruns either way.
///
/// Overrunning the estimate is anticipated rather than harmful. `signature.masm` notes that
/// accounts with very many procedures may slightly under-estimate the fee, and that this is
/// largely absorbed by the `ilog2`-domain fee formula. At n = 1 it is absorbed entirely: the
/// transaction still pays a fee that covers its true cost, and only this cycle-bound assertion
/// would complain. The fee is short only when the estimated and true totals straddle a power of
/// two, and there the batch builder rejects the underpaying note — so the failure mode at the edge
/// is closed, not silent underpayment.
///
/// What this change does cost is headroom. That same A/B puts `BasicWallet`'s three procedures at
/// +1_314 cycles, or 438 each, taking the n = 2 margin from 3_205 to **1_891 cycles against an
/// estimate of 176_384** — four more procedures would still fit, a fifth would not. If this ever
/// fails after a component is added to a user faucet factory, that is budget exhaustion rather
/// than a flake.
#[tokio::test]
async fn multisig_user_faucet_is_funded_by_p2id_and_pays_its_own_fee() -> anyhow::Result<()> {
    const NUM_APPROVERS: usize = 2;

    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset_id = AssetId::new_fungible(fee_faucet_id);
    // Falcon, because `multisig_auth_estimate` is expressed in the Falcon per-signer bound.
    let (faucet_account, signers) =
        existing_multisig_user_faucet(NUM_APPROVERS, AuthScheme::Falcon512Poseidon2)?;

    assert_eq!(
        faucet_account.vault().get_balance(fee_asset_id)?,
        AssetAmount::ZERO,
        "the faucet must start with no fee asset for this test to prove anything",
    );

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(faucet_account.clone())?;
    let funding_note = builder.add_p2id_note_with_fee(faucet_account.id(), FUNDING_AMOUNT)?;
    let mock_chain = builder.build()?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let mock_tx_builder = mock_chain
        .build_transaction(faucet_account.id())
        .authenticated_input_note(funding_note.id())
        .auth_args(args)
        .add_advice_map_entry(args, advice_value);

    // Execute once unsigned to obtain the transaction summary the approvers must sign.
    let tx_summary = mock_tx_builder
        .clone()
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    let msg = tx_summary.as_ref().to_commitment();
    let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

    let mut signed_builder = mock_tx_builder;
    for (public_key, authenticator) in &signers {
        let signature =
            authenticator.get_signature(public_key.to_commitment(), &signing_inputs).await?;
        signed_builder = signed_builder.add_signature(public_key.to_commitment(), msg, signature);
    }

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_paid_fee_and_kept_remainder(faucet_account, &executed_transaction)?;

    let measurements = executed_transaction.measurements();
    let auth_estimate = multisig_auth_estimate(NUM_APPROVERS);
    assert!(
        measurements.auth_procedure <= auth_estimate,
        "multisig auth procedure took {} cycles on a user faucet, exceeding the estimate of \
         {auth_estimate}; the per-procedure threshold scan grows with the account's procedure \
         count, and this bound was already close to exhausted, so this is a real budget overrun \
         rather than a flake — see this test's doc comment for the measured margin",
        measurements.auth_procedure,
    );

    Ok(())
}

/// A user faucet funded through its wallet interface can mint in the same transaction, paying the
/// fee out of what it just received. This is the claim the factory rustdoc and the CHANGELOG make
/// when they say a faucet without a wallet "could never mint on a fee-charging chain".
///
/// The faucet starts with an empty vault, so the P2ID note is its only source of the fee asset and
/// `receive_asset` is the only way in. Pre-funding the vault instead would make this test vacuous:
/// the mint and the fee payment both work without a wallet interface, and only the funding leg
/// requires one.
#[tokio::test]
async fn user_faucet_funded_by_p2id_mints_while_paying_its_own_fee() -> anyhow::Result<()> {
    const MINT_AMOUNT: u64 = 250;

    let fee_faucet_id: AccountId = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let fee_asset_id = AssetId::new_fungible(fee_faucet_id);
    let (faucet_account, authenticator) =
        existing_singlesig_user_faucet(AuthScheme::Falcon512Poseidon2)?;

    assert_eq!(
        faucet_account.vault().get_balance(fee_asset_id)?,
        AssetAmount::ZERO,
        "the faucet must start with no fee asset for this test to prove anything",
    );

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(faucet_account.clone())?;
    let funding_note = builder.add_p2id_note_with_fee(faucet_account.id(), FUNDING_AMOUNT)?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        "
            @transaction_script
            pub proc main
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                # => [faucet_id_suffix, faucet_id_prefix, amount, tag, note_type, RECIPIENT, ...]

                exec.::miden::standards::assets::fungible_asset::create
                # => [ASSET_ID, ASSET_VALUE, tag, note_type, RECIPIENT, ...]

                call.::miden::standards::faucets::fungible::mint_and_send
                # => [note_idx, pad(15)]

                dropw dropw dropw dropw
            end
        ",
        recipient = Word::from([0, 1, 2, 3u32]),
        note_type = NoteType::Private as u8,
        tag = u32::from(NoteTag::default()),
        amount = MINT_AMOUNT,
        faucet_id_prefix = faucet_account.id().prefix().as_felt(),
        faucet_id_suffix = faucet_account.id().suffix(),
    ))?;

    let (args, advice_value) = commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([9u32, 10, 11, 12]),
    );

    let executed_transaction = mock_chain
        .build_transaction(faucet_account.id())
        .authenticated_input_note(funding_note.id())
        .tx_script(tx_script)
        .auth_args(args)
        .add_advice_map_entry(args, advice_value)
        .authenticator(Some(authenticator))
        .build()?
        .execute()
        .await?;

    let output_notes = executed_transaction.output_notes();
    assert_eq!(
        output_notes.num_notes(),
        2,
        "expected the minted note and the TX_FEE note, got {} notes",
        output_notes.num_notes(),
    );

    let fee_note = (0..output_notes.num_notes())
        .map(|index| output_notes.get_note(index))
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .ok_or_else(|| anyhow::anyhow!("the mint transaction produced no TX_FEE note"))?;
    let paid = single_fungible_asset(fee_note.assets(), "TX_FEE note")?;
    assert_eq!(paid.faucet_id(), fee_faucet_id);
    assert!(
        paid.amount() >= executed_transaction.compute_fee(),
        "paid fee {} should cover the required fee {}",
        paid.amount(),
        executed_transaction.compute_fee(),
    );

    let minted_note = (0..output_notes.num_notes())
        .map(|index| output_notes.get_note(index))
        .find(|note| note.metadata().tag() != TxFeeNote::TAG)
        .ok_or_else(|| anyhow::anyhow!("the mint transaction produced no minted note"))?;
    let minted = single_fungible_asset(minted_note.assets(), "minted note")?;
    assert_eq!(minted.faucet_id(), faucet_account.id());
    assert_eq!(minted.amount(), AssetAmount::new(MINT_AMOUNT)?);

    // The vault started empty, so the remainder is what ties the fee back to the P2ID note rather
    // than to some other source.
    let mut updated_account = faucet_account;
    updated_account.apply_patch(executed_transaction.account_patch())?;
    let expected_remainder = FUNDING_AMOUNT
        .checked_sub(paid.amount().as_u64())
        .ok_or_else(|| anyhow::anyhow!("fee {} exceeded the funding amount", paid.amount()))?;
    assert_eq!(
        updated_account.vault().get_balance(fee_asset_id)?,
        AssetAmount::new(expected_remainder)?,
        "the faucet should hold the funding amount less the fee it paid",
    );

    Ok(())
}

/// Returns the single fungible asset carried by `assets`, erroring with `context` naming the note
/// if it does not carry exactly one fungible asset.
fn single_fungible_asset(assets: &NoteAssets, context: &str) -> anyhow::Result<FungibleAsset> {
    if assets.num_assets() != 1 {
        anyhow::bail!("the {context} should carry exactly one asset, got {}", assets.num_assets());
    }
    match assets.iter().next() {
        Some(Asset::Fungible(asset)) => Ok(*asset),
        other => anyhow::bail!("the {context} should carry a fungible asset, got {other:?}"),
    }
}

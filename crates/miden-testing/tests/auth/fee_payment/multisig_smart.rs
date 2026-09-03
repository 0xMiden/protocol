use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType, PartialNote};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::auth::multisig_smart::{
    ProcedurePolicy,
    ProcedurePolicyNoteRestriction,
};
use miden_standards::account::auth::{FeeConversionInfo, MultisigAuthArgs, SponsorshipPolicy};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_FEE_CONVERSION_INFO_MISSING,
    ERR_FEE_PAYMENT_ASSET_NOT_NATIVE,
    ERR_FEE_PAYMENT_EXCEEDS_BOUND,
};
use miden_standards::note::{FeeSponsorshipNote, P2idNote, TxFeeNote};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use miden_tx::auth::BasicAuthenticator;
use rstest::rstest;

use super::super::multisig::MultisigAuthArgsExt;
use super::multisig::{
    fee_paying_auth_args,
    multisig_auth_estimate,
    multisig_fixture,
    sign_with_all,
};
use super::sponsorship::{FEE_AMOUNT, fee_asset, network_account, p2id_network_note};
use super::{VERIFICATION_BASE_FEE, assert_single_fee_note};

// CONSTANTS
// ================================================================================================

/// Amount of the fee asset the fixture funds the account with.
const FEE_ASSET_AMOUNT: u64 = 1_000_000;

// HELPER FUNCTIONS
// ================================================================================================

/// A smart multisig wallet funded with the fee asset, with the keys needed to sign for it.
///
/// The chain is left unbuilt so a test can add input notes to it; call `builder.build()` to finish.
struct MultisigSmartFixture {
    builder: MockChainBuilder,
    account: Account,
    signers: Vec<(PublicKey, BasicAuthenticator)>,
}

/// Builds a wallet with the smart multisig auth component and the given procedure policies, on a
/// mock chain charging `verification_base_fee`, funded with enough of the fee asset to pay the fee.
///
/// The approver set is `num_approvers` Falcon signers with the threshold set to the full set.
fn multisig_smart_fixture(
    num_approvers: usize,
    verification_base_fee: u32,
    proc_policy_map: Vec<(Word, ProcedurePolicy)>,
) -> anyhow::Result<MultisigSmartFixture> {
    let (approver_set, signers) =
        multisig_fixture(num_approvers, num_approvers, AuthScheme::Falcon512Poseidon2)?;

    let mut builder = MockChain::builder().verification_base_fee(verification_base_fee);
    let account = builder.add_existing_wallet_with_assets(
        Auth::MultisigSmart { approver_set, proc_policy_map },
        [fee_asset(FEE_ASSET_AMOUNT)?],
    )?;

    Ok(MultisigSmartFixture { builder, account, signers })
}

/// Executes an empty transaction against a wallet with the multisig smart auth component on a
/// fee-charging mock chain, signing the summary with every approver.
async fn execute_fee_paying_multisig_smart_tx(
    num_approvers: usize,
) -> anyhow::Result<ExecutedTransaction> {
    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(num_approvers, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([9u32, 10, 11, 12]))?;
    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, &signers).await?;

    Ok(signed_builder.build()?.execute().await?)
}

// TESTS
// ================================================================================================

/// The multisig smart auth procedure pays the transaction fee, exactly as the plain multisig
/// component does.
#[tokio::test]
async fn multisig_smart_pays_fee_note() -> anyhow::Result<()> {
    let executed_transaction = execute_fee_paying_multisig_smart_tx(2).await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// The cycle estimate the component passes to the fee flow stays an upper bound on the cycles
/// actually spent authenticating, and bills every approver.
#[tokio::test]
async fn multisig_smart_auth_cycles_stay_within_the_estimate() -> anyhow::Result<()> {
    let num_approvers = 2;
    let executed_transaction = execute_fee_paying_multisig_smart_tx(num_approvers).await?;

    let auth_estimate = multisig_auth_estimate(num_approvers);
    let measured_cycles = executed_transaction.measurements().auth_procedure;
    assert!(
        measured_cycles <= auth_estimate,
        "measured auth cycles {measured_cycles} should stay within the estimate {auth_estimate}",
    );

    // A fee floor for an estimate that bills one approver too few. The fee flow adds its own
    // margins on top of the estimate, so the paid amount exceeding the floor shows every approver
    // was billed.
    let estimate_one_signer_short = multisig_auth_estimate(num_approvers - 1);
    let fee_floor_one_signer_short =
        u64::from(VERIFICATION_BASE_FEE) * u64::from(estimate_one_signer_short.ilog2() + 1);

    let fee_asset = assert_single_fee_note(&executed_transaction)?;
    assert!(
        fee_asset.amount().as_u64() > fee_floor_one_signer_short,
        "paid fee {} should exceed the {fee_floor_one_signer_short} floor for an estimate billing \
         only {} of the {num_approvers} approvers",
        fee_asset.amount().as_u64(),
        num_approvers - 1,
    );

    Ok(())
}

/// A transaction with no note restrictions pays the fee and creates its own output note in the
/// same transaction.
#[tokio::test]
async fn multisig_smart_pays_fee_alongside_a_user_output_note() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let sent_asset = FungibleAsset::new(fee_faucet_id, 7)?;

    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let output_note: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
        .asset(sent_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([57u32, 58, 59, 60])))
        .build()?
        .into();

    let send_note_script =
        SendNotesTransactionScript::new(&account.code_interface(), &[output_note.clone().into()])?;

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([61u32, 62, 63, 64]))?;
    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .send_notes_script(&send_note_script)
        .multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, &signers).await?;

    let executed_transaction = signed_builder.build()?.execute().await?;

    // both notes are present, and the fee still covers what the transaction actually cost
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);
    let fee_note = output_notes
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the transaction should create a fee note alongside the user's note");
    let paid = fee_note
        .assets()
        .iter()
        .next()
        .expect("the fee note should carry an asset")
        .unwrap_fungible();
    assert!(
        paid.amount() >= executed_transaction.compute_fee(),
        "paid fee {} should cover the required fee {}",
        paid.amount(),
        executed_transaction.compute_fee(),
    );

    Ok(())
}

/// Omitting the conversion info on a fee-charging chain fails before any signature is verified.
#[tokio::test]
async fn multisig_smart_fee_payment_fails_without_conversion_info() -> anyhow::Result<()> {
    let MultisigSmartFixture { builder, account, .. } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([49u32, 50, 51, 52]),
    );
    let result = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_CONVERSION_INFO_MISSING);

    Ok(())
}

/// The fee payment is inside what the signers sign: signatures over the summary of a transaction
/// paying at rate 1/1 do not authorize the same transaction paying at rate 3/2, since the larger
/// payment changes the fee note and the vault withdrawal. Only the rate differs between the two
/// runs, and it stays inside the payment bound, so the replay fails on the signatures.
#[tokio::test]
async fn multisig_smart_fee_payment_is_covered_by_the_signatures() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let MultisigSmartFixture { builder, account, signers } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;
    let mock_chain = builder.build()?;

    let block_number = mock_chain.latest_block_header().block_num();
    let salt = Word::from([41u32, 42, 43, 44]);
    let auth_args_at_rate =
        |rate_num: u64, rate_den: u64| -> anyhow::Result<MultisigAuthArgs> {
            Ok(MultisigAuthArgs::new(block_number, salt)
                .with_conversion_info(FeeConversionInfo::new(fee_faucet_id, rate_num, rate_den)?))
        };

    // sign the summary of the transaction that pays at rate 1/1
    let signed_builder = sign_with_all(
        mock_chain
            .build_transaction(account.id())
            .multisig_auth_args(auth_args_at_rate(1, 1)?),
        &signers,
    )
    .await?;

    // replay those signatures against the transaction that pays at rate 3/2
    signed_builder
        .multisig_auth_args(auth_args_at_rate(3, 2)?)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    Ok(())
}

/// On a chain with a zero verification base fee, no fee note is created and the caller need not
/// commit any conversion info.
#[tokio::test]
async fn multisig_smart_no_fee_note_on_zero_fee_chain() -> anyhow::Result<()> {
    let MultisigSmartFixture { builder, account, signers } = multisig_smart_fixture(2, 0, vec![])?;
    let mock_chain = builder.build()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([33u32, 34, 35, 36]),
    );
    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, &signers).await?;

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 0);
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "a zero fee must leave the account vault untouched",
    );

    Ok(())
}

/// A procedure policy that forbids output notes still permits the transaction fee note: with no
/// user note, the live output-note count is non-zero only because of the fee note.
#[tokio::test]
async fn multisig_smart_honors_no_output_notes_policy_while_paying_the_fee() -> anyhow::Result<()> {
    let no_output_notes_policy = ProcedurePolicy::with_immediate_threshold(1)?
        .with_note_restriction(ProcedurePolicyNoteRestriction::NoOutputNotes);

    let MultisigSmartFixture { mut builder, account, signers } = multisig_smart_fixture(
        2,
        VERIFICATION_BASE_FEE,
        vec![(BasicWallet::receive_asset_root().as_word(), no_output_notes_policy)],
    )?;

    // consuming a P2ID note invokes the policied `receive_asset` procedure without creating any
    // output note of its own, so the TX_FEE note is the only output note the transaction has
    let p2id_note = builder.add_p2id_note(
        account.id(),
        account.id(),
        &[FungibleAsset::mock(1)],
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([17u32, 18, 19, 20]))?;
    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(p2id_note.id())
        .multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, &signers).await?;

    let executed_transaction = signed_builder.build()?.execute().await?;

    assert_single_fee_note(&executed_transaction)?;

    Ok(())
}

/// A procedure policy that forbids output notes still rejects a transaction creating an output
/// note of its own on a fee-charging chain: tolerating the fee note does not extend to user notes.
#[tokio::test]
async fn multisig_smart_rejects_user_output_note_under_no_output_notes_policy() -> anyhow::Result<()>
{
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let sent_asset = FungibleAsset::new(fee_faucet_id, 5)?;

    let no_output_notes_policy = ProcedurePolicy::with_immediate_threshold(1)?
        .with_note_restriction(ProcedurePolicyNoteRestriction::NoOutputNotes);

    let MultisigSmartFixture { builder, account, .. } = multisig_smart_fixture(
        2,
        VERIFICATION_BASE_FEE,
        vec![(BasicWallet::move_asset_to_note_root().as_word(), no_output_notes_policy)],
    )?;
    let mock_chain = builder.build()?;

    let output_note: Note = P2idNote::builder()
        .sender(account.id())
        .target(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?)
        .asset(sent_asset)
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([21u32, 22, 23, 24])))
        .build()?
        .into();

    let send_note_script =
        SendNotesTransactionScript::new(&account.code_interface(), &[output_note.clone().into()])?;

    // the policy check runs before signature verification, so an unsigned transaction surfaces
    // the output-note error rather than an unauthorized error
    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([25u32, 26, 27, 28]))?;
    let result = mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .send_notes_script(&send_note_script)
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES);

    Ok(())
}

/// The smart component bounds its fee payment, since a per-procedure policy can authorize a
/// transaction below the account's default threshold while the conversion rate is host-supplied:
/// an inflated rate in the native asset and a foreign asset at an acceptable rate both abort
/// before any signature is verified.
#[rstest]
#[case::inflated_rate(
    FeeConversionInfo::new(ACCOUNT_ID_FEE_FAUCET.try_into().unwrap(), 1_000_000, 1).unwrap(),
    ERR_FEE_PAYMENT_EXCEEDS_BOUND
)]
#[case::foreign_asset(
    FeeConversionInfo::one_to_one(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap()),
    ERR_FEE_PAYMENT_ASSET_NOT_NATIVE
)]
#[tokio::test]
async fn multisig_smart_cannot_drain_the_vault_via_the_fee_payment(
    #[case] conversion_info: FeeConversionInfo,
    #[case] expected_error: miden_protocol::errors::MasmError,
) -> anyhow::Result<()> {
    let drain_policy = ProcedurePolicy::with_immediate_threshold(1)?;
    let MultisigSmartFixture { builder, account, .. } = multisig_smart_fixture(
        2,
        VERIFICATION_BASE_FEE,
        vec![(BasicWallet::receive_asset_root().as_word(), drain_policy)],
    )?;
    let mock_chain = builder.build()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([81u32, 82, 83, 84]),
    )
    .with_conversion_info(conversion_info);
    let result = mock_chain
        .build_transaction(account.id())
        .multisig_auth_args(auth_args)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// A smart multisig that creates a network output note sponsors it, funding a FEE_SPONSORSHIP
/// note from its own vault alongside its TX_FEE note.
#[tokio::test]
async fn multisig_smart_sponsors_its_network_output_note() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::from([91u32, 92, 93, 94]));
    // the fixture funds the account with the fee asset only, so the network note carries some of it
    let payload_asset = fee_asset(7)?;

    let MultisigSmartFixture { mut builder, account, signers } =
        multisig_smart_fixture(2, VERIFICATION_BASE_FEE, vec![])?;

    // the target network account prices the P2ID script root, which is what the sponsorship pays
    let target = network_account(
        [5; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [],
        SponsorshipPolicy::default(),
    )?;
    builder.add_account(target.clone())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let network_note = p2id_network_note(account.id(), target.id(), payload_asset, &mut rng)?;
    let send_notes_script = SendNotesTransactionScript::new(
        &account.code_interface(),
        &[PartialNote::from(network_note.clone())],
    )?;

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([95u32, 96, 97, 98]))?;
    let foreign_target = mock_chain.get_foreign_account_inputs(target.id())?;
    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .foreign_accounts([foreign_target])
        .expected_output_note(RawOutputNote::Full(network_note.clone()))
        .send_notes_script(&send_notes_script)
        .multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, &signers).await?;

    let executed_transaction = signed_builder.build()?.execute().await?;

    // the network note, its sponsorship note and the account's own fee note
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 3);

    let sponsorship = output_notes
        .iter()
        .find(|note| {
            note.recipient().is_some_and(|recipient| {
                recipient.script().root() == FeeSponsorshipNote::script_root()
            })
        })
        .expect("the smart multisig should sponsor the network note it created");
    let sponsorship_assets: Vec<Asset> = sponsorship.assets().iter().copied().collect();
    assert_eq!(sponsorship_assets, vec![fee_asset(FEE_AMOUNT)?]);
    assert_eq!(sponsorship.metadata().tag(), NoteTag::with_account_target(target.id()));

    // the account still pays its own fee, and it still covers what the transaction cost
    let fee_note = output_notes
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the smart multisig should pay its own fee note");
    let paid = fee_note
        .assets()
        .iter()
        .next()
        .expect("the fee note should carry an asset")
        .unwrap_fungible();
    assert!(
        paid.amount() >= executed_transaction.compute_fee(),
        "paid fee {} should cover the required fee {}",
        paid.amount(),
        executed_transaction.compute_fee(),
    );

    Ok(())
}

use core::iter;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKey};
use miden_protocol::account::{Account, AccountProcedureRoot, StorageMapKey};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionScript};
use miden_standards::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    FeeConversionInfo,
    GuardianConfig,
    MultisigAuthArgs,
    SponsorshipPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES,
    ERR_FEE_PAYMENT_ASSET_NOT_NATIVE,
    ERR_FEE_PAYMENT_EXCEEDS_BOUND,
};
use miden_standards::note::{FeeSponsorshipNote, P2idNote, TxFeeNote};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{Auth, MockChain, MockTransactionBuilder, assert_transaction_executor_error};
use miden_tx::auth::BasicAuthenticator;
use rstest::rstest;

use super::super::guarded_multisig::build_update_guardian_script_source;
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

/// Amount of the fee asset the fixtures fund the account with.
const FEE_ASSET_AMOUNT: u64 = 1_000_000;

// HELPER FUNCTIONS
// ================================================================================================

/// A guarded multisig fixture: `num_approvers` Falcon approvers with the threshold set to all of
/// them, plus a separate guardian using `guardian_scheme`.
struct GuardedFixture {
    approver_set: ApproverSet,
    guardian_config: GuardianConfig,
    approvers: Vec<(PublicKey, BasicAuthenticator)>,
    guardian: (PublicKey, BasicAuthenticator),
}

impl GuardedFixture {
    fn new(num_approvers: usize, guardian_scheme: AuthScheme) -> anyhow::Result<Self> {
        let (approver_set, approvers) =
            multisig_fixture(num_approvers, num_approvers, AuthScheme::Falcon512Poseidon2)?;

        let guardian_secret_key = match guardian_scheme {
            AuthScheme::EcdsaK256Keccak => AuthSecretKey::new_ecdsa_k256_keccak(),
            AuthScheme::Falcon512Poseidon2 => AuthSecretKey::new_falcon512_poseidon2(),
            _ => anyhow::bail!("unsupported guardian auth scheme: {guardian_scheme:?}"),
        };
        let guardian_public_key = guardian_secret_key.public_key();
        let guardian_authenticator =
            BasicAuthenticator::new(core::slice::from_ref(&guardian_secret_key));
        let guardian_config = GuardianConfig::new(Approver::new(
            guardian_public_key.to_commitment(),
            guardian_scheme,
        ));

        Ok(Self {
            approver_set,
            guardian_config,
            approvers,
            guardian: (guardian_public_key, guardian_authenticator),
        })
    }

    fn auth(&self, proc_threshold_map: Vec<(AccountProcedureRoot, u32)>) -> Auth {
        Auth::GuardedMultisig {
            approver_set: self.approver_set.clone(),
            guardian_config: self.guardian_config,
            proc_threshold_map,
        }
    }

    /// The approvers followed by the guardian.
    fn all_signers(&self) -> impl Iterator<Item = &(PublicKey, BasicAuthenticator)> {
        self.approvers.iter().chain(iter::once(&self.guardian))
    }
}

/// Executes an empty transaction against a funded guarded multisig wallet on a fee-charging chain,
/// signed by every approver and the guardian.
async fn execute_fee_paying_guarded_multisig_tx(
    num_approvers: usize,
    guardian_scheme: AuthScheme,
) -> anyhow::Result<ExecutedTransaction> {
    let fixture = GuardedFixture::new(num_approvers, guardian_scheme)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder
        .add_existing_wallet_with_assets(fixture.auth(vec![]), [fee_asset(FEE_ASSET_AMOUNT)?])?;
    let mock_chain = builder.build()?;

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([9u32, 10, 11, 12]))?;
    let mock_tx_builder = mock_chain.build_transaction(account.id()).multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, fixture.all_signers()).await?;

    Ok(signed_builder.build()?.execute().await?)
}

/// A guardian key rotation against a guarded multisig account on a fee-charging chain.
struct RotationSetup {
    mock_chain: MockChain,
    account: Account,
    fixture: GuardedFixture,
    new_guardian_key: PublicKey,
    /// A no-op output note the rotation script creates first, when the test asks for one.
    output_note: Option<Note>,
    script: TransactionScript,
}

impl RotationSetup {
    /// Sets up a guarded multisig account holding `vault_assets` and a tx script rotating its
    /// guardian key to a fresh Falcon key, after creating a no-op output note if asked to.
    fn new(
        vault_assets: Vec<Asset>,
        proc_threshold_map: Vec<(AccountProcedureRoot, u32)>,
        include_output_note: bool,
    ) -> anyhow::Result<Self> {
        let fixture = GuardedFixture::new(2, AuthScheme::EcdsaK256Keccak)?;

        let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
        let account = builder
            .add_existing_wallet_with_assets(fixture.auth(proc_threshold_map), vault_assets)?;
        let mock_chain = builder.build()?;

        let output_note = include_output_note
            .then(|| -> anyhow::Result<Note> {
                let recipient = NoteRecipient::new(
                    Word::from([1u32, 2, 3, 4]),
                    CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT)?,
                    NoteStorage::default(),
                );
                Ok(Note::new(
                    NoteAssets::new(vec![])?,
                    PartialNoteMetadata::new(account.id(), NoteType::Public),
                    recipient,
                ))
            })
            .transpose()?;

        let new_guardian_key = AuthSecretKey::new_falcon512_poseidon2().public_key();
        let script = CodeBuilder::new()
            .with_dynamically_linked_package(AuthGuardedMultisig::code())?
            .compile_tx_script(build_update_guardian_script_source(
                new_guardian_key.to_commitment().into(),
                AuthScheme::Falcon512Poseidon2 as u32,
                output_note.as_ref(),
            ))?;

        Ok(Self {
            mock_chain,
            account,
            fixture,
            new_guardian_key,
            output_note,
            script,
        })
    }

    /// Builds the rotation transaction, paying the fee as `conversion_info` says.
    fn transaction(
        &self,
        conversion_info: FeeConversionInfo,
        salt: Word,
    ) -> anyhow::Result<MockTransactionBuilder<'_>> {
        let auth_args =
            MultisigAuthArgs::new(self.mock_chain.latest_block_header().block_num(), salt)
                .with_conversion_info(conversion_info);

        let mut mock_tx_builder = self
            .mock_chain
            .build_transaction(self.account.id())
            .tx_script(self.script.clone())
            .multisig_auth_args(auth_args);
        if let Some(note) = &self.output_note {
            mock_tx_builder =
                mock_tx_builder.expected_output_note(RawOutputNote::Full(note.clone()));
        }

        Ok(mock_tx_builder)
    }
}

// TESTS
// ================================================================================================

/// The guarded multisig auth procedure pays the transaction fee, within the cycle estimate it
/// hands to the fee flow.
///
/// The estimate counts one signer more than there are approvers, for the guardian. Only the
/// `single_falcon_approver` case straddles a fee bucket edge, so it alone under-pays if the extra
/// slot is dropped.
#[rstest]
#[case::ecdsa_guardian(AuthScheme::EcdsaK256Keccak, 2)]
#[case::falcon_guardian(AuthScheme::Falcon512Poseidon2, 2)]
#[case::single_falcon_approver(AuthScheme::Falcon512Poseidon2, 1)]
#[tokio::test]
async fn guarded_multisig_pays_fee_note_within_the_cycle_estimate(
    #[case] guardian_scheme: AuthScheme,
    #[case] num_approvers: usize,
) -> anyhow::Result<()> {
    let executed_transaction =
        execute_fee_paying_guarded_multisig_tx(num_approvers, guardian_scheme).await?;

    let fee_asset = assert_single_fee_note(&executed_transaction)?;

    // the overshoot is bounded: the estimate should not overpay by more than a few base fee units
    let required_fee = executed_transaction.compute_fee();
    let max_overpayment = u64::from(3 * VERIFICATION_BASE_FEE);
    assert!(
        fee_asset.amount().as_u64() <= required_fee.as_u64() + max_overpayment,
        "paid fee {} should not exceed the required fee {required_fee} by more than \
         {max_overpayment}",
        fee_asset.amount()
    );

    let auth_estimate = multisig_auth_estimate(num_approvers + 1);
    let measurements = executed_transaction.measurements();
    assert!(
        measurements.auth_procedure <= auth_estimate,
        "guarded multisig auth took {} cycles, exceeding the estimate of {auth_estimate}",
        measurements.auth_procedure,
    );

    Ok(())
}

/// Guardian key rotation works on a fee-charging chain, since the rotation path excludes the
/// notes the fee payment creates from its no-output-notes check, and still rejects a transaction
/// creating an output note of its own.
#[rstest]
#[case::without_output_note(false)]
#[case::with_output_note(true)]
#[tokio::test]
async fn guarded_multisig_rotates_guardian_key_while_paying_the_fee(
    #[case] include_output_note: bool,
) -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let setup =
        RotationSetup::new(vec![fee_asset(FEE_ASSET_AMOUNT)?], vec![], include_output_note)?;

    let mock_tx_builder = setup.transaction(
        FeeConversionInfo::one_to_one(fee_faucet_id),
        Word::from([21u32, 22, 23, 24]),
    )?;
    // rotation intentionally skips the guardian signature
    let signed_builder = sign_with_all(mock_tx_builder, &setup.fixture.approvers).await?;
    let result = signed_builder.build()?.execute().await;

    if include_output_note {
        assert_transaction_executor_error!(
            result,
            ERR_AUTH_TRANSACTION_MUST_NOT_INCLUDE_OUTPUT_NOTES
        );
        return Ok(());
    }

    let executed_transaction = result?;
    assert_single_fee_note(&executed_transaction)?;

    // the new guardian key landed in storage
    let mut rotated_account = setup.account.clone();
    rotated_account.apply_patch(executed_transaction.account_patch())?;
    assert_eq!(
        rotated_account.storage().get_map_item(
            AuthGuardedMultisig::guardian_public_key_slot(),
            StorageMapKey::empty()
        )?,
        Word::from(setup.new_guardian_key.to_commitment())
    );
    assert_eq!(
        rotated_account
            .storage()
            .get_map_item(AuthGuardedMultisig::guardian_scheme_id_slot(), StorageMapKey::empty())?,
        Word::from([AuthScheme::Falcon512Poseidon2 as u32, 0, 0, 0])
    );

    Ok(())
}

/// Guardian key rotation cannot outrun the fee: an unfunded vault fails on the withdrawal. Since
/// rotation forbids input notes, funding the vault takes a separate transaction, which needs a
/// guardian signature.
#[tokio::test]
async fn guarded_multisig_rotation_fails_when_the_vault_cannot_fund_the_fee() -> anyhow::Result<()>
{
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;
    let setup = RotationSetup::new(vec![], vec![], false)?;

    let result = setup
        .transaction(FeeConversionInfo::one_to_one(fee_faucet_id), Word::from([31u32, 32, 33, 34]))?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}

/// A reduced-quorum guardian rotation cannot drain the vault through an inflated fee conversion
/// rate: the payment is bounded before the summary is created, so the transaction aborts before
/// any signature is verified.
#[tokio::test]
async fn guarded_multisig_rotation_cannot_drain_the_vault_via_the_fee_rate() -> anyhow::Result<()> {
    let fee_faucet_id = ACCOUNT_ID_FEE_FAUCET.try_into()?;

    let update_guardian_root = AuthGuardedMultisig::code()
        .get_procedure_root_by_path(
            "miden::standards::components::auth::guarded_multisig::update_guardian_public_key",
        )
        .expect("guarded multisig should export update_guardian_public_key");
    let setup = RotationSetup::new(
        vec![fee_asset(FEE_ASSET_AMOUNT)?],
        vec![(update_guardian_root, 1)],
        false,
    )?;

    let result = setup
        .transaction(
            FeeConversionInfo::new(fee_faucet_id, 1_000_000, 1)?,
            Word::from([81u32, 82, 83, 84]),
        )?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_EXCEEDS_BOUND);

    Ok(())
}

/// The same path cannot pay the fee in a foreign asset either: the bound is only meaningful
/// against the native fee asset, so the payment asset is pinned to it.
#[tokio::test]
async fn guarded_multisig_rotation_cannot_pay_the_fee_in_a_foreign_asset() -> anyhow::Result<()> {
    let payment_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let setup = RotationSetup::new(vec![fee_asset(FEE_ASSET_AMOUNT)?], vec![], false)?;

    let result = setup
        .transaction(
            FeeConversionInfo::one_to_one(payment_faucet_id),
            Word::from([91u32, 92, 93, 94]),
        )?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_PAYMENT_ASSET_NOT_NATIVE);

    Ok(())
}

/// A guarded multisig that creates a network output note sponsors it, funding a FEE_SPONSORSHIP
/// note from its own vault alongside its TX_FEE note.
#[tokio::test]
async fn guarded_multisig_sponsors_its_network_output_note() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::from([81u32, 82, 83, 84]));
    // the payload the network note carries, issued by a faucet other than the fee faucet so the
    // sponsorship's fee-asset funding is unambiguous
    let payload_asset: Asset = FungibleAsset::mock(50);

    let fixture = GuardedFixture::new(2, AuthScheme::EcdsaK256Keccak)?;

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = builder.add_existing_wallet_with_assets(
        fixture.auth(vec![]),
        [fee_asset(FEE_ASSET_AMOUNT)?, payload_asset],
    )?;

    // the target network account prices the P2ID script root, which is what the sponsorship pays
    let target = network_account(
        [4; 32],
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

    let auth_args = fee_paying_auth_args(&mock_chain, Word::from([85u32, 86, 87, 88]))?;
    let foreign_target = mock_chain.get_foreign_account_inputs(target.id())?;
    let mock_tx_builder = mock_chain
        .build_transaction(account.id())
        .foreign_accounts([foreign_target])
        .expected_output_note(RawOutputNote::Full(network_note.clone()))
        .send_notes_script(&send_notes_script)
        .multisig_auth_args(auth_args);
    let signed_builder = sign_with_all(mock_tx_builder, fixture.all_signers()).await?;

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
        .expect("the guarded multisig should sponsor the network note it created");
    let sponsorship_assets: Vec<Asset> = sponsorship.assets().iter().copied().collect();
    assert_eq!(sponsorship_assets, vec![fee_asset(FEE_AMOUNT)?]);
    assert_eq!(sponsorship.metadata().tag(), NoteTag::with_account_target(target.id()));

    // the account still pays its own fee, and it still covers what the transaction cost
    let fee_note = output_notes
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the guarded multisig should pay its own fee note");
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

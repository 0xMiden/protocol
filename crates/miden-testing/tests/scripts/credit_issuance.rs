//! End-to-end test of the credit issuance and repayment flow.
//!
//! A credit originator, a borrower and a creditor (a fund) agree on the terms of a loan off-chain.
//! The bond is an NFT issued by a network faucet controlled by the originator, whose asset value
//! commits to those terms. Every leg of the flow is a SWAP note:
//! - issuance: a private SWAP minted by the faucet offers the NFT to the creditor in exchange for
//!   the principal, which goes to the borrower in a private P2ID loan note.
//! - repayment: a private SWAP created by the borrower offers the principal plus interest to the
//!   NFT holder in exchange for the NFT, which goes back to the faucet in a public BURN payback
//!   note.
//!
//! The counterparties never read private note details from the chain: each one derives the notes
//! it expects from the agreed terms and watches the chain for their IDs. Their accounts are private
//! too, so the chain holds only commitments to their states. The NFT faucet is a network account,
//! which must be public.
//!
//! A second test covers the stablecoin side: the issuer confiscates stablecoins from a holder and
//! re-mints them to another account, which leaves the token supply unchanged.
//!
//! A third test shows how the issuer tracks its stablecoin while the creditor funds the borrower
//! and the borrower repays in private P2ID notes: the stablecoin faucet encrypts the details of
//! every private note holding the stablecoin to the issuer's key, so the issuer learns the amount
//! and the nullifier of each note, and sees on-chain when the note is consumed. The creditor and
//! the borrower have private accounts whose balances the chain does not show, so the attachment
//! and the nullifier are the only way for the issuer to follow the stablecoins.
//!
//! A fourth test shows how the originator tracks the bond while it changes hands privately between
//! issuance and repayment: the NFT faucet encrypts the details of every private note holding the
//! bond that another account creates to the originator's key, so the originator learns when the
//! bond leaves its holder and when the next holder takes it.

use std::sync::Arc;

use anyhow::Context;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{
    Asset,
    AssetAmount,
    AssetId,
    FungibleAsset,
    NonFungibleAsset,
    TokenSymbol,
};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::ecdh::ecgfp5::{PreparedPublicKey, SecretKey};
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteTag, NoteType, PartialNote};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
};
use miden_protocol::testing::word::WordMockExt;
use miden_protocol::transaction::{
    ExecutedTransaction,
    OutputNote,
    PrivateOutputNote,
    RawOutputNote,
};
use miden_protocol::{Hasher, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::faucets::{
    AssetStatus,
    FungibleFaucet,
    NonFungibleFaucet,
    TokenName,
    create_network_non_fungible_faucet,
};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{
    BasicBlocklist,
    BlocklistManager,
    BurnPolicy,
    MintPolicy,
    ReceivePolicy,
    SendPolicy,
    SupplyRestrictionManager,
    SupplyRestrictionPolicy,
    SupplyRestrictionStorage,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_ACCOUNT_IS_BLOCKED,
    ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE,
};
use miden_standards::note::config::{
    BlocklistConfig,
    BlocklistConfigNote,
    SupplyRestrictionConfig,
    SupplyRestrictionConfigNote,
};
use miden_standards::note::{
    BurnNote,
    EncryptedAssetsAttachment,
    EncryptedAssetsIssuerKey,
    MintNote,
    MintNoteStorage,
    NetworkNoteExt,
    P2idNote,
    P2idNoteStorage,
    SwapNote,
    TxFeeNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;
use rand::RngExt;

use super::policy_component;

// CONSTANTS
// ================================================================================================

const PRINCIPAL: u64 = 1000;

/// Fixed interest, regardless of the time passed until repayment.
const INTEREST_PERCENT: u8 = 5;

const VERIFICATION_BASE_FEE: u32 = 500;

/// The fee asset every account starts with, enough to pay for all of its transactions.
const INITIAL_FEE_BALANCE: u64 = 1_000_000;

// AGREED TERMS
// ================================================================================================

/// The terms of the loan the originator, borrower and creditor agree on off-chain.
///
/// The terms are the contract between the parties: each one derives the notes it creates or
/// watches the chain for from them.
struct CreditTerms {
    originator_id: AccountId,
    nft_faucet_id: AccountId,
    stablecoin_faucet_id: AccountId,
    borrower_id: AccountId,
    creditor_id: AccountId,
    principal: AssetAmount,
    interest_percent: u8,
    salt: Word,
}

/// The notes of the flow whose serial numbers are derived from the [`CreditTerms`].
///
/// The discriminant separates the serial numbers of the notes.
#[derive(Clone, Copy)]
enum CreditNote {
    Mint = 0,
    Issue = 1,
    Loan = 2,
    Repayment = 3,
    Burn = 4,
}

impl CreditTerms {
    /// Returns the NFT representing the bond.
    ///
    /// Its asset value commits to the terms, so the NFT is identifiable on-chain only by this
    /// commitment, while the terms themselves stay off-chain.
    fn bond(&self) -> NonFungibleAsset {
        NonFungibleAsset::from_parts(self.nft_faucet_id, self.bond_commitment())
    }

    /// Returns the commitment to the terms, i.e. the asset value of the bond.
    fn bond_commitment(&self) -> Word {
        let mut terms_data = Vec::new();
        terms_data.extend_from_slice(&<[u8; 15]>::from(self.borrower_id));
        terms_data.extend_from_slice(&<[u8; 15]>::from(self.creditor_id));
        terms_data.extend_from_slice(&self.principal.as_u64().to_le_bytes());
        terms_data.push(self.interest_percent);

        NonFungibleFaucet::compute_asset_commitment(&terms_data, self.salt)
    }

    /// Returns the serial number of the given note.
    ///
    /// It is the hash of the salt and the note as a domain separator.
    fn serial_number(&self, note: CreditNote) -> Word {
        Hasher::hash_double_word(&[self.salt, Word::from([note as u32, 0, 0, 0])])
    }

    fn principal(&self) -> anyhow::Result<Asset> {
        Ok(FungibleAsset::new(self.stablecoin_faucet_id, self.principal.as_u64())?.into())
    }

    /// Returns the amount of the principal plus interest.
    fn repayment_amount(&self) -> anyhow::Result<AssetAmount> {
        let interest = compute_interest(self.principal, self.interest_percent)?;
        Ok((self.principal + interest)?)
    }

    /// Returns the principal plus interest.
    fn repayment(&self) -> anyhow::Result<Asset> {
        Ok(
            FungibleAsset::new(self.stablecoin_faucet_id, self.repayment_amount()?.as_u64())?
                .into(),
        )
    }

    /// Returns the private P2ID note paying the principal to the borrower, created as the payback
    /// of the issue note.
    fn loan_note(&self, issue_payback_metadata: &NoteMetadata) -> anyhow::Result<Note> {
        Ok(Note::new(
            NoteAssets::new(vec![self.principal()?])?,
            *issue_payback_metadata.partial_metadata(),
            P2idNoteStorage::new(self.borrower_id)
                .into_recipient(self.serial_number(CreditNote::Loan)),
        ))
    }

    /// Returns the private SWAP note the faucet mints the bond into: the creditor takes the bond
    /// and pays the principal to the borrower in a private P2ID loan note.
    fn issue_note(&self) -> anyhow::Result<Note> {
        let loan_recipient = P2idNoteStorage::new(self.borrower_id)
            .into_recipient(self.serial_number(CreditNote::Loan));

        let issue_note = SwapNote::builder()
            .sender(self.nft_faucet_id)
            .offered_asset(self.bond())
            .requested_asset(self.principal()?)
            .serial_number(self.serial_number(CreditNote::Issue))
            .note_type(NoteType::Private)
            .payback_note_type(NoteType::Private)
            .payback_recipient(loan_recipient)
            .payback_tag(NoteTag::with_account_target(self.borrower_id))
            .build()?;

        Ok(issue_note.into())
    }

    /// Returns the public MINT note the originator sends to the faucet to mint the bond into the
    /// issue note.
    ///
    /// It only carries the commitment of the bond and the recipient digest of the issue note, so
    /// neither the terms nor the borrower are revealed.
    fn mint_note(&self, issue_note: &Note) -> anyhow::Result<Note> {
        let mint_note = MintNote::builder()
            .sender(self.originator_id)
            .mint_storage(MintNoteStorage::new_private_output(
                issue_note.recipient().digest(),
                self.bond(),
                issue_note.metadata().tag(),
            ))
            .serial_number(self.serial_number(CreditNote::Mint))
            .build()?;

        Ok(mint_note.into())
    }

    /// Returns the public BURN note the bond holder creates when filling the repayment note.
    fn burn_note(&self) -> anyhow::Result<Note> {
        let burn_note = BurnNote::builder()
            .sender(self.creditor_id)
            .asset(self.bond())
            .serial_number(self.serial_number(CreditNote::Burn))
            .build()?;

        Ok(burn_note.into())
    }

    /// Returns the private SWAP note the borrower repays the loan with: the bond holder takes the
    /// principal plus interest and sends the bond to the faucet in a public BURN payback note.
    fn repayment_note(&self) -> anyhow::Result<Note> {
        let burn_note = self.burn_note()?;

        let repayment_note = SwapNote::builder()
            .sender(self.borrower_id)
            .offered_asset(self.repayment()?)
            .requested_asset(self.bond())
            .serial_number(self.serial_number(CreditNote::Repayment))
            .note_type(NoteType::Private)
            .payback_note_type(NoteType::Public)
            .payback_recipient(burn_note.recipient().clone())
            .payback_tag(burn_note.metadata().tag())
            .payback_attachments(burn_note.attachments().iter().cloned())
            .build()?;

        Ok(repayment_note.into())
    }
}

/// Returns the fixed interest owed on `principal`.
fn compute_interest(principal: AssetAmount, interest_percent: u8) -> anyhow::Result<AssetAmount> {
    let interest = u128::from(principal.as_u64()) * u128::from(interest_percent) / 100;
    let interest = u64::try_from(interest).context("interest does not fit into a u64")?;

    Ok(AssetAmount::new(interest)?)
}

// TEST SETUP
// ================================================================================================

/// The accounts of the flow and the terms the parties agreed on.
///
/// `originator`, `creditor`, `borrower` and `other_fund` are the parties' own copies of their
/// private account states, which [`commit_private`] keeps current. The other fund is a second
/// creditor, to which the creditor can transfer the bond.
struct TestSetup {
    originator: Account,
    creditor: Account,
    borrower: Account,
    other_fund: Account,
    nft_faucet: Account,
    stablecoin_asset_id: AssetId,
    terms: CreditTerms,
}

impl TestSetup {
    /// Creates the private wallets of the parties and the network faucet on a fee-charging mock
    /// chain, deploys the faucet and agrees on the terms.
    ///
    /// The faucet applies `bond_send_policy` to the notes holding the bond, if provided. The
    /// creditor holds the principal and the borrower holds the interest upfront, so it can repay
    /// the full amount after receiving the principal. Every account holds the fee asset to pay for
    /// its transactions.
    async fn new(bond_send_policy: Option<SendPolicy>) -> anyhow::Result<(MockChain, Self)> {
        let stablecoin_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let principal = AssetAmount::new(PRINCIPAL)?;
        let interest = compute_interest(principal, INTEREST_PERCENT)?;

        let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
        let originator = add_private_wallet(&mut builder, [fee_asset(INITIAL_FEE_BALANCE)?])?;
        let creditor = add_private_wallet(
            &mut builder,
            [
                fee_asset(INITIAL_FEE_BALANCE)?,
                FungibleAsset::new(stablecoin_faucet_id, principal.as_u64())?.into(),
            ],
        )?;
        let borrower = add_private_wallet(
            &mut builder,
            [
                fee_asset(INITIAL_FEE_BALANCE)?,
                FungibleAsset::new(stablecoin_faucet_id, interest.as_u64())?.into(),
            ],
        )?;
        let other_fund = add_private_wallet(&mut builder, [fee_asset(INITIAL_FEE_BALANCE)?])?;
        let nft_faucet =
            create_nft_faucet(builder.rng_mut().random(), originator.id(), bond_send_policy)?;
        // the faucet is funded with the fee asset by a P2ID note, consumed when it is deployed
        let funding_note = builder.add_p2id_note(
            originator.id(),
            nft_faucet.id(),
            &[fee_asset(INITIAL_FEE_BALANCE)?],
            NoteType::Public,
        )?;
        let mut mock_chain = builder.build()?;

        let deploy_nft_faucet_tx = mock_chain
            .build_transaction(nft_faucet.clone())
            .authenticated_input_note(funding_note.id())
            .build()?
            .execute()
            .await?;
        commit(&mut mock_chain, &deploy_nft_faucet_tx)?;

        let terms = CreditTerms {
            originator_id: originator.id(),
            nft_faucet_id: nft_faucet.id(),
            stablecoin_faucet_id,
            borrower_id: borrower.id(),
            creditor_id: creditor.id(),
            principal,
            interest_percent: INTEREST_PERCENT,
            salt: Word::mock(1),
        };

        let setup = Self {
            originator,
            creditor,
            borrower,
            other_fund,
            nft_faucet,
            stablecoin_asset_id: AssetId::new_fungible(stablecoin_faucet_id),
            terms,
        };

        Ok((mock_chain, setup))
    }
}

// TEST
// ================================================================================================

/// Runs the full credit lifecycle: issuance of the bond NFT against the principal, and repayment
/// of the principal plus interest against burning the bond.
#[tokio::test]
async fn credit_issuance_and_repayment() -> anyhow::Result<()> {
    let (mut mock_chain, mut setup) = TestSetup::new(None).await?;
    let repayment_amount = setup.terms.repayment_amount()?;
    let bond = Asset::from(setup.terms.bond());

    // STEP 1: the parties agree on the terms off-chain
    // --------------------------------------------------------------------------------------------

    // the creditor derives the ID of the issue note it will watch the chain for
    let issue_note = setup.terms.issue_note()?;
    let issue_id = issue_note.id();

    // STEP 2: the credit originator issues a public MINT note to the network faucet
    // --------------------------------------------------------------------------------------------

    let mint_note = setup.terms.mint_note(&issue_note)?;

    let send_mint_note_tx =
        send_note(&mock_chain, &setup.originator, &mint_note, setup.nft_faucet.id()).await?;
    commit_private(&mut mock_chain, &mut setup.originator, &send_mint_note_tx)?;

    // STEP 3: the network faucet consumes the MINT note, creating the private issue SWAP note
    // --------------------------------------------------------------------------------------------

    let consume_mint_note_tx = mock_chain
        .build_transaction(setup.nft_faucet.id())
        .authenticated_input_note(mint_note.id())
        .build()?
        .execute()
        .await?;
    let [issued_note] = non_fee_output_notes(&consume_mint_note_tx)[..] else {
        anyhow::bail!("the faucet must create exactly the issue note");
    };
    assert_eq!(issued_note.metadata().note_type(), NoteType::Private);
    assert_eq!(issued_note.id(), issue_id);
    commit(&mut mock_chain, &consume_mint_note_tx)?;

    // STEP 4: the creditor sees the issue note on-chain and consumes it
    // --------------------------------------------------------------------------------------------

    assert!(mock_chain.is_note_committed(&issue_id));

    // The chain holds no details of the private note, so the creditor provides its own copy.
    let consume_issue_note_tx = mock_chain
        .build_transaction(setup.creditor.clone())
        .authenticated_input_note(issue_note)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.creditor, &consume_issue_note_tx)?;

    // the chain only commits to the creditor's state, so the creditor checks its own copy
    assert_eq!(setup.creditor.vault().get(bond.id()), Some(bond));
    assert_eq!(
        setup.creditor.vault().get_balance(setup.stablecoin_asset_id)?,
        AssetAmount::ZERO
    );

    // STEP 5: the payback is a private P2ID loan note paying the principal to the borrower
    // --------------------------------------------------------------------------------------------

    let [loan_note_header] = non_fee_output_notes(&consume_issue_note_tx)[..] else {
        anyhow::bail!("filling the issue note must create exactly the loan note");
    };
    assert_eq!(loan_note_header.metadata().note_type(), NoteType::Private);

    // the borrower derives the loan note from the terms and consumes it
    let loan_note = setup.terms.loan_note(loan_note_header.metadata())?;
    assert_eq!(loan_note.id(), loan_note_header.id());

    let consume_loan_note_tx = mock_chain
        .build_transaction(setup.borrower.clone())
        .authenticated_input_note(loan_note)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.borrower, &consume_loan_note_tx)?;

    assert_eq!(setup.borrower.vault().get_balance(setup.stablecoin_asset_id)?, repayment_amount);

    // STEP 6: the borrower repays the loan with a private repayment SWAP note
    // --------------------------------------------------------------------------------------------

    let repayment_note = setup.terms.repayment_note()?;
    let repayment_id = repayment_note.id();

    let send_repayment_note_tx =
        send_note(&mock_chain, &setup.borrower, &repayment_note, setup.nft_faucet.id()).await?;
    commit_private(&mut mock_chain, &mut setup.borrower, &send_repayment_note_tx)?;

    assert_eq!(
        setup.borrower.vault().get_balance(setup.stablecoin_asset_id)?,
        AssetAmount::ZERO
    );

    // STEP 7: the creditor sees the repayment note on-chain and consumes it
    // --------------------------------------------------------------------------------------------

    assert!(mock_chain.is_note_committed(&repayment_id));

    // Creating the BURN network note asks the faucet for its fee, so the faucet is a foreign
    // account of this transaction.
    let consume_repayment_note_tx = mock_chain
        .build_transaction(setup.creditor.clone())
        .authenticated_input_note(repayment_note)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(setup.nft_faucet.id())?])
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.creditor, &consume_repayment_note_tx)?;

    assert_eq!(setup.creditor.vault().get(bond.id()), None);
    assert_eq!(setup.creditor.vault().get_balance(setup.stablecoin_asset_id)?, repayment_amount);

    // STEP 8: the consumption created a public BURN note for the faucet carrying the bond
    // --------------------------------------------------------------------------------------------

    let [RawOutputNote::Full(burn_note)] = non_fee_output_notes(&consume_repayment_note_tx)[..]
    else {
        anyhow::bail!("filling the repayment note must create exactly the full BURN note");
    };
    assert_eq!(burn_note, &setup.terms.burn_note()?);
    assert!(burn_note.is_network_note());
    assert!(mock_chain.is_note_committed(&burn_note.id()));

    // STEP 9: the network faucet consumes the BURN note
    // --------------------------------------------------------------------------------------------

    let consume_burn_note_tx = mock_chain
        .build_transaction(setup.nft_faucet.id())
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &consume_burn_note_tx)?;

    let nft_faucet_account = mock_chain.committed_account(setup.nft_faucet.id())?;
    assert_eq!(
        NonFungibleFaucet::get_asset_status(
            nft_faucet_account.storage(),
            setup.terms.bond_commitment()
        )?,
        AssetStatus::Burned,
    );

    Ok(())
}

/// The stablecoin issuer confiscates part of a holder's balance and re-mints it to a recovery
/// account, e.g. after the holder lost access to its keys.
///
/// The holder is blocked until the amount is confiscated, so it cannot move the amount away in the
/// meantime. Confiscating removes the amount from the token supply and re-minting adds it back, so
/// the net effect on the token supply is zero. The holder's balance is unchanged, but after it is
/// unblocked it can only spend the part that is not confiscated.
#[tokio::test]
async fn stablecoin_confiscation_and_remint() -> anyhow::Result<()> {
    const HOLDER_AMOUNT: u32 = 500;
    const CONFISCATED_AMOUNT: u32 = 300;
    const SPENDABLE_AMOUNT: u32 = HOLDER_AMOUNT - CONFISCATED_AMOUNT;
    let holder_amount = AssetAmount::from(HOLDER_AMOUNT);
    let confiscated = AssetAmount::from(CONFISCATED_AMOUNT);

    let mut builder = MockChain::builder();
    let issuer_id = AccountId::mock_private(1);
    let issuer_secret_key = SecretKey::with_rng(&mut rand::rng());
    let issuer_prepared_key = Arc::new(PreparedPublicKey::new(issuer_secret_key.public_key()));

    // the holder already holds all stablecoins in circulation
    let stablecoin_faucet = add_stablecoin_faucet(
        &mut builder,
        issuer_id,
        holder_amount,
        EncryptedAssetsIssuerKey::new(&issuer_prepared_key),
    )?;
    let stablecoin_faucet_id = stablecoin_faucet.id();
    let holder_asset = FungibleAsset::new(stablecoin_faucet_id, holder_amount.as_u64())?;

    let holder = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        [holder_asset.into()],
    )?;
    let recovery =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos })?;

    // the issuer's notes to block and unblock the holder
    let [block_note, unblock_note] = [
        BlocklistConfig::BlockAccount { account: holder.id() },
        BlocklistConfig::UnblockAccount { account: holder.id() },
    ]
    .map(|config| {
        BlocklistConfigNote::builder()
            .sender(issuer_id)
            .target(stablecoin_faucet_id)
            .config(config)
            .serial_number(rand::rng().random())
            .build()
            .map(Note::from)
    });
    let (block_note, unblock_note) = (block_note?, unblock_note?);

    // the issuer's notes to confiscate the holder's stablecoins and re-mint them to the recovery
    // account in a public P2ID note
    let confiscate_note: Note = SupplyRestrictionConfigNote::builder()
        .sender(issuer_id)
        .target(stablecoin_faucet_id)
        .config(SupplyRestrictionConfig::Confiscate {
            account: holder.id(),
            amount: confiscated,
        })
        .serial_number(rand::rng().random())
        .build()?
        .into();
    let remint_note: Note = MintNote::builder()
        .sender(issuer_id)
        .mint_storage(MintNoteStorage::new_public_output(
            P2idNoteStorage::new(recovery.id()).into_recipient(rand::rng().random()),
            FungibleAsset::new(stablecoin_faucet_id, confiscated.as_u64())?,
            NoteTag::with_account_target(recovery.id()),
        )?)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    for note in [&block_note, &confiscate_note, &remint_note, &unblock_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    let supply_before_confiscation = stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?;

    // STEP 1: the issuer blocks the holder, so its balance cannot change anymore
    // --------------------------------------------------------------------------------------------

    mock_chain.consume_notes_and_commit(stablecoin_faucet_id, [block_note]).await?;

    let result = send_stablecoins(
        &mock_chain,
        &holder,
        stablecoin_faucet_id,
        &issuer_prepared_key,
        SPENDABLE_AMOUNT,
    )
    .await?;
    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    // STEP 2: the faucet consumes the confiscate note
    // --------------------------------------------------------------------------------------------

    mock_chain
        .consume_notes_and_commit(stablecoin_faucet_id, [confiscate_note])
        .await?;

    assert_eq!(
        stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?,
        (holder_amount - confiscated)?
    );
    assert_eq!(confiscated_amount(&mock_chain, stablecoin_faucet_id, holder.id())?, confiscated);

    // STEP 3: the faucet consumes the MINT note, re-minting the amount to the recovery account
    // --------------------------------------------------------------------------------------------

    let remint_tx =
        mock_chain.consume_notes_and_commit(stablecoin_faucet_id, [remint_note]).await?;
    let [RawOutputNote::Full(p2id_note)] = remint_tx.output_notes().iter().collect::<Vec<_>>()[..]
    else {
        anyhow::bail!("the faucet must create exactly the full P2ID note");
    };
    let receive_tx = mock_chain
        .build_transaction(recovery.id())
        .authenticated_input_note(p2id_note.clone())
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(stablecoin_faucet_id)?])
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &receive_tx)?;

    let stablecoin_asset_id = AssetId::new_fungible(stablecoin_faucet_id);
    let recovery_account = mock_chain.committed_account(recovery.id())?;
    assert_eq!(recovery_account.vault().get_balance(stablecoin_asset_id)?, confiscated);

    // the confiscation and the re-mint cancel out
    assert_eq!(
        stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?,
        supply_before_confiscation
    );

    // STEP 4: the issuer unblocks the holder, which can spend only what is not confiscated
    // --------------------------------------------------------------------------------------------

    mock_chain
        .consume_notes_and_commit(stablecoin_faucet_id, [unblock_note])
        .await?;

    let holder_account = mock_chain.committed_account(holder.id())?;
    assert_eq!(holder_account.vault().get_balance(stablecoin_asset_id)?, holder_amount);

    let result = send_stablecoins(
        &mock_chain,
        &holder,
        stablecoin_faucet_id,
        &issuer_prepared_key,
        SPENDABLE_AMOUNT + 1,
    )
    .await?;
    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_TRANSFER_EXCEEDS_UNRESTRICTED_BALANCE
    );

    let send_tx = send_stablecoins(
        &mock_chain,
        &holder,
        stablecoin_faucet_id,
        &issuer_prepared_key,
        SPENDABLE_AMOUNT,
    )
    .await??;
    commit(&mut mock_chain, &send_tx)?;

    // the issuer decrypts the private note in which the holder sent the spendable amount
    let (_, sent_details) = issuer_decrypts_new_note(&mock_chain, &issuer_secret_key)?;
    assert_eq!(
        sent_details.assets(),
        &NoteAssets::new(vec![
            FungibleAsset::new(stablecoin_faucet_id, SPENDABLE_AMOUNT.into())?.into()
        ])?
    );

    let holder_account = mock_chain.committed_account(holder.id())?;
    assert_eq!(holder_account.vault().get_balance(stablecoin_asset_id)?, confiscated);

    Ok(())
}

/// The stablecoin issuer tracks the private notes in which the creditor funds the borrower with the
/// principal and the borrower repays the principal plus interest.
///
/// The creditor and the borrower have private accounts, so a block holds only the new commitments
/// to their states (see [`commit_private`]) and does not show how their balances change. The
/// stablecoin faucet's send policy attaches the details of every private note holding the
/// stablecoin, encrypted to the issuer's public key. The chain holds only the note's header and
/// attachments, so of all observers of the chain, only the issuer learns what the note holds and
/// which nullifier it has. The issuer thus tracks the out-flow of stablecoins from the sender when
/// the note is created, and their in-flow to the recipient when the note's nullifier appears
/// on-chain.
#[tokio::test]
async fn issuer_tracks_private_stablecoin_transfers() -> anyhow::Result<()> {
    let principal = AssetAmount::new(PRINCIPAL)?;
    let interest = compute_interest(principal, INTEREST_PERCENT)?;
    let repayment_amount = (principal + interest)?;
    let issuer_id = AccountId::mock_private(1);
    let issuer_secret_key = SecretKey::with_rng(&mut rand::rng());
    let issuer_prepared_key = Arc::new(PreparedPublicKey::new(issuer_secret_key.public_key()));

    let mut builder = MockChain::builder();
    // The creditor holds the principal and the borrower holds the interest, which are all
    // stablecoins in circulation. The faucet is public: every transfer of the stablecoin invokes
    // the faucet's callbacks as a foreign account, so the holder executing the transfer needs the
    // faucet's code and storage, which the chain provides only for a public account.
    let stablecoin_faucet = add_stablecoin_faucet(
        &mut builder,
        issuer_id,
        repayment_amount,
        EncryptedAssetsIssuerKey::new(&issuer_prepared_key),
    )?;
    let stablecoin_faucet_id = stablecoin_faucet.id();
    let stablecoin_asset_id = AssetId::new_fungible(stablecoin_faucet_id);
    let principal_asset = FungibleAsset::new(stablecoin_faucet_id, principal.as_u64())?;
    let repayment_asset = FungibleAsset::new(stablecoin_faucet_id, repayment_amount.as_u64())?;

    let mut creditor = add_private_wallet(&mut builder, [principal_asset.into()])?;
    let mut borrower = add_private_wallet(
        &mut builder,
        [FungibleAsset::new(stablecoin_faucet_id, interest.as_u64())?.into()],
    )?;
    let mut mock_chain = builder.build()?;

    // STEP 1: the creditor funds the borrower with the principal in a private P2ID note
    // --------------------------------------------------------------------------------------------

    // the creditor shares the details of the note with the borrower off-chain
    let loan_note = send_private_stablecoins(
        &mut mock_chain,
        &mut creditor,
        borrower.id(),
        principal_asset,
        &issuer_prepared_key,
    )
    .await?;

    // STEP 2: the issuer decrypts the loan note in the new block
    // --------------------------------------------------------------------------------------------

    // Anyone sees in the block that the creditor's account changed and that it created a private
    // note, but only the account's new commitment and the note's header and attachments, not what
    // the note holds. The issuer decrypts the attachment, which it accepts only if the decrypted
    // details recompute the note's ID: it learns the amount the creditor sent, and computes the
    // nullifier that consuming the note will reveal.
    let (loan_on_chain, loan_details) = issuer_decrypts_new_note(&mock_chain, &issuer_secret_key)?;
    assert_eq!(loan_details.assets(), &NoteAssets::new(vec![principal_asset.into()])?);
    assert_eq!(loan_details.note_id(loan_on_chain.metadata()), loan_on_chain.id());
    let loan_nullifier = loan_details.nullifier(loan_on_chain.metadata());
    // the nullifier is not on-chain until the note is consumed
    assert!(mock_chain.is_note_unspent(&loan_nullifier));

    // another key cannot decrypt the attachment
    let other_secret_key = SecretKey::with_rng(&mut rand::rng());
    assert!(
        EncryptedAssetsAttachment::decrypt_and_verify_note(
            loan_on_chain.header(),
            loan_on_chain.attachments(),
            &other_secret_key,
        )
        .is_none()
    );

    // STEP 3: the borrower consumes the loan note, revealing its nullifier
    // --------------------------------------------------------------------------------------------

    let consume_loan_tx = consume_private_stablecoins(
        &mut mock_chain,
        &mut borrower,
        loan_note,
        stablecoin_faucet_id,
    )
    .await?;

    // the consumption reveals the nullifier the issuer computed, so the issuer sees the note spent
    assert_eq!(consume_loan_tx.input_notes().get_note(0).note().nullifier(), loan_nullifier);
    assert!(mock_chain.is_note_consumed(&loan_nullifier));

    // the chain only commits to the borrower's state, so the borrower checks its own copy
    assert_eq!(borrower.vault().get_balance(stablecoin_asset_id)?, repayment_amount);

    // STEP 4: the borrower repays the principal plus interest in a private P2ID note
    // --------------------------------------------------------------------------------------------

    let repayment_note = send_private_stablecoins(
        &mut mock_chain,
        &mut borrower,
        creditor.id(),
        repayment_asset,
        &issuer_prepared_key,
    )
    .await?;

    // the issuer decrypts the repayment note like the loan note
    let (repayment_on_chain, repayment_details) =
        issuer_decrypts_new_note(&mock_chain, &issuer_secret_key)?;
    assert_eq!(repayment_details.assets(), &NoteAssets::new(vec![repayment_asset.into()])?);
    let repayment_nullifier = repayment_details.nullifier(repayment_on_chain.metadata());

    // STEP 5: the creditor consumes the repayment note, revealing its nullifier
    // --------------------------------------------------------------------------------------------

    let consume_repayment_tx = consume_private_stablecoins(
        &mut mock_chain,
        &mut creditor,
        repayment_note,
        stablecoin_faucet_id,
    )
    .await?;

    assert_eq!(
        consume_repayment_tx.input_notes().get_note(0).note().nullifier(),
        repayment_nullifier
    );
    assert!(mock_chain.is_note_consumed(&repayment_nullifier));

    assert_eq!(creditor.vault().get_balance(stablecoin_asset_id)?, repayment_amount);

    Ok(())
}

/// The originator tracks the bond while it changes hands privately between issuance and
/// repayment.
///
/// The NFT faucet's send policy attaches the details of every private note holding the bond that
/// an account other than the faucet creates, encrypted to the originator's public key. The
/// originator derives the issue note from the terms, but not the private note in which the
/// creditor transfers the bond to the other fund, e.g. after selling it. The originator decrypts
/// that note's attachment, so it learns that the bond left the creditor, and computes the nullifier
/// that appears on-chain once the other fund takes the bond. The other fund then collects the
/// repayment and returns the bond to the faucet in the public BURN note.
#[tokio::test]
async fn issuer_tracks_private_bond_transfers() -> anyhow::Result<()> {
    let originator_secret_key = SecretKey::with_rng(&mut rand::rng());
    let originator_prepared_key =
        Arc::new(PreparedPublicKey::new(originator_secret_key.public_key()));
    // the faucet encrypts the details of the private notes holding the bond to the originator's key
    let bond_send_policy =
        SendPolicy::with_encrypted_assets(EncryptedAssetsIssuerKey::new(&originator_prepared_key));
    let (mut mock_chain, mut setup) = TestSetup::new(Some(bond_send_policy)).await?;
    let nft_faucet_id = setup.nft_faucet.id();
    let bond = Asset::from(setup.terms.bond());

    // STEP 1: the network faucet mints the bond into the private issue note
    // --------------------------------------------------------------------------------------------

    let issue_note = setup.terms.issue_note()?;
    let issue_nullifier = issue_note.nullifier();
    let mint_note = setup.terms.mint_note(&issue_note)?;

    let send_mint_note_tx =
        send_note(&mock_chain, &setup.originator, &mint_note, nft_faucet_id).await?;
    commit_private(&mut mock_chain, &mut setup.originator, &send_mint_note_tx)?;

    let consume_mint_note_tx = mock_chain
        .build_transaction(nft_faucet_id)
        .authenticated_input_note(mint_note.id())
        .build()?
        .execute()
        .await?;
    // The faucet creates the issue note itself, so the note gets no attachment. The originator
    // derives the note and its nullifier from the terms.
    let [issued_note] = non_fee_output_notes(&consume_mint_note_tx)[..] else {
        anyhow::bail!("the faucet must create exactly the issue note");
    };
    assert_eq!(issued_note.id(), issue_note.id());
    assert!(issued_note.attachments().is_empty());
    commit(&mut mock_chain, &consume_mint_note_tx)?;

    // STEP 2: the creditor consumes the issue note and the borrower the loan note
    // --------------------------------------------------------------------------------------------

    // Adding the bond to the vault invokes the faucet's asset callback, so the faucet is a foreign
    // account of this transaction.
    let consume_issue_note_tx = mock_chain
        .build_transaction(setup.creditor.clone())
        .authenticated_input_note(issue_note)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(nft_faucet_id)?])
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.creditor, &consume_issue_note_tx)?;

    // The terms name the creditor as the taker of the issue note, so once the originator sees
    // on-chain that the note is consumed, it knows that the creditor holds the bond. The
    // creditor's own state confirms it.
    assert!(mock_chain.is_note_consumed(&issue_nullifier));
    assert_eq!(setup.creditor.vault().get(bond.id()), Some(bond));

    let [loan_note_header] = non_fee_output_notes(&consume_issue_note_tx)[..] else {
        anyhow::bail!("filling the issue note must create exactly the loan note");
    };
    let consume_loan_note_tx = mock_chain
        .build_transaction(setup.borrower.clone())
        .authenticated_input_note(setup.terms.loan_note(loan_note_header.metadata())?)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.borrower, &consume_loan_note_tx)?;

    // STEP 3: the creditor transfers the bond to the other fund in a private P2ID note
    // --------------------------------------------------------------------------------------------

    let transfer_note: Note = P2idNote::builder()
        .sender(setup.creditor.id())
        .target(setup.other_fund.id())
        .assets([bond])
        .note_type(NoteType::Private)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    let send_notes_script = SendNotesTransactionScript::new(
        &setup.creditor.code_interface(),
        &[PartialNote::from(transfer_note.clone())],
    )?;

    // The faucet's send policy encrypts the details of the note to the originator's key, so the
    // transaction provides them by expecting the note, and provides the prepared key.
    let send_transfer_note_tx = mock_chain
        .build_transaction(setup.creditor.clone())
        .send_notes_script(&send_notes_script)
        .expected_output_note(RawOutputNote::Full(transfer_note))
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(nft_faucet_id)?])
        .ies_prepared_public_key(originator_prepared_key)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    // the creditor shares the note as the transaction created it, i.e. with the attachment, with
    // the other fund off-chain
    let [RawOutputNote::Full(transfer_note)] = non_fee_output_notes(&send_transfer_note_tx)[..]
    else {
        anyhow::bail!("the transaction must create exactly the full transfer note");
    };
    let transfer_note = transfer_note.clone();
    commit_private(&mut mock_chain, &mut setup.creditor, &send_transfer_note_tx)?;

    // STEP 4: the originator decrypts the transfer note in the new block
    // --------------------------------------------------------------------------------------------

    // Anyone sees in the block that the creditor created a private note, but not what it holds.
    // The originator decrypts the attachment: it learns that the note holds the bond, and computes
    // the nullifier that consuming the note will reveal.
    let (transfer_on_chain, transfer_details) =
        issuer_decrypts_new_note(&mock_chain, &originator_secret_key)?;
    assert_eq!(transfer_on_chain.metadata().sender(), setup.creditor.id());
    assert_eq!(transfer_details.assets(), &NoteAssets::new(vec![bond])?);
    let transfer_nullifier = transfer_details.nullifier(transfer_on_chain.metadata());
    assert!(mock_chain.is_note_unspent(&transfer_nullifier));

    // STEP 5: the other fund consumes the transfer note, revealing its nullifier
    // --------------------------------------------------------------------------------------------

    let consume_transfer_note_tx = mock_chain
        .build_transaction(setup.other_fund.clone())
        .authenticated_input_note(transfer_note)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(nft_faucet_id)?])
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.other_fund, &consume_transfer_note_tx)?;

    // the originator sees on-chain that the next holder took the bond
    assert!(mock_chain.is_note_consumed(&transfer_nullifier));
    assert_eq!(setup.other_fund.vault().get(bond.id()), Some(bond));

    // STEP 6: the borrower repays the loan with the private repayment SWAP note
    // --------------------------------------------------------------------------------------------

    let repayment_note = setup.terms.repayment_note()?;
    let send_repayment_note_tx =
        send_note(&mock_chain, &setup.borrower, &repayment_note, nft_faucet_id).await?;
    commit_private(&mut mock_chain, &mut setup.borrower, &send_repayment_note_tx)?;

    // STEP 7: the other fund fills the repayment note, returning the bond in the public BURN note
    // --------------------------------------------------------------------------------------------

    // Creating the BURN network note asks the faucet for its fee and invokes its send policy, so
    // the faucet is a foreign account of this transaction.
    let consume_repayment_note_tx = mock_chain
        .build_transaction(setup.other_fund.clone())
        .authenticated_input_note(repayment_note)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(nft_faucet_id)?])
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit_private(&mut mock_chain, &mut setup.other_fund, &consume_repayment_note_tx)?;

    assert_eq!(setup.other_fund.vault().get(bond.id()), None);
    assert_eq!(
        setup.other_fund.vault().get_balance(setup.stablecoin_asset_id)?,
        setup.terms.repayment_amount()?
    );

    // the BURN note is public, so the policy adds no attachment and anyone sees the bond return
    let [RawOutputNote::Full(burn_note)] = non_fee_output_notes(&consume_repayment_note_tx)[..]
    else {
        anyhow::bail!("filling the repayment note must create exactly the full BURN note");
    };
    assert_eq!(burn_note.metadata().sender(), setup.other_fund.id());
    assert_eq!(burn_note.assets(), &NoteAssets::new(vec![bond])?);
    assert_eq!(burn_note.attachments(), setup.terms.burn_note()?.attachments());

    // STEP 8: the network faucet consumes the BURN note
    // --------------------------------------------------------------------------------------------

    let consume_burn_note_tx = mock_chain
        .build_transaction(nft_faucet_id)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &consume_burn_note_tx)?;

    let nft_faucet_account = mock_chain.committed_account(nft_faucet_id)?;
    assert_eq!(
        NonFungibleFaucet::get_asset_status(
            nft_faucet_account.storage(),
            setup.terms.bond_commitment()
        )?,
        AssetStatus::Burned,
    );

    Ok(())
}

// HELPERS
// ================================================================================================

/// Returns `amount` units of the native fee asset.
fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_FEE_FAUCET)?, amount)?.into())
}

/// Creates a new public non-fungible network faucet controlled by `owner`, which is the only
/// account allowed to mint. Anyone can burn.
fn create_nft_faucet(
    init_seed: [u8; 32],
    owner: AccountId,
    send_policy: Option<SendPolicy>,
) -> anyhow::Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("BOND")?)
        .symbol(TokenSymbol::new("BOND")?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .maybe_active_send_policy(send_policy)
        .build();

    // The network auth prices the notes it consumes, as does the wallet creating a network note
    // for this faucet, so schedule a zero fee for every note the faucet accepts.
    let fee_policy = AuthNetworkAccount::default_allowed_note_scripts()
        .into_iter()
        .chain([MintNote::script_root(), BurnNote::script_root()])
        .fold(BasicConstantFeePolicy::new(), |fee_policy, script_root| {
            fee_policy.with_fee(script_root, AssetAmount::ZERO)
        });
    let fee_policy_manager = FeePolicyManager::builder()
        .active_fee_policy(fee_policy.into())
        .fee_faucet_id(AccountId::try_from(ACCOUNT_ID_FEE_FAUCET)?)
        .build();

    Ok(create_network_non_fungible_faucet(
        init_seed,
        faucet,
        AccessControl::Ownable2Step { owner },
        token_policy_manager,
        fee_policy_manager,
    )?)
}

/// Adds an existing public stablecoin faucet controlled by `issuer_id`, with `token_supply` in
/// circulation, to the chain.
///
/// Only the issuer can mint, block accounts and restrict their amounts. The faucet applies
/// [`stablecoin_send_policy`] with `issuer_key`, and rejects assets received by blocked accounts.
fn add_stablecoin_faucet(
    builder: &mut MockChainBuilder,
    issuer_id: AccountId,
    token_supply: AssetAmount,
    issuer_key: EncryptedAssetsIssuerKey,
) -> anyhow::Result<Account> {
    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(stablecoin_send_policy(issuer_key)?)
        .active_receive_policy(ReceivePolicy::empty_basic_blocklist())
        .build();
    let stablecoin = FungibleFaucet::builder()
        .name(TokenName::new("STABLE")?)
        .symbol(TokenSymbol::new("STBL")?)
        .decimals(6)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .token_supply(token_supply)
        .build()?;
    let faucet_seed = builder.rng_mut().random();

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        AccountBuilder::new(faucet_seed)
            .account_type(AccountType::Public)
            .with_component(stablecoin)
            .with_components(AccessControl::Ownable2Step { owner: issuer_id })
            .with_components(token_policy_manager)
            .with_component(BlocklistManager)
            .with_component(SupplyRestrictionManager),
        AccountState::Exists,
    )
}

/// Returns the send policy of the stablecoin, which rejects notes created by blocked accounts and
/// notes that spend frozen or confiscated amounts, and attaches the details of private notes,
/// encrypted to `issuer_key`.
///
/// The policy composes the checks of the basic blocklist and supply restriction policies with the
/// encrypted assets policy. The encrypted assets policy runs last, so the attachment list it
/// returns is the output of the composed policy.
fn stablecoin_send_policy(issuer_key: EncryptedAssetsIssuerKey) -> anyhow::Result<SendPolicy> {
    let (root, component) = policy_component(
        "tests::stablecoin_send_policy",
        "check_send_policy",
        Vec::new(),
        "
        use miden::standards::faucets::policies::transfer::basic_blocklist
        use miden::standards::faucets::policies::transfer::encrypted_assets
        use miden::standards::faucets::policies::transfer::supply_restriction_policy

        #! Inputs:  [note_idx, pad(15)]
        #! Outputs: [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
        @account_procedure
        pub proc check_send_policy
            exec.basic_blocklist::check_native_account
            exec.supply_restriction_policy::check_native_account
            # => [note_idx, pad(15)]

            exec.encrypted_assets::check_send_policy
            # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
        end
        ",
    )?;

    // the other components hold the storage of the composed policies
    Ok(SendPolicy::custom(
        root,
        [
            component,
            BasicBlocklist::default().into(),
            SupplyRestrictionPolicy::new(SupplyRestrictionStorage::new()).into(),
            issuer_key.into(),
        ],
    )?)
}

/// Adds an existing private wallet holding `assets` to the chain.
///
/// The chain holds only a commitment to the wallet's state, so the caller keeps the returned
/// account up to date with [`commit_private`].
fn add_private_wallet(
    builder: &mut MockChainBuilder,
    assets: impl IntoIterator<Item = Asset>,
) -> anyhow::Result<Account> {
    let wallet_seed = builder.rng_mut().random();

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        AccountBuilder::new(wallet_seed)
            .account_type(AccountType::Private)
            .with_component(BasicWallet)
            .with_assets(assets),
        AccountState::Exists,
    )
}

/// Returns the latest committed token supply of the stablecoin faucet.
fn stablecoin_token_supply(
    mock_chain: &MockChain,
    stablecoin_faucet_id: AccountId,
) -> anyhow::Result<AssetAmount> {
    let faucet = mock_chain.committed_account(stablecoin_faucet_id)?;
    Ok(FungibleFaucet::try_from(faucet.storage())?.token_supply())
}

/// Returns the amount of `holder_id` that is confiscated on the stablecoin faucet.
fn confiscated_amount(
    mock_chain: &MockChain,
    stablecoin_faucet_id: AccountId,
    holder_id: AccountId,
) -> anyhow::Result<AssetAmount> {
    let faucet = mock_chain.committed_account(stablecoin_faucet_id)?;
    let key = StorageMapKey::new(AccountIdKey::from(holder_id).as_word());
    // the restricted amounts are stored as [frozen, confiscated, 0, 0]
    let restricted_amounts = faucet
        .storage()
        .get_map_item(SupplyRestrictionStorage::restricted_amounts_slot(), key)?;
    Ok(AssetAmount::try_from(restricted_amounts[1])?)
}

/// Executes a transaction in which `holder` sends `amount` stablecoins in a private P2ID note.
///
/// The stablecoin faucet's send policy encrypts the details of the note to the issuer's key, so the
/// transaction provides them by expecting the note, and provides the issuer's `prepared_key`.
async fn send_stablecoins(
    mock_chain: &MockChain,
    holder: &Account,
    stablecoin_faucet_id: AccountId,
    prepared_key: &Arc<PreparedPublicKey>,
    amount: u32,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let note: Note = P2idNote::builder()
        .sender(holder.id())
        .target(AccountId::mock_private(2))
        .assets(vec![FungibleAsset::new(stablecoin_faucet_id, amount.into())?])
        .note_type(NoteType::Private)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    let script = SendNotesTransactionScript::new(
        &holder.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;

    Ok(mock_chain
        .build_transaction(holder.id())
        .send_notes_script(&script)
        .expected_output_note(RawOutputNote::Full(note))
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(stablecoin_faucet_id)?])
        .ies_prepared_public_key(Arc::clone(prepared_key))
        .build()?
        .execute()
        .await)
}

/// Executes a transaction in which the private `sender` sends `asset` to `target_id` in a private
/// P2ID note, and adds it to the chain.
///
/// The stablecoin faucet's send policy encrypts the details of the note to the issuer's key, so the
/// transaction provides them by expecting the note, and provides the issuer's `prepared_key`.
/// Returns the note as the transaction created it, i.e. with the attachment of the policy.
async fn send_private_stablecoins(
    mock_chain: &mut MockChain,
    sender: &mut Account,
    target_id: AccountId,
    asset: FungibleAsset,
    prepared_key: &Arc<PreparedPublicKey>,
) -> anyhow::Result<Note> {
    let note: Note = P2idNote::builder()
        .sender(sender.id())
        .target(target_id)
        .assets([asset])
        .note_type(NoteType::Private)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    let send_notes_script = SendNotesTransactionScript::new(
        &sender.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;

    let send_tx = mock_chain
        .build_transaction(sender.clone())
        .send_notes_script(&send_notes_script)
        .expected_output_note(RawOutputNote::Full(note))
        .foreign_accounts([mock_chain.get_foreign_account_inputs(asset.faucet_id())?])
        .ies_prepared_public_key(Arc::clone(prepared_key))
        .build()?
        .execute()
        .await?;
    let [RawOutputNote::Full(sent_note)] = send_tx.output_notes().iter().collect::<Vec<_>>()[..]
    else {
        anyhow::bail!("the transaction must create exactly the full P2ID note");
    };
    let sent_note = sent_note.clone();
    commit_private(mock_chain, sender, &send_tx)?;

    Ok(sent_note)
}

/// Executes a transaction in which the private `account` consumes the private `note` holding
/// stablecoins, whose details it received off-chain, and adds it to the chain.
///
/// Adding the stablecoins to the vault invokes the faucet's asset callback, so the transaction
/// reads the faucet as a foreign account.
async fn consume_private_stablecoins(
    mock_chain: &mut MockChain,
    account: &mut Account,
    note: Note,
    stablecoin_faucet_id: AccountId,
) -> anyhow::Result<ExecutedTransaction> {
    let consume_tx = mock_chain
        .build_transaction(account.clone())
        .authenticated_input_note(note)
        .foreign_accounts([mock_chain.get_foreign_account_inputs(stablecoin_faucet_id)?])
        .build()?
        .execute()
        .await?;
    commit_private(mock_chain, account, &consume_tx)?;

    Ok(consume_tx)
}

/// Returns the single private note of the latest block whose encrypted asset attachment decrypts
/// with the issuer's `secret_key`, and the note details the issuer learns from it.
///
/// The block holds only the headers and attachments of its private notes.
fn issuer_decrypts_new_note(
    mock_chain: &MockChain,
    secret_key: &SecretKey,
) -> anyhow::Result<(PrivateOutputNote, EncryptedAssetsAttachment)> {
    let decrypted_notes: Vec<_> = mock_chain
        .latest_block()
        .body()
        .output_notes()
        .filter_map(|(_, note)| {
            let OutputNote::Private(note) = note else {
                return None;
            };
            EncryptedAssetsAttachment::decrypt_and_verify_note(
                note.header(),
                note.attachments(),
                secret_key,
            )
            .map(|details| (note.clone(), details))
        })
        .collect();

    let Ok([decrypted_note]) = <[_; 1]>::try_from(decrypted_notes) else {
        anyhow::bail!("the issuer must decrypt exactly one note of the block");
    };
    Ok(decrypted_note)
}

/// Executes a transaction against the private `sender` that creates `note`.
///
/// A wallet creating a network note asks the target faucet for the note's fee, so for network notes
/// the NFT faucet is provided as a foreign account.
async fn send_note(
    mock_chain: &MockChain,
    sender: &Account,
    note: &Note,
    nft_faucet_id: AccountId,
) -> anyhow::Result<ExecutedTransaction> {
    let send_notes_script = SendNotesTransactionScript::new(
        &sender.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;

    let mut tx_builder = mock_chain
        .build_transaction(sender.clone())
        .send_notes_script(&send_notes_script)
        .expected_output_note(RawOutputNote::Full(note.clone()));
    if note.is_network_note() {
        tx_builder = tx_builder
            .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(nft_faucet_id)?]);
    }

    let executed_tx = tx_builder.native_fee_auth_args().build()?.execute().await?;

    Ok(executed_tx)
}

/// Returns the output notes of the transaction other than the note paying its fee.
fn non_fee_output_notes(executed_tx: &ExecutedTransaction) -> Vec<&RawOutputNote> {
    executed_tx
        .output_notes()
        .iter()
        .filter(|note| note.metadata().tag() != TxFeeNote::TAG)
        .collect()
}

/// Adds the executed transaction to the chain and proves the next block, committing its effects.
fn commit(mock_chain: &mut MockChain, executed_tx: &ExecutedTransaction) -> anyhow::Result<()> {
    mock_chain.add_pending_executed_transaction(executed_tx)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

/// Commits the executed transaction of the private `account` like [`commit`], and applies the
/// transaction's changes to `account`.
///
/// The block holds only the new commitment to the account's state, so the account's owner keeps
/// its own copy of the state up to date and checks it against that commitment.
fn commit_private(
    mock_chain: &mut MockChain,
    account: &mut Account,
    executed_tx: &ExecutedTransaction,
) -> anyhow::Result<()> {
    commit(mock_chain, executed_tx)?;
    account.apply_patch(executed_tx.account_patch())?;

    let block = mock_chain.latest_block();
    let account_update = block
        .body()
        .updated_accounts()
        .iter()
        .find(|update| update.account_id() == account.id())
        .context("the block must update the account")?;
    assert!(account_update.is_private(), "the block must hold only the account's commitment");
    assert_eq!(account_update.final_state_commitment(), account.to_commitment());

    Ok(())
}

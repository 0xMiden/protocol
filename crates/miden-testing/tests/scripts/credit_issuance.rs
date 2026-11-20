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
//! it expects from the agreed terms and watches the chain for their IDs.
//!
//! A second test covers the stablecoin side: the issuer confiscates stablecoins from a holder and
//! re-mints them to another account, which leaves the token supply unchanged.

use anyhow::Context;
use miden_protocol::Word;
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
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteTag, NoteType, PartialNote};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
};
use miden_protocol::testing::word::WordMockExt;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_standards::account::access::AccessControl;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::faucets::{
    AssetStatus,
    FungibleFaucet,
    NonFungibleFaucet,
    TokenName,
    TokenSupplyRestriction,
    create_network_non_fungible_faucet,
};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::note::config::{SupplyRestrictionConfig, SupplyRestrictionConfigNote};
use miden_standards::note::{
    BurnNote,
    MintNote,
    MintNoteStorage,
    NetworkNoteExt,
    P2idNoteStorage,
    SwapNote,
    TxFeeNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::{AccountState, Auth, MockChain};
use rand::RngExt;

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

/// The terms of the loan the originator, borrower and creditor agree on off-chain, including the
/// serial numbers of the notes.
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
    mint_serial_number: Word,
    issue_serial_number: Word,
    loan_serial_number: Word,
    repayment_serial_number: Word,
    burn_serial_number: Word,
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
            P2idNoteStorage::new(self.borrower_id).into_recipient(self.loan_serial_number),
        ))
    }

    /// Returns the private SWAP note the faucet mints the bond into: the creditor takes the bond
    /// and pays the principal to the borrower in a private P2ID loan note.
    fn issue_note(&self) -> anyhow::Result<Note> {
        let loan_recipient =
            P2idNoteStorage::new(self.borrower_id).into_recipient(self.loan_serial_number);

        let issue_note = SwapNote::builder()
            .sender(self.nft_faucet_id)
            .offered_asset(self.bond())
            .requested_asset(self.principal()?)
            .serial_number(self.issue_serial_number)
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
            .serial_number(self.mint_serial_number)
            .build()?;

        Ok(mint_note.into())
    }

    /// Returns the public BURN note the bond holder creates when filling the repayment note.
    fn burn_note(&self) -> anyhow::Result<Note> {
        let burn_note = BurnNote::builder()
            .sender(self.creditor_id)
            .asset(self.bond())
            .serial_number(self.burn_serial_number)
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
            .serial_number(self.repayment_serial_number)
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
struct TestSetup {
    originator: Account,
    creditor: Account,
    borrower: Account,
    nft_faucet: Account,
    stablecoin_asset_id: AssetId,
    terms: CreditTerms,
}

impl TestSetup {
    /// Creates the accounts on a fee-charging mock chain, deploys the network faucet and agrees on
    /// the terms.
    ///
    /// The creditor holds the principal and the borrower holds the interest upfront, so it can
    /// repay the full amount after receiving the principal. Every account holds the fee asset to
    /// pay for its transactions.
    async fn new() -> anyhow::Result<(MockChain, Self)> {
        let stablecoin_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
        let principal = AssetAmount::new(PRINCIPAL)?;
        let interest = compute_interest(principal, INTEREST_PERCENT)?;

        let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
        let originator = builder.add_existing_wallet_with_assets(
            Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
            [fee_asset(INITIAL_FEE_BALANCE)?],
        )?;
        let creditor = builder.add_existing_wallet_with_assets(
            Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
            [
                fee_asset(INITIAL_FEE_BALANCE)?,
                FungibleAsset::new(stablecoin_faucet_id, principal.as_u64())?.into(),
            ],
        )?;
        let borrower = builder.add_existing_wallet_with_assets(
            Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
            [
                fee_asset(INITIAL_FEE_BALANCE)?,
                FungibleAsset::new(stablecoin_faucet_id, interest.as_u64())?.into(),
            ],
        )?;
        let nft_faucet = create_nft_faucet(builder.rng_mut().random(), originator.id())?;
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
            mint_serial_number: Word::mock(2),
            issue_serial_number: Word::mock(3),
            loan_serial_number: Word::mock(4),
            repayment_serial_number: Word::mock(5),
            burn_serial_number: Word::mock(6),
        };

        let setup = Self {
            originator,
            creditor,
            borrower,
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
    let (mut mock_chain, setup) = TestSetup::new().await?;
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
    commit(&mut mock_chain, &send_mint_note_tx)?;

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
        .build_transaction(setup.creditor.id())
        .authenticated_input_note(issue_note)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &consume_issue_note_tx)?;

    let creditor_account = mock_chain.committed_account(setup.creditor.id())?;
    assert_eq!(creditor_account.vault().get(bond.id()), Some(bond));
    assert_eq!(
        creditor_account.vault().get_balance(setup.stablecoin_asset_id)?,
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
        .build_transaction(setup.borrower.id())
        .authenticated_input_note(loan_note)
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &consume_loan_note_tx)?;

    let borrower_account = mock_chain.committed_account(setup.borrower.id())?.clone();
    assert_eq!(
        borrower_account.vault().get_balance(setup.stablecoin_asset_id)?,
        repayment_amount,
    );

    // STEP 6: the borrower repays the loan with a private repayment SWAP note
    // --------------------------------------------------------------------------------------------

    let repayment_note = setup.terms.repayment_note()?;
    let repayment_id = repayment_note.id();

    let send_repayment_note_tx =
        send_note(&mock_chain, &borrower_account, &repayment_note, setup.nft_faucet.id()).await?;
    commit(&mut mock_chain, &send_repayment_note_tx)?;

    let borrower_account = mock_chain.committed_account(setup.borrower.id())?;
    assert_eq!(
        borrower_account.vault().get_balance(setup.stablecoin_asset_id)?,
        AssetAmount::ZERO
    );

    // STEP 7: the creditor sees the repayment note on-chain and consumes it
    // --------------------------------------------------------------------------------------------

    assert!(mock_chain.is_note_committed(&repayment_id));

    // Creating the BURN network note asks the faucet for its fee, so the faucet is a foreign
    // account of this transaction.
    let consume_repayment_note_tx = mock_chain
        .build_transaction(setup.creditor.id())
        .authenticated_input_note(repayment_note)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(setup.nft_faucet.id())?])
        .native_fee_auth_args()
        .build()?
        .execute()
        .await?;
    commit(&mut mock_chain, &consume_repayment_note_tx)?;

    let creditor_account = mock_chain.committed_account(setup.creditor.id())?;
    assert_eq!(creditor_account.vault().get(bond.id()), None);
    assert_eq!(
        creditor_account.vault().get_balance(setup.stablecoin_asset_id)?,
        repayment_amount,
    );

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

/// The stablecoin issuer confiscates an amount from a holder and re-mints it to a recovery
/// account, e.g. after the holder lost access to its keys.
///
/// Confiscating removes the amount from the token supply and re-minting adds it back, so the net
/// effect on the token supply is zero. The holder's balance is unchanged, but it is fully
/// confiscated, so only the recovery account's balance counts towards the circulating supply.
#[tokio::test]
async fn stablecoin_confiscation_and_remint() -> anyhow::Result<()> {
    const HOLDER_AMOUNT: u32 = 500;
    let amount = AssetAmount::from(HOLDER_AMOUNT);

    let mut builder = MockChain::builder();
    let issuer_id = AccountId::mock_private(1);

    // the holder already holds all stablecoins in circulation
    let stablecoin = FungibleFaucet::builder()
        .name(TokenName::new("STABLE")?)
        .symbol(TokenSymbol::new("STBL")?)
        .decimals(6)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .token_supply(amount)
        .build()?;
    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .build();
    let faucet_seed = builder.rng_mut().random();
    let stablecoin_faucet = builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        AccountBuilder::new(faucet_seed)
            .account_type(AccountType::Public)
            .with_component(stablecoin)
            .with_components(AccessControl::Ownable2Step { owner: issuer_id })
            .with_components(token_policy_manager)
            .with_component(TokenSupplyRestriction),
        AccountState::Exists,
    )?;
    let stablecoin_faucet_id = stablecoin_faucet.id();
    let stablecoin_asset = FungibleAsset::new(stablecoin_faucet_id, amount.as_u64())?;

    let holder = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        [stablecoin_asset.into()],
    )?;
    let recovery =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos })?;

    // the issuer's notes to confiscate the holder's stablecoins and re-mint them to the recovery
    // account in a public P2ID note
    let confiscate_note: Note = SupplyRestrictionConfigNote::builder()
        .sender(issuer_id)
        .target(stablecoin_faucet_id)
        .config(SupplyRestrictionConfig::Confiscate { account: holder.id(), amount })
        .serial_number(rand::rng().random())
        .build()?
        .into();
    let remint_note: Note = MintNote::builder()
        .sender(issuer_id)
        .mint_storage(MintNoteStorage::new_public_output(
            P2idNoteStorage::new(recovery.id()).into_recipient(rand::rng().random()),
            stablecoin_asset,
            NoteTag::with_account_target(recovery.id()),
        )?)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    for note in [&confiscate_note, &remint_note] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    let supply_before_confiscation = stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?;

    // STEP 1: the faucet consumes the confiscate note
    // --------------------------------------------------------------------------------------------

    mock_chain
        .consume_notes_and_commit(stablecoin_faucet_id, [confiscate_note])
        .await?;

    assert_eq!(stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?, AssetAmount::ZERO);
    assert_eq!(confiscated_amount(&mock_chain, stablecoin_faucet_id, holder.id())?, amount);

    // STEP 2: the faucet consumes the MINT note, re-minting the amount to the recovery account
    // --------------------------------------------------------------------------------------------

    let remint_tx =
        mock_chain.consume_notes_and_commit(stablecoin_faucet_id, [remint_note]).await?;
    let [RawOutputNote::Full(p2id_note)] = remint_tx.output_notes().iter().collect::<Vec<_>>()[..]
    else {
        anyhow::bail!("the faucet must create exactly the full P2ID note");
    };
    mock_chain.consume_notes_and_commit(recovery.id(), [p2id_note.clone()]).await?;

    let stablecoin_asset_id = AssetId::new_fungible(stablecoin_faucet_id);
    let recovery_account = mock_chain.committed_account(recovery.id())?;
    assert_eq!(recovery_account.vault().get_balance(stablecoin_asset_id)?, amount);

    // the confiscation and the re-mint cancel out
    assert_eq!(
        stablecoin_token_supply(&mock_chain, stablecoin_faucet_id)?,
        supply_before_confiscation
    );

    // the holder still holds the confiscated stablecoins, which a send policy must keep it from
    // spending
    let holder_account = mock_chain.committed_account(holder.id())?;
    assert_eq!(holder_account.vault().get_balance(stablecoin_asset_id)?, amount);

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
fn create_nft_faucet(init_seed: [u8; 32], owner: AccountId) -> anyhow::Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("BOND")?)
        .symbol(TokenSymbol::new("BOND")?)
        .build()?;

    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
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
        .get_map_item(TokenSupplyRestriction::restricted_amounts_slot(), key)?;
    Ok(AssetAmount::try_from(restricted_amounts[1])?)
}

/// Executes a transaction against `sender` that creates `note`.
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
        .build_transaction(sender.id())
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

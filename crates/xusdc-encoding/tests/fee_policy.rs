//! USDCx fee-policy composition and administration.
//!
//! The builder constructs the xUSDC fee policy from the network fee parameters, installs the
//! fee manager and `ConstantFeeManager`, and lets the `ADMIN` role reprice scheduled note roots
//! through `ConstantFeePolicyConfigNote`.

mod support;

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountType, StorageMapKey, StorageSlotContent,
};
use miden_protocol::asset::{AssetAmount, AssetId, FungibleAsset};
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{RawOutputNote, TransactionFee};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::SponsorshipPolicy;
use miden_standards::account::fees::{
    BasicConstantFeePolicy, ConstantFeeManager, FeePolicyManager,
};
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT,
};
use miden_standards::note::config::{
    BlocklistConfigNote, ConstantFeePolicyConfigNote, FaucetMetadataConfigNote,
    MinBurnAmountConfigNote, PauseConfigNote, RbacConfigNote,
};
use miden_standards::note::{FeeSponsorshipNote, MintNote, P2idNote, TxFeeNote};
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};
use miden_tx::NetworkNotePricer;
use support::mint_transport::commit;
use support::*;
use xusdc_encoding::account::xreserve::{XReserveAdminAuthority, XReserveStablecoinBuilder};
use xusdc_encoding::note::costs::{
    XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES, XUSDC_BURN_CONSUMPTION_CYCLES,
    XUSDC_MINT_CONSUMPTION_CYCLES,
};
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME,
};
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::xreserve::encoding::{ForeignChainAddress, Signature, XReserveBurnItems};

const NEW_FEE: u64 = 73;
const VERIFICATION_BASE_FEE: u32 = 500;
const SPONSORED_MINT_AMOUNT: u64 = 5_000;

fn fee_faucet_id() -> AccountId {
    ACCOUNT_ID_FEE_FAUCET
        .try_into()
        .expect("the protocol test fee-faucet id is valid")
}

fn fee_entry(amount: u64) -> Word {
    Word::from([
        Felt::new(amount).expect("the test fee fits in a felt"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ONE,
    ])
}

fn note_pricer() -> NetworkNotePricer {
    NetworkNotePricer::builder()
        .fee_parameters(fee_parameters())
        .fee_asset_id(fee_asset_id())
        .build()
}

fn fee_parameters() -> FeeParameters {
    FeeParameters::new(VERIFICATION_BASE_FEE)
}

fn fee_asset_id() -> AssetId {
    AssetId::new_fungible(fee_faucet_id())
}

fn production_builder() -> Result<XReserveStablecoinBuilder> {
    production_builder_with_supply(AssetAmount::ZERO)
}

fn production_builder_with_supply(token_supply: AssetAmount) -> Result<XReserveStablecoinBuilder> {
    Ok(XReserveStablecoinBuilder::builder()
        .token_supply(token_supply)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(1)])
        .pauser_holders(vec![test_account_id(2)])
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(fee_parameters())
        .fee_asset_id(fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()?)
}

fn scheduled_fee(account: &Account, note_root: NoteScriptRoot) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            BasicConstantFeePolicy::fee_schedule_slot_name(),
            StorageMapKey::new(note_root.as_word()),
        )
        .map_err(|err| anyhow::anyhow!("reading the fee schedule: {err}"))
}

fn scheduled_fee_amount(account: &Account, note_root: NoteScriptRoot) -> Result<AssetAmount> {
    AssetAmount::new(scheduled_fee(account, note_root)?[0].as_canonical_u64()).map_err(Into::into)
}

fn sponsorship_note<R: FeltRng>(
    feature_note: &Note,
    target: AccountId,
    amount: AssetAmount,
    rng: &mut R,
) -> Result<Note> {
    let note = FeeSponsorshipNote::builder()
        .sender(feature_note.metadata().sender())
        .target_account(target)
        .feature_note_id(feature_note.id())
        .asset(FungibleAsset::new(fee_faucet_id(), amount.as_u64())?)
        .generate_serial_number(rng)
        .build()?;
    Ok(Note::from(note))
}

fn assert_output_note_roots(
    executed: &miden_protocol::transaction::ExecutedTransaction,
    expected: &[NoteScriptRoot],
) {
    let actual: Vec<NoteScriptRoot> = (0..executed.output_notes().num_notes())
        .map(|index| {
            executed
                .output_notes()
                .get_note(index)
                .recipient()
                .expect("fee-enabled output notes are public")
                .script()
                .root()
        })
        .collect();
    for root in expected {
        assert!(
            actual.contains(root),
            "missing expected output note root {root}"
        );
    }
    assert_eq!(actual.len(), expected.len());
}

fn repricing_note(
    sender: AccountId,
    target: AccountId,
    fee_issuer: AccountId,
    note_root: NoteScriptRoot,
    amount: u64,
    serial_seed: u32,
) -> Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(target)
        .note_script_root(note_root)
        .fee_asset(FungibleAsset::new(fee_issuer, amount)?)
        .serial_number(Word::from([serial_seed, 0, 0, 0]))
        .build()?;
    Ok(Note::from(note))
}

fn priced_components() -> Result<Vec<AccountComponent>> {
    Ok(production_builder()?.build_components()?)
}

struct SponsoredConfigFixture {
    mock_chain: MockChain,
    faucet_id: AccountId,
    feature_note: Note,
    sponsorship_note: Note,
    config_note_fee: AssetAmount,
    mint_fee: AssetAmount,
}

fn assert_mint_fee_unchanged(fixture: &SponsoredConfigFixture) -> Result<()> {
    let account = fixture.mock_chain.committed_account(fixture.faucet_id)?;
    assert_eq!(
        scheduled_fee(account, MintNote::script_root())?,
        fee_entry(fixture.mint_fee.as_u64()),
        "a rejected config note must leave the schedule unchanged",
    );
    Ok(())
}

fn setup_sponsored_config_note(
    build_note: impl FnOnce(AccountId) -> Result<Note>,
) -> Result<SponsoredConfigFixture> {
    let config_note_fee = note_pricer().price(ConstantFeePolicyConfigNote::script_root())?;
    let components = priced_components()?;
    let account = build_network_faucet_account(components, fee_parameters(), fee_asset_id())?;
    let mint_fee =
        AssetAmount::new(scheduled_fee(&account, MintNote::script_root())?[0].as_canonical_u64())?;
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    builder.add_account(account.clone())?;
    let feature_note = build_note(account.id())?;
    let sponsorship_note: Note = FeeSponsorshipNote::builder()
        .sender(feature_note.metadata().sender())
        .target_account(account.id())
        .feature_note_id(feature_note.id())
        .asset(FungibleAsset::new(
            fee_faucet_id(),
            config_note_fee.as_u64(),
        )?)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(feature_note.clone()));
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    Ok(SponsoredConfigFixture {
        mock_chain,
        faucet_id: account.id(),
        feature_note,
        sponsorship_note,
        config_note_fee,
        mint_fee,
    })
}

struct SponsoredMintFixture {
    mock_chain: MockChain,
    faucet_id: AccountId,
    recipient_id: AccountId,
    attester_note: Note,
    attester_sponsorship: Note,
    mint_note: Note,
    mint_sponsorship: Note,
}

fn setup_sponsored_mint() -> Result<SponsoredMintFixture> {
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    let recipient = builder.add_existing_wallet(Auth::IncrNonce)?;
    let producer = add_emitting_wallet(&mut builder, Auth::IncrNonce, [])?;
    let account =
        build_network_faucet_account(priced_components()?, fee_parameters(), fee_asset_id())?;
    builder.add_account(account.clone())?;

    let payload = support::mint_transport::payload_for(
        recipient.id(),
        account.id(),
        SPONSORED_MINT_AMOUNT,
        31,
    );
    let attester = gen_attester(1, &payload);
    let attester_note = XReserveSetAttesterNote::create(
        test_account_id(1),
        account.id(),
        attester.commitment,
        1,
        builder.rng_mut(),
    )?;
    let attester_sponsorship = sponsorship_note(
        &attester_note,
        account.id(),
        scheduled_fee_amount(&account, XReserveSetAttesterNote::script_root())?,
        builder.rng_mut(),
    )?;
    let mint_note = mint_note_from_payload(
        producer.id(),
        account.id(),
        &payload,
        DepositAttestation::new(Signature::new(attester.sig_bytes), attester.pubkey),
        builder.rng_mut(),
    )?;
    let mint_sponsorship = sponsorship_note(
        &mint_note,
        account.id(),
        scheduled_fee_amount(&account, MintNote::script_root())?,
        builder.rng_mut(),
    )?;

    for note in [
        &attester_note,
        &attester_sponsorship,
        &mint_note,
        &mint_sponsorship,
    ] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    Ok(SponsoredMintFixture {
        mock_chain,
        faucet_id: account.id(),
        recipient_id: recipient.id(),
        attester_note,
        attester_sponsorship,
        mint_note,
        mint_sponsorship,
    })
}

struct SponsoredBurnFixture {
    mock_chain: MockChain,
    faucet_id: AccountId,
    user_id: AccountId,
    burn_asset: FungibleAsset,
    burn_items: XReserveBurnItems,
    burn_note: Note,
    sponsorship_note: Note,
}

fn setup_sponsored_burn() -> Result<SponsoredBurnFixture> {
    let amount = AssetAmount::new(SPONSORED_MINT_AMOUNT)?;
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    let components = production_builder_with_supply(amount)?.build_components()?;
    let account = build_network_faucet_account(components, fee_parameters(), fee_asset_id())?;
    builder.add_account(account.clone())?;
    let burn_asset = FungibleAsset::new(account.id(), amount.as_u64())?;
    let user = add_emitting_wallet(&mut builder, Auth::IncrNonce, [burn_asset.into()])?;
    let burn_items = XReserveBurnItems::builder()
        .dest_domain(TEST_SOURCE_DOMAIN)
        .dest_recipient(ForeignChainAddress::new([0xAB; 32]))
        .build();
    let burn_note = XReserveBurnNote::create(
        user.id(),
        account.id(),
        amount,
        burn_items.clone(),
        builder.rng_mut(),
    )?;
    let sponsorship_note = sponsorship_note(
        &burn_note,
        account.id(),
        scheduled_fee_amount(&account, XReserveBurnNote::script_root())?,
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    Ok(SponsoredBurnFixture {
        mock_chain,
        faucet_id: account.id(),
        user_id: user.id(),
        burn_asset,
        burn_items,
        burn_note,
        sponsorship_note,
    })
}

struct InsufficientFeeFixture {
    mock_chain: MockChain,
    faucet_id: AccountId,
    feature_note: Note,
    sponsorship_note: Option<Note>,
}

fn setup_insufficient_fee(sponsored_amount: Option<u64>) -> Result<InsufficientFeeFixture> {
    let mut builder = MockChain::builder()
        .fee_faucet_id(fee_faucet_id())
        .verification_base_fee(VERIFICATION_BASE_FEE);
    let account =
        build_network_faucet_account(priced_components()?, fee_parameters(), fee_asset_id())?;
    builder.add_account(account.clone())?;
    let feature_note = XReserveSetAttesterNote::create(
        test_account_id(1),
        account.id(),
        Word::from([71u32, 72, 73, 74]),
        1,
        builder.rng_mut(),
    )?;
    let sponsorship_note = sponsored_amount
        .map(|amount| {
            sponsorship_note(
                &feature_note,
                account.id(),
                AssetAmount::new(amount)?,
                builder.rng_mut(),
            )
        })
        .transpose()?;
    builder.add_output_note(RawOutputNote::Full(feature_note.clone()));
    if let Some(note) = &sponsorship_note {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    Ok(InsufficientFeeFixture {
        mock_chain,
        faucet_id: account.id(),
        feature_note,
        sponsorship_note,
    })
}

#[test]
fn production_installs_one_mutable_basic_constant_fee_policy() -> Result<()> {
    let components = priced_components()?;
    assert!(
        components
            .iter()
            .any(|component| component.has_procedure(ConstantFeeManager::set_note_fee_root())),
        "the production component set must install ConstantFeeManager::set_note_fee",
    );

    let auth_components: Vec<AccountComponent> =
        XReserveStablecoinBuilder::auth_component(fee_parameters(), fee_asset_id())?
            .into_iter()
            .collect();
    assert_eq!(
        auth_components
            .iter()
            .filter(|component| component.has_procedure(BasicConstantFeePolicy::root()))
            .count(),
        1,
        "the auth composition must install exactly one BasicConstantFeePolicy component",
    );

    let fee_schedule = auth_components
        .iter()
        .flat_map(|component| component.storage_slots())
        .find(|slot| slot.name() == BasicConstantFeePolicy::fee_schedule_slot_name())
        .expect("the constructed fee policy carries its schedule");
    let StorageSlotContent::Map(fee_schedule) = fee_schedule.content() else {
        anyhow::bail!("the fee schedule slot must be a map");
    };
    let allowed_roots = XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(
        fee_schedule.num_entries(),
        allowed_roots.len(),
        "the fee schedule and note allowlist must contain the same number of roots",
    );
    for root in &allowed_roots {
        assert_ne!(
            fee_schedule.get(&StorageMapKey::new(root.as_word())),
            Word::empty(),
            "every allowlisted note root must have an explicit schedule entry",
        );
    }

    let manager_slots = auth_components[0].storage_slots();
    assert_eq!(
        manager_slots
            .iter()
            .find(|slot| slot.name() == FeePolicyManager::active_fee_policy_slot())
            .expect("the auth component carries the active fee-policy slot")
            .value(),
        BasicConstantFeePolicy::root().as_word(),
    );
    assert_eq!(
        manager_slots
            .iter()
            .find(|slot| slot.name() == FeePolicyManager::fee_asset_id_slot())
            .expect("the auth component carries the fee-asset slot")
            .value(),
        AssetId::new_fungible(fee_faucet_id()).to_word(),
        "the fee manager must store the explicitly supplied fee faucet's fungible asset id",
    );
    let allowed_slot = manager_slots
        .iter()
        .find(|slot| slot.name() == FeePolicyManager::allowed_fee_policies_slot())
        .expect("the auth component carries the allowed fee-policies slot");
    let StorageSlotContent::Map(allowed_policies) = allowed_slot.content() else {
        anyhow::bail!("the allowed fee-policies slot must be a map");
    };
    assert_eq!(
        allowed_policies.num_entries(),
        1,
        "the internally built manager must not register a reserved alternate policy",
    );
    assert_eq!(
        allowed_policies.get(&StorageMapKey::new(
            BasicConstantFeePolicy::root().as_word()
        )),
        Word::from([1u32, 0, 0, 0]),
    );

    assert!(
        !XReserveAdminAuthority::new()
            .procedure_roles()
            .contains_key(&ConstantFeeManager::set_note_fee_root()),
        "set_note_fee must be unmapped so Authority::RbacControlled falls back to ADMIN",
    );
    Ok(())
}

#[test]
fn fee_policy_prices_standard_and_xusdc_execution_paths() -> Result<()> {
    let account =
        build_network_faucet_account(priced_components()?, fee_parameters(), fee_asset_id())?;
    let pricer = note_pricer();
    let own_fee =
        |cycles| -> Result<u64> { Ok(pricer.fee(TransactionFee::new(cycles)?)?.as_u64()) };
    let expected_mint =
        own_fee(XUSDC_MINT_CONSUMPTION_CYCLES)? + pricer.price(P2idNote::script_root())?.as_u64();

    for (root, expected) in [
        (MintNote::script_root(), expected_mint),
        (
            XReserveBurnNote::script_root(),
            own_fee(XUSDC_BURN_CONSUMPTION_CYCLES)?,
        ),
        (
            XReserveSetAttesterNote::script_root(),
            own_fee(XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES)?,
        ),
        (
            MinBurnAmountConfigNote::script_root(),
            pricer
                .price(MinBurnAmountConfigNote::script_root())?
                .as_u64(),
        ),
        (
            FaucetMetadataConfigNote::script_root(),
            pricer
                .price(FaucetMetadataConfigNote::script_root())?
                .as_u64(),
        ),
        (
            PauseConfigNote::script_root(),
            pricer.price(PauseConfigNote::script_root())?.as_u64(),
        ),
        (
            BlocklistConfigNote::script_root(),
            pricer.price(BlocklistConfigNote::script_root())?.as_u64(),
        ),
        (
            RbacConfigNote::script_root(),
            pricer.price(RbacConfigNote::script_root())?.as_u64(),
        ),
        (
            ConstantFeePolicyConfigNote::script_root(),
            pricer
                .price(ConstantFeePolicyConfigNote::script_root())?
                .as_u64(),
        ),
    ] {
        assert_eq!(scheduled_fee(&account, root)?, fee_entry(expected));
        assert!(
            expected > 0,
            "the verification base fee must price every checked path"
        );
    }
    assert_eq!(
        scheduled_fee(&account, FeeSponsorshipNote::script_root())?,
        fee_entry(0),
        "sponsorship notes are exempt from sponsoring themselves and price to zero"
    );
    Ok(())
}

#[tokio::test]
async fn sponsored_mint_uses_the_installed_xusdc_fee_schedule() -> Result<()> {
    let mut fixture = setup_sponsored_mint()?;

    let activation = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.attester_note.id())
        .authenticated_input_note(fixture.attester_sponsorship.id())
        .build()?
        .execute()
        .await?;
    assert!(activation.compute_fee().as_u64() > 0);
    assert_output_note_roots(&activation, &[TxFeeNote::script_root()]);
    commit(&mut fixture.mock_chain, &activation)?;

    let minted = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.mint_note.id())
        .authenticated_input_note(fixture.mint_sponsorship.id())
        .build()?
        .execute()
        .await?;
    assert!(minted.compute_fee().as_u64() > 0);
    assert_output_note_roots(
        &minted,
        &[P2idNote::script_root(), TxFeeNote::script_root()],
    );
    let p2id = (0..minted.output_notes().num_notes())
        .map(|index| minted.output_notes().get_note(index))
        .find(|note| {
            note.recipient()
                .is_some_and(|recipient| recipient.script().root() == P2idNote::script_root())
        })
        .expect("the mint transaction creates a P2ID note");
    let minted_asset = p2id
        .assets()
        .iter_fungible()
        .next()
        .expect("the P2ID note carries the minted fungible asset");
    assert_eq!(minted_asset.faucet_id(), fixture.faucet_id);
    assert_eq!(minted_asset.amount().as_u64(), SPONSORED_MINT_AMOUNT);
    assert_eq!(
        p2id.metadata().tag(),
        miden_protocol::note::NoteTag::with_account_target(fixture.recipient_id),
    );

    commit(&mut fixture.mock_chain, &minted)?;
    assert_eq!(
        committed_token_supply(&fixture.mock_chain, fixture.faucet_id)?,
        AssetAmount::new(SPONSORED_MINT_AMOUNT)?,
    );
    assert!(fixture
        .mock_chain
        .is_note_consumed(&fixture.mint_note.nullifier()));
    assert!(fixture
        .mock_chain
        .is_note_consumed(&fixture.mint_sponsorship.nullifier()));
    Ok(())
}

#[tokio::test]
async fn sponsored_burn_uses_the_installed_xusdc_fee_schedule() -> Result<()> {
    let mut fixture = setup_sponsored_burn()?;
    let mut payload = fixture
        .burn_note
        .attachments()
        .iter()
        .find(|attachment| {
            attachment.attachment_scheme().as_u16() == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME
        })
        .expect("the burn note carries its withdrawal attachment")
        .content()
        .to_elements();
    payload.truncate(XReserveBurnNote::NUM_PAYLOAD_ITEMS);
    assert_eq!(XReserveBurnItems::decode(&payload)?, fixture.burn_items);

    let emitted = try_emit_burn_note(
        &fixture.mock_chain,
        &fixture.burn_note,
        &fixture.burn_asset,
        fixture.faucet_id,
        fixture.user_id,
    )
    .await?;
    commit(&mut fixture.mock_chain, &emitted)?;

    let burned = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.burn_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await?;
    assert!(burned.compute_fee().as_u64() > 0);
    assert_output_note_roots(&burned, &[TxFeeNote::script_root()]);
    commit(&mut fixture.mock_chain, &burned)?;

    assert_eq!(
        committed_token_supply(&fixture.mock_chain, fixture.faucet_id)?,
        AssetAmount::ZERO,
    );
    assert!(fixture
        .mock_chain
        .is_note_consumed(&fixture.burn_note.nullifier()));
    assert!(fixture
        .mock_chain
        .is_note_consumed(&fixture.sponsorship_note.nullifier()));
    Ok(())
}

#[tokio::test]
async fn priced_xusdc_note_requires_complete_sponsorship() -> Result<()> {
    let account =
        build_network_faucet_account(priced_components()?, fee_parameters(), fee_asset_id())?;
    let required = scheduled_fee_amount(&account, XReserveSetAttesterNote::script_root())?.as_u64();
    assert!(required > 0);
    for sponsored_amount in [None, Some(required - 1)] {
        let fixture = setup_insufficient_fee(sponsored_amount)?;
        let mut transaction = fixture
            .mock_chain
            .build_transaction(fixture.faucet_id)
            .authenticated_input_note(fixture.feature_note.id());
        if let Some(note) = &fixture.sponsorship_note {
            transaction = transaction.authenticated_input_note(note.id());
        }
        let result = transaction.build()?.execute().await;
        assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED);
    }
    Ok(())
}

#[tokio::test]
async fn administrator_reprices_a_priced_config_note_under_collected_fees_bound() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(1),
            faucet_id,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            1,
        )
    })?;
    let account = fixture
        .mock_chain
        .committed_account(fixture.faucet_id)?
        .clone();
    assert_eq!(
        SponsorshipPolicy::try_from(account.storage())?,
        SponsorshipPolicy::AtMostCollectedFees,
    );
    assert_eq!(
        scheduled_fee(&account, ConstantFeePolicyConfigNote::script_root())?,
        fee_entry(fixture.config_note_fee.as_u64()),
        "the config note must retain its deployment fee",
    );

    let executed = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await?;
    assert!(
        executed.compute_fee().as_u64() > 0,
        "the fee-enabled transaction must pay a fee"
    );
    let mut evolved = account;
    evolved.apply_patch(executed.account_patch())?;
    assert_eq!(
        scheduled_fee(&evolved, MintNote::script_root())?,
        fee_entry(NEW_FEE)
    );
    Ok(())
}

#[tokio::test]
async fn config_note_for_another_account_cannot_reprice_the_faucet() -> Result<()> {
    let other_account = AccountId::builder()
        .account_type(AccountType::Public)
        .build_with_seed([98; 32]);
    let fixture = setup_sponsored_config_note(|_faucet_id| {
        repricing_note(
            test_account_id(1),
            other_account,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            4,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn non_administrator_cannot_reprice_the_fee_schedule() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(99),
            faucet_id,
            fee_faucet_id(),
            MintNote::script_root(),
            NEW_FEE,
            2,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}

#[tokio::test]
async fn configured_fee_asset_cannot_be_changed_by_a_config_note() -> Result<()> {
    let fixture = setup_sponsored_config_note(|faucet_id| {
        repricing_note(
            test_account_id(1),
            faucet_id,
            test_faucet_id(249),
            MintNote::script_root(),
            NEW_FEE,
            3,
        )
    })?;
    let result = fixture
        .mock_chain
        .build_transaction(fixture.faucet_id)
        .authenticated_input_note(fixture.feature_note.id())
        .authenticated_input_note(fixture.sponsorship_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str(
            "provided fee asset ID does not match the fee manager's configured fee asset ID",
        )
    );
    assert_mint_fee_unchanged(&fixture)?;
    Ok(())
}

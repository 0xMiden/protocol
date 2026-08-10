use std::collections::BTreeSet;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteScriptRoot, NoteTag, NoteType, PartialNote};
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::{
    AuthNetworkAccount,
    FeeConversionInfo,
    SponsorshipPolicy,
    commit_fee_conversion_info,
};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{
    FeeSponsorshipNote,
    NetworkAccountTarget,
    NoteExecutionHint,
    P2idNote,
    TxFeeNote,
};
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::utils::create_spawn_note;
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

/// Builds an existing public network account (`AuthNetworkAccount` + `BasicWallet` +
/// `FeePolicyManager`) that allowlists `allowed_notes`, prices each `(root, amount)` in `priced`
/// through its active `BasicConstantFeePolicy`, holds `assets` in its vault, and bounds its
/// sponsorship spending by `sponsorship_policy`.
fn network_account(
    seed: [u8; 32],
    allowed_notes: impl IntoIterator<Item = NoteScriptRoot>,
    priced: &[(NoteScriptRoot, u64)],
    assets: impl IntoIterator<Item = Asset>,
    sponsorship_policy: SponsorshipPolicy,
) -> anyhow::Result<Account> {
    let mut policy = BasicConstantFeePolicy::new();
    for (root, amount) in priced {
        policy = policy.with_fee(*root, AssetAmount::new(*amount)?);
    }
    let fee_policy_manager = FeePolicyManager::builder()
        .active_fee_policy(policy.into())
        .fee_faucet_id(fee_faucet_id()?)
        .build();
    let auth = AuthNetworkAccount::new(BTreeSet::from_iter(allowed_notes), fee_policy_manager)?
        .with_sponsorship_policy(sponsorship_policy);

    Ok(AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_components(auth)
        .with_component(BasicWallet)
        .with_assets(assets)
        .build_existing()?)
}

/// Returns the auth args and advice-map entry committing to the trivial (native, rate 1/1) fee
/// conversion info, for a signing account paying its own fee.
fn native_conversion_info() -> (Word, Vec<miden_protocol::Felt>) {
    commit_fee_conversion_info(
        FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into().unwrap()),
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
/// carrying exactly the fee the target account's policy prices the note at.
#[tokio::test]
async fn pay_fee_sponsors_network_output_note() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::from([1u32, 2, 3, 4]));
    // a payload asset issued by a faucet other than the fee faucet, carried by the network note
    let payload_asset: Asset = FungibleAsset::mock(50);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);

    // the sponsor is a signing wallet holding the fee asset (for its own fee and the sponsorship)
    // and the payload asset
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::basic_ecdsa(),
        [fee_asset(1_000_000)?, payload_asset],
    )?;

    // the target network account prices the P2ID script root at FEE_AMOUNT
    let target = network_account(
        [2; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [],
        SponsorshipPolicy::default(),
    )?;
    builder.add_account(target.clone())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // the sponsor creates the P2ID network note via a send-notes transaction script
    let network_note = p2id_network_note(sponsor.id(), target.id(), payload_asset, &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?;

    let (auth_args, advice_value) = native_conversion_info();
    let foreign_target = mock_chain.get_foreign_account_inputs(target.id())?;

    let executed = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([foreign_target])
        .send_notes_script(&tx_script)
        .auth_args(auth_args)
        .add_advice_map_entry(auth_args, advice_value)
        .expected_output_note(RawOutputNote::Full(network_note.clone()))
        .build()?
        .execute()
        .await?;

    // three output notes: the network note, its sponsorship note, and the sponsor's fee note
    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 3);

    // the network note is the first note
    assert_eq!(
        output_notes.get_note(0).id(),
        network_note.id(),
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

/// End-to-end single hop: a local wallet creates a P2ID network note (and, via `pay_fee`, its
/// FEE_SPONSORSHIP note); the target network account then consumes both, and its
/// `collect_sponsored_fees` credits the prepaid fee into its vault.
#[tokio::test]
async fn network_account_collects_sponsored_fee_single_hop() -> anyhow::Result<()> {
    const NETWORK_INITIAL_FEE_BALANCE: u64 = 1_000_000;

    let mut rng = RandomCoin::new(Word::from([1u32, 2, 3, 4]));
    let payload_asset = FungibleAsset::mock(50).unwrap_fungible();

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let sponsor = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth { auth_scheme: AuthScheme::EcdsaK256Keccak },
        [fee_asset(1_000_000)?, Asset::from(payload_asset)],
    )?;
    let network = network_account(
        [2; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [fee_asset(NETWORK_INITIAL_FEE_BALANCE)?],
        SponsorshipPolicy::default(),
    )?;
    builder.add_account(network.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // tx1: the sponsor creates the P2ID network note; pay_fee adds its sponsorship note
    let network_note =
        p2id_network_note(sponsor.id(), network.id(), Asset::from(payload_asset), &mut rng)?;
    let tx_script = SendNotesTransactionScript::new(
        &sponsor.code().interface(sponsor.id()),
        &[PartialNote::from(network_note.clone())],
    )?;
    let (auth_args, advice_value) = native_conversion_info();
    let foreign_network = mock_chain.get_foreign_account_inputs(network.id())?;
    let creation_tx = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([foreign_network])
        .send_notes_script(&tx_script)
        .auth_args(auth_args)
        .add_advice_map_entry(auth_args, advice_value)
        .expected_output_note(RawOutputNote::Full(network_note.clone()))
        .build()?
        .execute()
        .await?;

    let sponsorship_id = creation_tx
        .output_notes()
        .iter()
        .find(|note| {
            note.recipient().map(|recipient| recipient.script().root())
                == Some(FeeSponsorshipNote::script_root())
        })
        .expect("a sponsorship note should be created")
        .id();

    mock_chain.add_pending_executed_transaction(&creation_tx)?;
    mock_chain.prove_next_block()?;

    // tx2: the network account consumes the feature note and its sponsorship and collects the
    // prepaid fee.
    let collection_tx = mock_chain
        .build_transaction(network.id())
        .authenticated_input_note(sponsorship_id)
        .authenticated_input_note(network_note.id())
        .build()?
        .execute()
        .await?;

    // the network account pays its own fee note
    let fee_note = collection_tx
        .output_notes()
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("the network account should pay its own fee note");
    let &Asset::Fungible(paid) =
        fee_note.assets().iter().next().expect("fee note carries one asset")
    else {
        panic!("fee note asset should be fungible");
    };

    mock_chain.add_pending_executed_transaction(&collection_tx)?;
    mock_chain.prove_next_block()?;

    // the network account's fee-asset balance reflects the collected sponsorship (+FEE_AMOUNT), net
    // of the fee it paid for its own transaction
    let committed = mock_chain.committed_account(network.id())?;
    let fee_balance = committed.vault().get_balance(AssetId::new_fungible(fee_faucet_id()?))?;
    assert_eq!(
        fee_balance.as_u64(),
        NETWORK_INITIAL_FEE_BALANCE + FEE_AMOUNT - paid.amount().as_u64(),
    );

    // and it received the feature note's payload asset
    let payload_balance = committed
        .vault()
        .get_balance(AssetId::new_fungible(payload_asset.faucet_id()))?;
    assert_eq!(payload_balance.as_u64(), payload_asset.amount().as_u64());

    Ok(())
}

/// End-to-end multi hop: network account A consumes a spawn note, which creates a P2ID network
/// note targeting network account B and (via A's `pay_fee`) sponsors that note; B then consumes the
/// note and its sponsorship, collecting the prepaid fee.
#[tokio::test]
async fn spawned_network_note_sponsored_by_a_and_collected_by_b_multi_hop() -> anyhow::Result<()> {
    const B_INITIAL_FEE_BALANCE: u64 = 1_000_000;

    let mut rng = RandomCoin::new(Word::from([7u32, 8, 9, 10]));
    let payload_asset: Asset = FungibleAsset::mock(50);

    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);

    // downstream network account B, whose policy prices the spawned P2ID note
    let network_b = network_account(
        [3; 32],
        [P2idNote::script_root(), FeeSponsorshipNote::script_root()],
        &[(P2idNote::script_root(), FEE_AMOUNT)],
        [fee_asset(B_INITIAL_FEE_BALANCE)?],
        SponsorshipPolicy::default(),
    )?;

    // probe network account A to learn its id (independent of allowlist storage), which the
    // spawned note names as sender; the spawn note is authored by A and consumed by A
    let network_a_id =
        network_account([2; 32], [P2idNote::script_root()], &[], [], SponsorshipPolicy::Unlimited)?
            .id();
    let spawned_note = p2id_network_note(network_a_id, network_b.id(), payload_asset, &mut rng)?;
    let spawn_note = create_spawn_note([&spawned_note])?;

    // real network account A allowlists the spawn note, funded to pay its own fee, to sponsor the
    // spawned note, and to move the payload into it; A's policy must price the spawn note it
    // consumes, since a constant policy aborts fee estimation for unscheduled note scripts
    let network_a = network_account(
        [2; 32],
        [spawn_note.script().root(), FeeSponsorshipNote::script_root()],
        &[(spawn_note.script().root(), 0)],
        [fee_asset(1_000_000)?, payload_asset],
        SponsorshipPolicy::Unlimited,
    )?;
    assert_eq!(network_a.id(), network_a_id, "account id must not depend on the allowlist");

    builder.add_account(network_a.clone())?;
    builder.add_account(network_b.clone())?;
    builder.add_output_note(RawOutputNote::Full(spawn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // tx1: A consumes the spawn note, creating the P2ID network note and sponsoring it
    let foreign_b = mock_chain.get_foreign_account_inputs(network_b.id())?;
    let spawn_tx = mock_chain
        .build_transaction(network_a.id())
        .authenticated_input_note(spawn_note.id())
        .foreign_accounts([foreign_b])
        .expected_output_notes(vec![RawOutputNote::Full(spawned_note.clone())])
        .build()?
        .execute()
        .await?;

    assert!(
        spawn_tx.output_notes().iter().any(|note| note.id() == spawned_note.id()),
        "A should create the spawned network note",
    );
    let sponsorship_id = spawn_tx
        .output_notes()
        .iter()
        .find(|note| {
            note.recipient().map(|recipient| recipient.script().root())
                == Some(FeeSponsorshipNote::script_root())
        })
        .expect("A should sponsor the spawned note")
        .id();

    mock_chain.add_pending_executed_transaction(&spawn_tx)?;
    mock_chain.prove_next_block()?;

    // tx2: B consumes the spawned feature note and its sponsorship, collecting the prepaid fee
    let collect_tx = mock_chain
        .build_transaction(network_b.id())
        .authenticated_input_notes([spawned_note.id(), sponsorship_id])
        .build()?
        .execute()
        .await?;

    let fee_note = collect_tx
        .output_notes()
        .iter()
        .find(|note| note.metadata().tag() == TxFeeNote::TAG)
        .expect("B should pay its own fee note");
    let paid = fee_note
        .assets()
        .iter()
        .next()
        .expect("fee note carries one asset")
        .unwrap_fungible();

    mock_chain.add_pending_executed_transaction(&collect_tx)?;
    mock_chain.prove_next_block()?;

    // B collected the fee A prepaid for the spawned note
    let committed_b = mock_chain.committed_account(network_b.id())?;
    let b_fee_balance = committed_b.vault().get_balance(AssetId::new_fungible(fee_faucet_id()?))?;
    assert_eq!(
        b_fee_balance.as_u64(),
        B_INITIAL_FEE_BALANCE + FEE_AMOUNT - paid.amount().as_u64(),
    );

    Ok(())
}

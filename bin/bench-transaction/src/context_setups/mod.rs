use std::collections::BTreeSet;

use anyhow::Result;
pub use miden_agglayer::testing::ClaimDataSource;
use miden_agglayer::testing::create_existing_bridge_account_with_roles;
use miden_agglayer::{
    AggLayerBridge,
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    ConversionMetadata,
    DeregisterAggFaucetNote,
    EthAddress,
    MetadataHash,
    RemoveGerNote,
    UpdateGerNote,
    create_existing_agglayer_faucet,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, StorageMapKey};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteAssets, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_FEE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountConfigNote, StandardNote};
use miden_testing::{Auth, MockChain, MockChainBuilder, MockTransaction};
use rand::RngExt;

use crate::cycle_counting_benchmarks::ExecutionBenchmark;

mod network_action;
mod network_faucet;
mod network_wallet;

/// AggLayer network ID encoded in the bundled claim test vectors. Bridges in these benchmark
/// setups are created with this value so vector-based claims validate against the configured ID.
const MIDEN_NETWORK_ID: u32 = 77;

// SHARED NETWORK-ACCOUNT SCENARIO HELPERS
// ================================================================================================

/// Verification base fee charged by the chains of the network-account benchmark scenarios.
///
/// Mirrors `VERIFICATION_BASE_FEE` in `crates/miden-testing/tests/auth/fee_payment/mod.rs` so the
/// benchmarked transactions pay fees the same way the fee-payment tests exercise them.
pub const NETWORK_VERIFICATION_BASE_FEE: u32 = 500;

/// Amount of the native fee asset the consuming account is funded with.
///
/// Generous compared to the actual fee (roughly `verification_base_fee * 20`), so fee payment
/// never fails for lack of funds.
const FEE_FUNDING_AMOUNT: u64 = 1_000_000;

/// Returns the chain's native fee asset carrying [`FEE_FUNDING_AMOUNT`].
fn fee_funding_asset() -> Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, FEE_FUNDING_AMOUNT)?.into())
}

/// Returns network-account authentication allowlisting the given note script roots (and no
/// transaction scripts), with a fee policy manager pricing each `(root, amount)` in `priced`
/// through a [`BasicConstantFeePolicy`] and every other allowlisted root at an explicit 0 fee.
fn network_auth_with_fees(
    allowed_script_roots: impl IntoIterator<Item = NoteScriptRoot>,
    priced: &[(NoteScriptRoot, u64)],
) -> Result<Auth> {
    let allowed_script_roots: BTreeSet<NoteScriptRoot> = allowed_script_roots.into_iter().collect();
    let fee_policy_manager = fee_policy_manager(allowed_script_roots.iter().copied(), priced)?;
    Ok(Auth::NetworkAccount {
        allowed_script_roots,
        allowed_tx_script_roots: BTreeSet::new(),
        fee_policy_manager,
    })
}

/// Returns network-account authentication allowlisting the given note script roots, pricing
/// them all at an explicit 0 fee.
fn network_auth(allowed_script_roots: impl IntoIterator<Item = NoteScriptRoot>) -> Result<Auth> {
    network_auth_with_fees(allowed_script_roots, &[])
}

/// Returns a fee policy manager charging fees in the native fee asset through a
/// [`BasicConstantFeePolicy`].
///
/// The network account's auth procedure estimates every input note's fee through the active
/// policy during fee collection, and a constant policy aborts for unscheduled roots - so every
/// `zero_fee_root` (and the auto-allowlisted NETWORK_ACCOUNT_CONFIG note) is scheduled at an
/// explicit 0 fee, and each `(root, amount)` in `priced` at its amount.
fn fee_policy_manager(
    zero_fee_roots: impl IntoIterator<Item = NoteScriptRoot>,
    priced: &[(NoteScriptRoot, u64)],
) -> Result<FeePolicyManager> {
    let mut policy = BasicConstantFeePolicy::new()
        .with_fee(NetworkAccountConfigNote::script_root(), AssetAmount::ZERO);
    for root in zero_fee_roots {
        policy = policy.with_fee(root, AssetAmount::ZERO);
    }
    for (root, amount) in priced {
        policy = policy.with_fee(*root, AssetAmount::new(*amount)?);
    }
    Ok(FeePolicyManager::builder()
        .active_fee_policy(policy.into())
        .fee_faucet_id(ACCOUNT_ID_FEE_FAUCET.try_into()?)
        .build())
}

/// Returns a chain builder which charges [`NETWORK_VERIFICATION_BASE_FEE`] when `with_fee` is
/// set and no fees otherwise.
fn chain_builder(with_fee: bool) -> MockChainBuilder {
    if with_fee {
        MockChain::builder().verification_base_fee(NETWORK_VERIFICATION_BASE_FEE)
    } else {
        MockChain::builder()
    }
}

// SCENARIO DISPATCH
// ================================================================================================

/// Builds the transaction context for the given benchmark scenario.
pub async fn build_benchmark_context(bench: ExecutionBenchmark) -> Result<MockTransaction> {
    match bench {
        ExecutionBenchmark::ConsumeSingleP2IDFalcon => tx_consume_single_p2id_note_falcon(),
        ExecutionBenchmark::ConsumeSingleP2IDEcdsa => tx_consume_single_p2id_note_ecdsa(),
        ExecutionBenchmark::ConsumeTwoP2IDFalcon => tx_consume_two_p2id_notes_falcon(),
        ExecutionBenchmark::ConsumeTwoP2IDEcdsa => tx_consume_two_p2id_notes_ecdsa(),
        ExecutionBenchmark::CreateSingleP2IDFalcon => tx_create_single_p2id_note_falcon(),
        ExecutionBenchmark::CreateSingleP2IDEcdsa => tx_create_single_p2id_note_ecdsa(),
        ExecutionBenchmark::ConsumeClaimNoteL1ToMiden => {
            tx_consume_claim_note(ClaimDataSource::L1ToMiden, false).await
        },
        ExecutionBenchmark::ConsumeClaimNoteL2ToMiden => {
            tx_consume_claim_note(ClaimDataSource::L2ToMiden, false).await
        },
        ExecutionBenchmark::ConsumeB2AggNote => tx_consume_b2agg_note(None, false).await,
        ExecutionBenchmark::ConsumeB2AggNotePopulated2p31 => {
            tx_consume_b2agg_note(Some(1 << 31), false).await
        },
        ExecutionBenchmark::ConsumeB2AggNotePopulated2p31m1 => {
            tx_consume_b2agg_note(Some((1u32 << 31) - 1), false).await
        },
        ExecutionBenchmark::ConsumeP2idNetwork => network_wallet::tx_consume_p2id_note_network(),
        ExecutionBenchmark::ConsumeP2idMaxAssetsNetwork => {
            network_wallet::tx_consume_p2id_note_max_assets_network()
        },
        ExecutionBenchmark::ConsumeP2ideClaimNetwork => {
            network_wallet::tx_consume_p2ide_note_network(false)
        },
        ExecutionBenchmark::ConsumeP2ideMaxAssetsNetwork => {
            network_wallet::tx_consume_p2ide_note_max_assets_network()
        },
        ExecutionBenchmark::ConsumeP2ideReclaimNetwork => {
            network_wallet::tx_consume_p2ide_note_network(true)
        },
        ExecutionBenchmark::ConsumeSwapPublicPaybackNetwork => {
            network_wallet::tx_consume_swap_note_network(NoteType::Public)
        },
        ExecutionBenchmark::ConsumeSwapPrivatePaybackNetwork => {
            network_wallet::tx_consume_swap_note_network(NoteType::Private)
        },
        ExecutionBenchmark::ConsumePswapFullFillNetwork => {
            network_wallet::tx_consume_pswap_note_network(true)
        },
        ExecutionBenchmark::ConsumePswapPartialFillNetwork => {
            network_wallet::tx_consume_pswap_note_network(false)
        },
        ExecutionBenchmark::ConsumeMintFungibleNetwork => {
            network_faucet::tx_consume_mint_note_fungible_network()
        },
        ExecutionBenchmark::ConsumeMintNonFungibleNetwork => {
            network_faucet::tx_consume_mint_note_non_fungible_network()
        },
        ExecutionBenchmark::ConsumeBurnNetwork => network_faucet::tx_consume_burn_note_network(),
        ExecutionBenchmark::ConsumeFaucetPolicyActionNetwork => {
            network_action::tx_consume_faucet_policy_action_note_network()
        },
        ExecutionBenchmark::ConsumePauseActionNetwork => {
            network_action::tx_consume_pause_action_note_network()
        },
        ExecutionBenchmark::ConsumeOwnerActionNetwork => {
            network_action::tx_consume_owner_action_note_network()
        },
        ExecutionBenchmark::ConsumeRbacActionNetwork => {
            network_action::tx_consume_rbac_action_note_network()
        },
        ExecutionBenchmark::ConsumeNetworkAccountConfigNetwork => {
            network_action::tx_consume_network_account_config_note_network()
        },
        ExecutionBenchmark::ConsumeFeeSponsorshipWithFeatureNetwork => {
            network_wallet::tx_consume_fee_sponsorship_note_network(false)
        },
        ExecutionBenchmark::ConsumeFeeSponsorshipReclaim => {
            network_wallet::tx_consume_fee_sponsorship_note_network(true)
        },
        ExecutionBenchmark::ConsumeClaimL1WithFee => {
            tx_consume_claim_note(ClaimDataSource::L1ToMiden, true).await
        },
        ExecutionBenchmark::ConsumeClaimL2WithFee => {
            tx_consume_claim_note(ClaimDataSource::L2ToMiden, true).await
        },
        ExecutionBenchmark::ConsumeB2AggWithFee => tx_consume_b2agg_note(None, true).await,
        ExecutionBenchmark::ConsumeB2AggPopulatedWithFee => {
            tx_consume_b2agg_note(Some((1u32 << 31) - 1), true).await
        },
        ExecutionBenchmark::ConsumeConfigAggBridgeWithFee => {
            tx_consume_config_agg_bridge_note().await
        },
        ExecutionBenchmark::ConsumeDeregisterAggFaucetWithFee => {
            tx_consume_deregister_agg_faucet_note().await
        },
        ExecutionBenchmark::ConsumeUpdateGerWithFee => tx_consume_update_ger_note().await,
        ExecutionBenchmark::ConsumeRemoveGerWithFee => tx_consume_remove_ger_note().await,
    }
}

// P2ID NOTE SETUPS
// ================================================================================================

pub fn tx_create_single_p2id_note_falcon() -> Result<MockTransaction> {
    tx_create_single_p2id_note_with_auth(AuthScheme::Falcon512Poseidon2)
}

pub fn tx_create_single_p2id_note_ecdsa() -> Result<MockTransaction> {
    tx_create_single_p2id_note_with_auth(AuthScheme::EcdsaK256Keccak)
}

/// Returns the mock transaction which could be used to run the transaction which creates a
/// single P2ID note.
fn tx_create_single_p2id_note_with_auth(auth_scheme: AuthScheme) -> Result<MockTransaction> {
    let mut builder = MockChain::builder();
    let fungible_asset = FungibleAsset::mock(150);
    let account = builder
        .add_existing_wallet_with_assets(Auth::BasicAuth { auth_scheme }, [fungible_asset])?;

    let output_note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let tx_note_creation_script = format!(
        "
        use miden::core::sys
        use miden::standards::wallets::basic as basic_wallet
        use miden::standards::note::note_creator

        @transaction_script
        pub proc main
            # drop the transaction script args
            dropw
            # => [pad(16)]

            # create an output note with fungible asset
            push.{RECIPIENT}
            push.{note_type}
            push.{tag}
            # => [tag, note_type, RECIPIENT, pad(16)]

            call.note_creator::create_note
            # => [note_idx, pad(21)]

            # move the asset to the note
            push.{ASSET_VALUE}
            push.{ASSET_ID}
            # => [ASSET_ID, ASSET_VALUE, note_idx, pad(21)]

            call.basic_wallet::move_asset_to_note
            # => [pad(30)]

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        RECIPIENT = output_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = output_note.metadata().tag(),
        ASSET_ID = fungible_asset.to_id_word(),
        ASSET_VALUE = fungible_asset.to_value_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_note_creation_script)?;

    // construct the mock transaction
    mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(output_note))
        .tx_script(tx_script)
        .build()
}

pub fn tx_consume_single_p2id_note_falcon() -> Result<MockTransaction> {
    tx_consume_single_p2id_note_with_auth(AuthScheme::Falcon512Poseidon2)
}

pub fn tx_consume_single_p2id_note_ecdsa() -> Result<MockTransaction> {
    tx_consume_single_p2id_note_with_auth(AuthScheme::EcdsaK256Keccak)
}

/// Returns the mock transaction which could be used to run the transaction which consumes a
/// single P2ID note into a new basic wallet.
fn tx_consume_single_p2id_note_with_auth(auth_scheme: AuthScheme) -> Result<MockTransaction> {
    // Create assets
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = MockChain::builder();

    // Create target account
    let target_account = builder.create_new_wallet(Auth::BasicAuth { auth_scheme })?;

    // Create the note
    let note = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            target_account.id(),
            &[fungible_asset],
            NoteType::Public,
        )
        .unwrap();

    let mock_chain = builder.build()?;

    // construct the mock transaction
    mock_chain
        .build_transaction(target_account.clone())
        .authenticated_input_note(note.id())
        .build()
}

pub fn tx_consume_two_p2id_notes_falcon() -> Result<MockTransaction> {
    tx_consume_two_p2id_notes_with_auth(AuthScheme::Falcon512Poseidon2)
}

pub fn tx_consume_two_p2id_notes_ecdsa() -> Result<MockTransaction> {
    tx_consume_two_p2id_notes_with_auth(AuthScheme::EcdsaK256Keccak)
}

/// Returns the mock transaction which could be used to run the transaction which consumes two
/// P2ID notes into an existing basic wallet.
fn tx_consume_two_p2id_notes_with_auth(auth_scheme: AuthScheme) -> Result<MockTransaction> {
    let mut builder = MockChain::builder();

    let account = builder.add_existing_wallet(Auth::BasicAuth { auth_scheme })?;
    let fungible_asset_1: Asset = FungibleAsset::mock(100);
    let fungible_asset_2: Asset = FungibleAsset::mock(23);

    let note_1 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_1],
        NoteType::Private,
    )?;
    let note_2 = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_2],
        NoteType::Private,
    )?;

    let mock_chain = builder.build()?;

    // construct the mock transaction
    mock_chain
        .build_transaction(account.id())
        .authenticated_input_notes([note_1.id(), note_2.id()])
        .build()
}

// BRIDGE FIXTURE
// ================================================================================================

/// Accounts shared by the agglayer benchmark scenarios: the bridge role wallets and the bridge
/// account they control.
struct BridgeFixture {
    faucet_manager: Account,
    ger_injector: Account,
    ger_remover: Account,
    bridge_account: Account,
}

/// Adds the three bridge role wallets and the bridge account to the chain builder.
///
/// When `pre_populate_leaves` is `Some(n)`, the bridge account's LET frontier is pre-populated
/// with dummy values for `n` leaves before the account is added to the chain (see
/// [`populate_let_frontier`]).
///
/// When `with_fee` is set, the bridge account is funded with the native fee asset so its
/// network-account auth can pay the transaction fee.
fn setup_bridge_fixture(
    builder: &mut MockChainBuilder,
    pre_populate_leaves: Option<u32>,
    with_fee: bool,
) -> Result<BridgeFixture> {
    // CREATE FAUCET MANAGER ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    let faucet_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER INJECTOR ACCOUNT (sends the UPDATE_GER note)
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER REMOVER ACCOUNT (sends the REMOVE_GER note)
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let mut bridge_account = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        MIDEN_NETWORK_ID,
    );

    if let Some(num_leaves) = pre_populate_leaves {
        populate_let_frontier(&mut bridge_account, num_leaves);
    }

    if with_fee {
        bridge_account.vault_mut().add_asset(fee_funding_asset()?)?;
    }

    builder.add_account(bridge_account.clone())?;

    Ok(BridgeFixture {
        faucet_manager,
        ger_injector,
        ger_remover,
        bridge_account,
    })
}

// CLAIM NOTE SETUPS
// ================================================================================================

/// Sets up and returns the transaction context for executing a CLAIM note against the bridge
/// account.
///
/// This requires executing prerequisite transactions (CONFIG_AGG_BRIDGE and UPDATE_GER) during
/// setup to prepare the bridge account state. Only the returned CLAIM transaction context is
/// benchmarked — the prerequisite transactions are not included in cycle/time measurements.
///
/// The `data_source` parameter selects between L1-to-Miden and L2-to-Miden test vectors. When
/// `with_fee` is set, the chain charges [`NETWORK_VERIFICATION_BASE_FEE`] and the fee-funded
/// bridge account pays the transaction fee.
pub async fn tx_consume_claim_note(
    data_source: ClaimDataSource,
    with_fee: bool,
) -> Result<MockTransaction> {
    let mut builder = chain_builder(with_fee);

    let BridgeFixture {
        faucet_manager,
        ger_injector,
        bridge_account,
        ..
    } = setup_bridge_fixture(&mut builder, None, with_fee)?;

    // GET CLAIM DATA FROM JSON
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    // CREATE SENDER ACCOUNT (for creating the claim note)
    let sender_account_builder =
        miden_protocol::account::Account::builder(builder.rng_mut().random())
            .with_component(miden_standards::account::wallets::BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        miden_testing::AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let config_metadata_hash = leaf_data.metadata_hash;
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };

    let claim_note = ClaimNote::create(
        claim_inputs,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash: config_metadata_hash,
        },
        faucet_manager.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_injector.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    let config_mock_tx = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(config_note.id())
        .build()?;
    let config_executed = config_mock_tx.execute().await?;

    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    let update_ger_mock_tx = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(update_ger_note.id())
        .build()?;
    let update_ger_executed = update_ger_mock_tx.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: BUILD CLAIM NOTE MOCK TRANSACTION (ready to execute)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_mock_tx = mock_chain
        .build_transaction(bridge_account.id())
        .unauthenticated_input_note(claim_note)
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    Ok(claim_mock_tx)
}

// B2AGG NOTE SETUPS
// ================================================================================================

/// Pre-populates the bridge account's LET (Local Exit Tree) frontier with dummy values,
/// simulating a tree that already has `num_leaves` entries.
///
/// This allows benchmarking bridge-out with different frontier occupancy levels without
/// performing actual sequential insertions. The frontier values are deterministic but not
/// cryptographically valid - cycle counts are independent of stored values.
fn populate_let_frontier(bridge: &mut Account, num_leaves: u32) {
    let zero = Felt::ZERO;

    // Set num_leaves
    bridge
        .storage_mut()
        .set_item(
            AggLayerBridge::let_num_leaves_slot_name(),
            Word::new([Felt::new_unchecked(num_leaves as u64), zero, zero, zero]),
        )
        .expect("should set LET num_leaves");

    // Populate all 32 frontier double-word entries with dummy values.
    // The double_word_array stores each entry under two map keys:
    //   Word 0: key [h, 0, 0, 0]
    //   Word 1: key [h, 1, 0, 0]
    for h in 0u32..32 {
        let key0 = StorageMapKey::from_array([h, 0, 0, 0]);
        let val0 = Word::new([
            Felt::new_unchecked(h as u64 + 1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);
        bridge
            .storage_mut()
            .set_map_item(AggLayerBridge::let_frontier_slot_name(), key0, val0)
            .expect("should set frontier word 0");

        let key1 = StorageMapKey::from_array([h, 1, 0, 0]);
        let val1 = Word::new([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(h as u64 + 8),
        ]);
        bridge
            .storage_mut()
            .set_map_item(AggLayerBridge::let_frontier_slot_name(), key1, val1)
            .expect("should set frontier word 1");
    }

    // Set dummy root values (not used by the append logic, but stored for completeness)
    bridge
        .storage_mut()
        .set_item(
            AggLayerBridge::let_root_lo_slot_name(),
            Word::new([Felt::new_unchecked(0xdead), zero, zero, zero]),
        )
        .expect("should set LET root lo");
    bridge
        .storage_mut()
        .set_item(
            AggLayerBridge::let_root_hi_slot_name(),
            Word::new([Felt::new_unchecked(0xbeef), zero, zero, zero]),
        )
        .expect("should set LET root hi");
}

/// Sets up and returns the mock transaction for executing a B2AGG (bridge-out) note against
/// the bridge account.
///
/// This requires executing a prerequisite CONFIG_AGG_BRIDGE transaction during setup to register
/// the faucet in the bridge. Only the returned B2AGG mock transaction is benchmarked — the
/// prerequisite CONFIG_AGG_BRIDGE transaction is not included in cycle/time measurements.
///
/// When `pre_populate_leaves` is `Some(n)`, the bridge account's LET frontier is pre-populated
/// with dummy values for `n` leaves before building the B2AGG mock transaction. This allows
/// benchmarking with different frontier occupancy levels.
///
/// The setup uses the first entry from the MTF (Merkle Tree Frontier) test vectors for destination
/// data.
pub async fn tx_consume_b2agg_note(
    pre_populate_leaves: Option<u32>,
    with_fee: bool,
) -> Result<MockTransaction> {
    let vectors = &*miden_agglayer::testing::SOLIDITY_MTF_VECTORS;

    let mut builder = chain_builder(with_fee);

    let BridgeFixture { faucet_manager, bridge_account, .. } =
        setup_bridge_fixture(&mut builder, pre_populate_leaves, with_fee)?;

    // CREATE AGGLAYER FAUCET ACCOUNT (with conversion metadata for FPI)
    let origin_token_address = EthAddress::from_hex(&vectors.origin_token_address)
        .expect("valid shared origin token address");
    let origin_network = 64u32;
    let scale = 0u8;
    let bridge_amount: u64 = vectors.amounts[0].parse().expect("valid amount decimal string");

    let faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "AGG",
        8,
        FungibleAsset::MAX_AMOUNT.into(),
        Felt::new_unchecked(bridge_amount),
        bridge_account.id(),
    );
    builder.add_account(faucet.clone())?;

    // CREATE CONFIG_AGG_BRIDGE NOTE (registers faucet + token address in bridge)
    let metadata_hash = MetadataHash::from_token_info("AGG", "AGG", 8);
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash,
        },
        faucet_manager.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE B2AGG NOTE
    let destination_network = vectors.destination_networks[0];
    let destination_address =
        EthAddress::from_hex(&vectors.destination_addresses[0]).expect("valid destination address");
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), bridge_amount)?.into();
    let b2agg_note = B2AggNote::create(
        destination_network,
        destination_address,
        NoteAssets::new(vec![bridge_asset])?,
        bridge_account.id(),
        faucet.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    let config_executed = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(config_note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: BUILD B2AGG NOTE MOCK TRANSACTION (ready to execute)
    let burn_note_script = StandardNote::BURN.script();
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let b2agg_mock_tx = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(b2agg_note.id())
        .add_note_script(burn_note_script)
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    Ok(b2agg_mock_tx)
}

// AGGLAYER MANAGEMENT NOTE SETUPS
// ================================================================================================

/// Creates an agglayer faucet plus the CONFIG_AGG_BRIDGE note registering it in the bridge,
/// using the deterministic L1-to-Miden test-vector metadata.
///
/// Returns the registered faucet account and the registration note (already added to the chain
/// builder as an output note).
fn setup_faucet_registration(
    builder: &mut MockChainBuilder,
    faucet_manager: &Account,
    bridge_account: &Account,
) -> Result<(Account, Note)> {
    let (_proof_data, leaf_data, _ger, _cgi_chain_hash) = ClaimDataSource::L1ToMiden.get_data();

    let agglayer_faucet = create_existing_agglayer_faucet(
        builder.rng_mut().draw_word(),
        "AGG",
        8,
        FungibleAsset::MAX_AMOUNT.into(),
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address: leaf_data.origin_token_address,
            scale: 10,
            origin_network: leaf_data.origin_network,
            is_native: false,
            metadata_hash: leaf_data.metadata_hash,
        },
        faucet_manager.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    Ok((agglayer_faucet, config_note))
}

/// Returns the transaction context for the fee-funded bridge account consuming a
/// CONFIG_AGG_BRIDGE note.
pub async fn tx_consume_config_agg_bridge_note() -> Result<MockTransaction> {
    let mut builder = chain_builder(true);

    let BridgeFixture { faucet_manager, bridge_account, .. } =
        setup_bridge_fixture(&mut builder, None, true)?;

    let (_agglayer_faucet, config_note) =
        setup_faucet_registration(&mut builder, &faucet_manager, &bridge_account)?;

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(config_note.id())
        .build()
}

/// Returns the transaction context for the fee-funded bridge account consuming a
/// DEREGISTER_AGG_FAUCET note, after a prerequisite CONFIG_AGG_BRIDGE transaction registered the
/// faucet.
pub async fn tx_consume_deregister_agg_faucet_note() -> Result<MockTransaction> {
    let mut builder = chain_builder(true);

    let BridgeFixture { faucet_manager, bridge_account, .. } =
        setup_bridge_fixture(&mut builder, None, true)?;

    let (agglayer_faucet, config_note) =
        setup_faucet_registration(&mut builder, &faucet_manager, &bridge_account)?;

    let deregister_note = DeregisterAggFaucetNote::create(
        agglayer_faucet.id(),
        faucet_manager.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(deregister_note.clone()));

    let mut mock_chain = builder.build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER THE FAUCET IN THE BRIDGE
    let config_executed = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(config_note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: BUILD DEREGISTER_AGG_FAUCET NOTE TRANSACTION CONTEXT (ready to execute)
    mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(deregister_note.id())
        .build()
}

/// Returns the transaction context for the fee-funded bridge account consuming an UPDATE_GER
/// note.
pub async fn tx_consume_update_ger_note() -> Result<MockTransaction> {
    let mut builder = chain_builder(true);

    let BridgeFixture { ger_injector, bridge_account, .. } =
        setup_bridge_fixture(&mut builder, None, true)?;

    let (_proof_data, _leaf_data, ger, _cgi_chain_hash) = ClaimDataSource::L1ToMiden.get_data();
    let update_ger_note =
        UpdateGerNote::create(ger, ger_injector.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(update_ger_note.id())
        .build()
}

/// Returns the transaction context for the fee-funded bridge account consuming a REMOVE_GER
/// note, after a prerequisite UPDATE_GER transaction stored the GER.
pub async fn tx_consume_remove_ger_note() -> Result<MockTransaction> {
    let mut builder = chain_builder(true);

    let BridgeFixture {
        ger_injector,
        ger_remover,
        bridge_account,
        ..
    } = setup_bridge_fixture(&mut builder, None, true)?;

    let (_proof_data, _leaf_data, ger, _cgi_chain_hash) = ClaimDataSource::L1ToMiden.get_data();
    let update_ger_note =
        UpdateGerNote::create(ger, ger_injector.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let remove_ger_note =
        RemoveGerNote::create(ger, ger_remover.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(remove_ger_note.clone()));

    let mut mock_chain = builder.build()?;

    // TX0: EXECUTE UPDATE_GER NOTE TO STORE THE GER IN THE BRIDGE ACCOUNT
    let update_ger_executed = mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(update_ger_note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: BUILD REMOVE_GER NOTE TRANSACTION CONTEXT (ready to execute)
    mock_chain
        .build_transaction(bridge_account.id())
        .authenticated_input_note(remove_ger_note.id())
        .build()
}

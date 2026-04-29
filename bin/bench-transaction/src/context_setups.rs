use anyhow::Result;
pub use miden_agglayer::testing::ClaimDataSource;
use miden_agglayer::{
    B2AggNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddress,
    MetadataHash,
    UpdateGerNote,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{NoteAssets, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::StandardNote;
use miden_testing::{Auth, MockChain, TransactionContext};
use rand::Rng;

// P2ID NOTE SETUPS
// ================================================================================================

/// Returns the transaction context which could be used to run the transaction which creates a
/// single P2ID note.
pub fn tx_create_single_p2id_note() -> Result<TransactionContext> {
    let mut builder = MockChain::builder();
    let fungible_asset = FungibleAsset::mock(150);
    let account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [fungible_asset],
    )?;

    let output_note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let tx_note_creation_script = format!(
        "
        use miden::protocol::output_note
        use miden::core::sys

        begin
            # create an output note with fungible asset
            push.{RECIPIENT}
            push.{note_type}
            push.{tag}
            exec.output_note::create
            # => [note_idx]

            # move the asset to the note
            dup
            push.{ASSET_VALUE}
            push.{ASSET_KEY}
            call.::miden::standards::wallets::basic::move_asset_to_note
            # => [note_idx]

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        RECIPIENT = output_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = output_note.metadata().tag(),
        ASSET_KEY = fungible_asset.to_key_word(),
        ASSET_VALUE = fungible_asset.to_value_word(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_note_creation_script)?;

    // construct the transaction context
    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(output_note)])
        .tx_script(tx_script)
        .disable_debug_mode()
        .build()
}

/// Returns the transaction context which could be used to run the transaction which consumes a
/// single P2ID note into a new basic wallet.
pub fn tx_consume_single_p2id_note() -> Result<TransactionContext> {
    // Create assets
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = MockChain::builder();

    // Create target account
    let target_account = builder.create_new_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

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

    // construct the transaction context
    mock_chain
        .build_tx_context(target_account.clone(), &[note.id()], &[])?
        .disable_debug_mode()
        .build()
}

/// Returns the transaction context which could be used to run the transaction which consumes two
/// P2ID notes into an existing basic wallet.
pub fn tx_consume_two_p2id_notes() -> Result<TransactionContext> {
    let mut builder = MockChain::builder();

    let account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
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

    // construct the transaction context
    mock_chain
        .build_tx_context(account.id(), &[note_1.id(), note_2.id()], &[])?
        .disable_debug_mode()
        .build()
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
/// The `data_source` parameter selects between L1-to-Miden and L2-to-Miden test vectors.
pub async fn tx_consume_claim_note(data_source: ClaimDataSource) -> Result<TransactionContext> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (sends the UPDATE_GER note)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply = Felt::new(FungibleAsset::MAX_AMOUNT);
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
        &origin_token_address,
        origin_network,
        scale,
        leaf_data.metadata_hash,
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

    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };

    let claim_note = create_claim_note(
        claim_inputs,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        agglayer_faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN
    let mut mock_chain = builder.build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: BUILD CLAIM NOTE TRANSACTION CONTEXT (ready to execute)
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .disable_debug_mode()
        .build()?;

    Ok(claim_tx_context)
}

// B2AGG NOTE SETUPS
// ================================================================================================

/// Sets up and returns the transaction context for executing a B2AGG (bridge-out) note against
/// the bridge account.
///
/// This requires executing a prerequisite CONFIG_AGG_BRIDGE transaction during setup to register
/// the faucet in the bridge. Only the returned B2AGG transaction context is benchmarked — the
/// prerequisite CONFIG_AGG_BRIDGE transaction is not included in cycle/time measurements.
///
/// The setup uses the first entry from the MTF (Merkle Tree Frontier) test vectors for destination
/// data.
pub async fn tx_consume_b2agg_note() -> Result<TransactionContext> {
    let vectors = &*miden_agglayer::testing::SOLIDITY_MTF_VECTORS;

    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (not used in bridge-out, but required for bridge creation)
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

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
        Felt::new(FungibleAsset::MAX_AMOUNT),
        Felt::new(bridge_amount),
        bridge_account.id(),
        &origin_token_address,
        origin_network,
        scale,
        MetadataHash::from_token_info("AGG", "AGG", 8),
    );
    builder.add_account(faucet.clone())?;

    // CREATE CONFIG_AGG_BRIDGE NOTE (registers faucet + token address in bridge)
    let config_note = ConfigAggBridgeNote::create(
        faucet.id(),
        &origin_token_address,
        bridge_admin.id(),
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
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: BUILD B2AGG NOTE TRANSACTION CONTEXT (ready to execute)
    let burn_note_script = StandardNote::BURN.script();
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let b2agg_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[b2agg_note.id()], &[])?
        .add_note_script(burn_note_script)
        .foreign_accounts(vec![foreign_account_inputs])
        .disable_debug_mode()
        .build()?;

    Ok(b2agg_tx_context)
}

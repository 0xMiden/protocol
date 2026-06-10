extern crate alloc;

use alloc::slice;
use alloc::string::String;

use anyhow::Context;
use miden_agglayer::errors::{
    ERR_CLAIM_ALREADY_SPENT,
    ERR_CLAIM_LEAF_DESTINATION_NETWORK_MISMATCH,
    ERR_TOKEN_NOT_REGISTERED,
};
use miden_agglayer::{
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    ConversionMetadata,
    EthAddress,
    EthEmbeddedAccountId,
    ExitRoot,
    LeafValue,
    SmtNode,
    UpdateGerNote,
    agglayer_library,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountIdVersion, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, AssetCallbackFlag, FungibleAsset};
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{NoteAssets, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::policies::MintPolicyConfig;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_FUNGIBLE_MINT_NOTE_ASSET_NOT_FROM_THIS_FAUCET;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_testing::utils::create_p2id_note_exact;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    TransactionContextBuilder,
    assert_transaction_executor_error,
};
use miden_tx::utils::hex_to_bytes;
use rand::Rng;

use super::test_utils::{
    ClaimDataSource,
    MIDEN_NETWORK_ID,
    MerkleProofVerificationFile,
    SOLIDITY_MERKLE_PROOF_VECTORS,
};

// CONSTANTS
// ================================================================================================

/// Maximum allowed cycle count for CLAIM note processing.
/// Current observed values: ~25,662 (real/simulated), ~40,485 (rollup).
const MAX_CLAIM_NOTE_PROCESSING_CYCLES: usize = 64_000;

// HELPER FUNCTIONS
// ================================================================================================

fn merkle_proof_verification_code(
    index: usize,
    merkle_paths: &MerkleProofVerificationFile,
) -> String {
    let mut store_path_source = String::new();
    for height in 0..32 {
        let path_node = merkle_paths.merkle_paths[index * 32 + height].as_str();
        let smt_node = SmtNode::from(hex_to_bytes(path_node).unwrap());
        let [node_lo, node_hi] = smt_node.to_words();
        store_path_source.push_str(&format!(
            "
            \tpush.{node_lo} mem_storew_le.{} dropw
            \tpush.{node_hi} mem_storew_le.{} dropw
    ",
            height * 8,
            height * 8 + 4
        ));
    }

    let root = ExitRoot::from(hex_to_bytes(&merkle_paths.roots[index]).unwrap());
    let [root_lo, root_hi] = root.to_words();

    let leaf = LeafValue::from(hex_to_bytes(&merkle_paths.leaves[index]).unwrap());
    let [leaf_lo, leaf_hi] = leaf.to_words();

    format!(
        r#"
        use agglayer::bridge::bridge_in

        begin
            {store_path_source}

            push.{root_lo} mem_storew_le.256 dropw
            push.{root_hi} mem_storew_le.260 dropw

            push.256
            push.{index}
            push.0
            push.{leaf_hi}
            push.{leaf_lo}

            exec.bridge_in::verify_merkle_proof
            assert.err="verification failed"
        end
    "#
    )
}

/// Tests the bridge-in flow with the new 2-transaction architecture:
///
/// TX0: CONFIG_AGG_BRIDGE → bridge (registers faucet + token address in registries)
/// TX1: UPDATE_GER → bridge (stores GER)
/// TX2: CLAIM → bridge (validates proof, creates MINT note)
/// TX3: MINT → aggfaucet (mints asset, creates P2ID note)
/// TX4: P2ID → destination (simulated case only)
///
/// Parameterized over two claim data sources:
/// - [`ClaimDataSource::L1ToMiden`]: uses locally generated [`ProofData`] and [`LeafData`] from
///   `claim_asset_vectors_l1_tx.json`, produced by simulating a `bridgeAsset()` call.
/// - [`ClaimDataSource::L2ToMiden`]: uses rollup deposit data from
///   `claim_asset_vectors_l2_tx.json`, produced by simulating a rollup deposit.
#[rstest::rstest]
#[case::l1_to_miden(ClaimDataSource::L1ToMiden)]
#[case::l2_to_miden(ClaimDataSource::L2ToMiden)]
#[tokio::test]
async fn test_bridge_in_claim_to_p2id(#[case] data_source: ClaimDataSource) -> anyhow::Result<()> {
    use miden_agglayer::AggLayerBridge;

    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    // --------------------------------------------------------------------------------------------
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (sends the UPDATE_GER note)
    // --------------------------------------------------------------------------------------------
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON (source depends on the test case)
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger, cgi_chain_hash) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT (with agglayer_faucet component)
    // Use the origin token address and network from the claim data.
    // --------------------------------------------------------------------------------------------
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

    // Get the destination account ID from the leaf data.
    // This requires the destination_address to be in the embedded Miden AccountId format
    // (first 4 bytes must be zero).
    let destination_account_id = EthEmbeddedAccountId::try_from(leaf_data.destination_address)
        .expect("destination address is not an embedded Miden AccountId")
        .into_account_id();

    let destination_account =
        Account::mock(u128::from(destination_account_id), IncrNonceAuthComponent);
    builder.add_account(destination_account.clone())?;

    // CREATE SENDER ACCOUNT (for creating the claim note)
    // --------------------------------------------------------------------------------------------
    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE (now targets the bridge, not the faucet)
    // --------------------------------------------------------------------------------------------

    // The P2ID serial number is derived from the PROOF_DATA_KEY (RPO hash of proof data)
    let serial_num = proof_data.to_commitment();

    // Calculate the scaled-down Miden amount using the faucet's scale factor
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let metadata_hash = leaf_data.metadata_hash;
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };

    let claim_note = ClaimNote::create(
        claim_inputs,
        bridge_account.id(), // Target the bridge, not the faucet
        sender_account.id(),
        builder.rng_mut(),
    )?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE (registers faucet + token address in bridge)
    // --------------------------------------------------------------------------------------------
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    // --------------------------------------------------------------------------------------------
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: EXECUTE CLAIM NOTE AGAINST BRIDGE (validates proof, creates MINT note)
    // --------------------------------------------------------------------------------------------
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    let claim_executed = claim_tx_context
        .execute()
        .await
        .context("TX2: CLAIM note execution against bridge failed")?;

    // VERIFY CGI CHAIN HASH WAS SUCCESSFULLY UPDATED
    // --------------------------------------------------------------------------------------------

    let mut updated_bridge_account = bridge_account.clone();
    updated_bridge_account.apply_delta(claim_executed.account_delta())?;

    let actual_cgi_chain_hash = AggLayerBridge::cgi_chain_hash(&updated_bridge_account)?;

    assert_eq!(cgi_chain_hash, actual_cgi_chain_hash);

    let claim_cycles = claim_executed.measurements().notes_processing;
    assert!(
        claim_cycles <= MAX_CLAIM_NOTE_PROCESSING_CYCLES,
        "CLAIM note processing exceeded cycle budget: {claim_cycles} > {MAX_CLAIM_NOTE_PROCESSING_CYCLES}"
    );

    // VERIFY MINT NOTE WAS CREATED BY THE BRIDGE
    // --------------------------------------------------------------------------------------------
    assert_eq!(claim_executed.output_notes().num_notes(), 1);
    let mint_output_note = claim_executed.output_notes().get_note(0);

    // Verify the MINT note was sent by the bridge
    assert_eq!(mint_output_note.metadata().sender(), bridge_account.id());
    assert_eq!(mint_output_note.metadata().note_type(), NoteType::Public);

    // Commit the CLAIM transaction and prove the block so the MINT note can be consumed
    mock_chain.add_pending_executed_transaction(&claim_executed)?;
    mock_chain.prove_next_block()?;

    // TX3: EXECUTE MINT NOTE AGAINST AGGFAUCET (mints asset, creates P2ID note)
    // --------------------------------------------------------------------------------------------
    let mint_tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[mint_output_note.id()], &[])?
        .add_note_script(P2idNote::script())
        .build()?;

    let mint_executed = mint_tx_context
        .execute()
        .await
        .context("TX3: MINT note execution against faucet failed")?;

    // VERIFY P2ID NOTE WAS CREATED BY THE FAUCET
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(mint_executed.output_notes().num_notes(), 1);
    let output_note = mint_executed.output_notes().get_note(0);

    // Verify note metadata properties
    assert_eq!(output_note.metadata().sender(), agglayer_faucet.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // Extract and verify P2ID asset contents
    let mut assets_iter = output_note.assets().iter_fungible();
    let p2id_asset = assets_iter.next().unwrap();

    // Verify minted amount matches expected scaled value
    assert_eq!(
        Felt::from(p2id_asset.amount()),
        miden_claim_amount,
        "asset amount does not match"
    );

    // Verify faucet ID matches agglayer_faucet (P2ID token issuer)
    assert_eq!(
        p2id_asset.faucet_id(),
        agglayer_faucet.id(),
        "P2ID asset faucet ID doesn't match agglayer_faucet: got {:?}, expected {:?}",
        p2id_asset.faucet_id(),
        agglayer_faucet.id()
    );

    // Verify full note ID construction
    let expected_asset: Asset =
        FungibleAsset::new(agglayer_faucet.id(), miden_claim_amount.as_canonical_u64())
            .unwrap()
            .with_callbacks(AssetCallbackFlag::Enabled)
            .into();
    let expected_output_p2id_note = create_p2id_note_exact(
        agglayer_faucet.id(),
        destination_account_id,
        vec![expected_asset],
        NoteType::Public,
        serial_num,
    )
    .unwrap();

    assert_eq!(RawOutputNote::Full(expected_output_p2id_note.clone()), *output_note);

    // TX4: CONSUME THE P2ID NOTE WITH THE DESTINATION ACCOUNT
    // --------------------------------------------------------------------------------------------
    // Add the faucet transaction to the chain and prove the next block so the P2ID note is
    // committed and can be consumed.
    mock_chain.add_pending_executed_transaction(&mint_executed)?;
    mock_chain.prove_next_block()?;

    // Execute the consume transaction for the destination account. Pass the account
    // directly since the JSON-encoded destination decodes to a private account ID. The
    // issuing AggLayer faucet must be supplied as a foreign account so the kernel can
    // dispatch the receive callback when the asset is added to the destination vault.
    let agglayer_faucet_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let consume_tx_context = mock_chain
        .build_tx_context(
            destination_account.clone(),
            &[],
            slice::from_ref(&expected_output_p2id_note),
        )?
        .foreign_accounts(vec![agglayer_faucet_inputs])
        .build()?;
    let consume_executed_transaction = consume_tx_context.execute().await?;

    // Verify the destination account received the minted asset
    let mut destination_account = destination_account;
    destination_account.apply_delta(consume_executed_transaction.account_delta())?;

    let balance = destination_account.vault().get_balance(expected_asset.vault_key())?;
    assert_eq!(
        balance.as_u64(),
        miden_claim_amount.as_canonical_u64(),
        "destination account balance does not match"
    );
    Ok(())
}

/// Asserts that a MINT note produced by `claim` for faucet A cannot be consumed by a
/// different same-bridge faucet B.
///
/// Both faucets are registered in the bridge, so the only thing preventing faucet B from
/// consuming faucet A's MINT note is the faucet bind itself. The MINT note embeds the full
/// `ASSET` (`ASSET_KEY` + `ASSET_VALUE`) in its storage; `fungible::mint_and_send` derives the
/// asset for the consuming faucet and rejects it with
/// `ERR_FUNGIBLE_MINT_NOTE_ASSET_NOT_FROM_THIS_FAUCET` when its key does not match the stored
/// `ASSET_KEY`. Before this fix the MINT note carried only the amount, so faucet B would mint its
/// own token and the cross-faucet consumption would succeed.
#[tokio::test]
async fn test_mint_cannot_be_consumed_by_unrelated_faucet() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    let token_symbol_a = "AGGA";
    let token_symbol_b = "AGGB";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let scale = 10u8;

    // faucet_A is the bridge's registered faucet for the claim's origin token address.
    let faucet_a_seed = builder.rng_mut().draw_word();
    let faucet_a = create_existing_agglayer_faucet(
        faucet_a_seed,
        token_symbol_a,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(faucet_a.clone())?;

    // faucet_B is owned by the same bridge but tied to a different origin token. It is the
    // attacker's target: the claimant tries to direct faucet_A's MINT note here.
    let faucet_b_seed = builder.rng_mut().draw_word();
    // Flip one byte of the address so the new EthAddress is distinct from faucet_A's.
    let mut other_bytes = leaf_data.origin_token_address.into_bytes();
    other_bytes[0] ^= 0x01;
    let other_token_address = EthAddress::new(other_bytes);
    let faucet_b = create_existing_agglayer_faucet(
        faucet_b_seed,
        token_symbol_b,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(faucet_b.clone())?;

    assert_ne!(faucet_a.id(), faucet_b.id(), "test setup: faucet IDs must differ");

    // The destination is also baked into the fixture; create it so the bridge claim succeeds.
    let destination_account_id = EthEmbeddedAccountId::try_from(leaf_data.destination_address)
        .expect("destination address is not an embedded Miden AccountId")
        .into_account_id();
    let dest = Account::mock(u128::from(destination_account_id), IncrNonceAuthComponent);
    builder.add_account(dest)?;

    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data: leaf_data.clone(),
        miden_claim_amount,
    };

    let claim_note = ClaimNote::create(
        claim_inputs,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // Register faucet_A in the bridge for the claim's origin token address.
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_a.id(),
            origin_token_address: leaf_data.origin_token_address,
            scale,
            origin_network: leaf_data.origin_network,
            is_native: false,
            metadata_hash: leaf_data.metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // Register faucet_B too: it is a fully legitimate same-bridge faucet, so the attack below
    // fails only because of the faucet bind, not because faucet_B is unknown to the bridge.
    let config_note_b = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: faucet_b.id(),
            origin_token_address: other_token_address,
            scale,
            origin_network: leaf_data.origin_network,
            is_native: false,
            metadata_hash: leaf_data.metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note_b.clone()));

    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.clone().build()?;

    // TX0: register faucet_A and faucet_B.
    let config_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id(), config_note_b.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: store GER.
    let update_ger_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: claim → produces MINT note bound to faucet_A's asset.
    let faucet_a_foreign_inputs = mock_chain.get_foreign_account_inputs(faucet_a.id())?;
    let claim_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_a_foreign_inputs])
        .build()?
        .execute()
        .await
        .context("CLAIM execution should succeed")?;

    assert_eq!(claim_executed.output_notes().num_notes(), 1);
    let mint_output_note = claim_executed.output_notes().get_note(0);

    mock_chain.add_pending_executed_transaction(&claim_executed)?;
    mock_chain.prove_next_block()?;

    // ATTACK: try to consume the MINT note against faucet_B (wrong faucet).
    //
    // The MINT note's stored `ASSET_KEY` carries faucet_A's ID. faucet_B's `mint_and_send`
    // derives the asset for faucet_B, finds its key differs from the stored one, and rejects
    // the consumption.
    let attack_tx_context = mock_chain
        .build_tx_context(faucet_b.id(), &[mint_output_note.id()], &[])?
        .add_note_script(P2idNote::script())
        .build()?;

    let attack_result = attack_tx_context.execute().await;
    assert_transaction_executor_error!(
        attack_result,
        ERR_FUNGIBLE_MINT_NOTE_ASSET_NOT_FROM_THIS_FAUCET
    );

    Ok(())
}

/// CLAIM must reject a leaf whose `destination_network` does not match the bridge's configured
/// network ID, even when the rest of the proof data is unchanged.
#[tokio::test]
async fn test_claim_rejects_wrong_destination_network() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (sends CONFIG_AGG_BRIDGE notes)
    // --------------------------------------------------------------------------------------------
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT (sends the UPDATE_GER note)
    // --------------------------------------------------------------------------------------------
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON
    // --------------------------------------------------------------------------------------------
    let (proof_data, mut leaf_data, ger, _cgi) = data_source.get_data();

    // Override destination_network so it no longer matches the bridge's MIDEN_NETWORK_ID.
    // Proof data is unchanged; the bridge should fail before Merkle verification.
    // --------------------------------------------------------------------------------------------
    leaf_data.destination_network = MIDEN_NETWORK_ID.saturating_add(1);

    // CREATE AGGLAYER FAUCET ACCOUNT (with agglayer_faucet component)
    // Use the origin token address and network from the claim data.
    // --------------------------------------------------------------------------------------------
    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let agglayer_faucet_seed = builder.rng_mut().draw_word();
    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let scale = 10u8;

    let metadata_hash = leaf_data.metadata_hash;
    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Calculate the scaled-down Miden amount
    // --------------------------------------------------------------------------------------------
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    // CREATE CLAIM NOTE (targets the bridge)
    // --------------------------------------------------------------------------------------------
    let claim_note = ClaimNote::create(
        ClaimNoteStorage {
            proof_data,
            leaf_data,
            miden_claim_amount,
        },
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE (registers faucet + token address in bridge)
    // --------------------------------------------------------------------------------------------
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;

    // TX0: EXECUTE CONFIG_AGG_BRIDGE NOTE TO REGISTER FAUCET IN BRIDGE
    // --------------------------------------------------------------------------------------------
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    mock_chain.add_pending_executed_transaction(&config_tx_context.execute().await?)?;
    mock_chain.prove_next_block()?;

    // TX1: EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    mock_chain.add_pending_executed_transaction(&update_ger_tx_context.execute().await?)?;
    mock_chain.prove_next_block()?;

    // TX2: EXECUTE CLAIM NOTE AGAINST BRIDGE (must fail: wrong destination_network)
    // --------------------------------------------------------------------------------------------
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;
    let result = claim_tx_context.execute().await;
    assert_transaction_executor_error!(result, ERR_CLAIM_LEAF_DESTINATION_NETWORK_MISMATCH);

    Ok(())
}

/// Tests that consuming a CLAIM note with the same PROOF_DATA_KEY twice fails.
///
/// This test verifies the nullifier tracking mechanism:
/// 1. Sets up the bridge (CONFIG + UPDATE_GER)
/// 2. Executes the first CLAIM note successfully
/// 3. Creates a second CLAIM note with the same proof data
/// 4. Attempts to execute the second CLAIM note and asserts it fails with "claim note has already
///    been spent"
#[tokio::test]
async fn test_duplicate_claim_note_rejected() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE GER MANAGER ACCOUNT
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE BRIDGE ACCOUNT
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

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

    // Calculate the scaled-down Miden amount
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    // CREATE FIRST CLAIM NOTE
    let claim_inputs_1 = ClaimNoteStorage {
        proof_data: proof_data.clone(),
        leaf_data: leaf_data.clone(),
        miden_claim_amount,
    };

    let claim_note_1 = ClaimNote::create(
        claim_inputs_1,
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note_1.clone()));

    // CREATE SECOND CLAIM NOTE (same proof data = same PROOF_DATA_KEY)
    let claim_inputs_2 = ClaimNoteStorage {
        proof_data: proof_data.clone(),
        leaf_data: leaf_data.clone(),
        miden_claim_amount,
    };

    let claim_note_2 = ClaimNote::create(
        claim_inputs_2,
        bridge_account.id(),
        bridge_admin.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note_2.clone()));

    // CREATE CONFIG_AGG_BRIDGE NOTE
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: false,
            metadata_hash: leaf_data.metadata_hash,
        },
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
    let mut mock_chain = builder.clone().build()?;

    // TX0: CONFIG_AGG_BRIDGE
    let config_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: UPDATE_GER
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: FIRST CLAIM (should succeed)
    let faucet_foreign_inputs_1 = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context_1 = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note_1])?
        .foreign_accounts(vec![faucet_foreign_inputs_1])
        .build()?;
    let claim_executed_1 = claim_tx_context_1.execute().await?;
    assert_eq!(claim_executed_1.output_notes().num_notes(), 1);

    mock_chain.add_pending_executed_transaction(&claim_executed_1)?;
    mock_chain.prove_next_block()?;

    // TX3: SECOND CLAIM WITH SAME PROOF_DATA_KEY (should fail)
    let faucet_foreign_inputs_2 = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx_context_2 = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note_2])?
        .foreign_accounts(vec![faucet_foreign_inputs_2])
        .build()?;
    let result = claim_tx_context_2.execute().await;

    assert!(result.is_err(), "Second claim with same PROOF_DATA_KEY should fail");
    let error_msg = result.unwrap_err().to_string();
    let expected_err_code = ERR_CLAIM_ALREADY_SPENT.code().to_string();
    assert!(
        error_msg.contains(&expected_err_code),
        "expected error code {expected_err_code} for 'claim note has already been spent', got: {error_msg}"
    );

    Ok(())
}

/// Tests the bridge-in unlock path for Miden-native faucets.
///
/// When a faucet is registered with `is_native = true`, a valid CLAIM note does NOT go through
/// the MINT→faucet→P2ID flow. Instead, the bridge removes the asset from its own vault and
/// emits a P2ID note directly to the recipient.
///
/// Flow:
/// 1. Register a native (non-bridge-owned) faucet with `is_native = true` using the
///    origin_token_address and metadata_hash from a simulated L1→Miden claim vector.
/// 2. Seed the bridge vault by running one lock transaction (bridge-out of a B2AGG note carrying
///    `miden_claim_amount` of the native asset).
/// 3. Store a GER that covers the claim's Merkle proof.
/// 4. Execute the CLAIM against the bridge — the `claim` proc dispatches into `unlock_and_send`
///    because the faucet is registered with `is_native = true`.
/// 5. Assert that exactly one output P2ID note is produced, its asset matches what was locked, the
///    bridge vault is drained to 0, and the destination can consume the P2ID.
#[tokio::test]
async fn bridge_in_unlock_native_token() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    // Bridge admin / GER manager / bridge account.
    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let mut bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    // Claim data: leaf data's origin_token_address + metadata_hash must match the registration
    // below so the bridge's token-registry lookup resolves to the native faucet.
    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();
    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let metadata_hash = leaf_data.metadata_hash;
    let scale = 10u8;

    // The amount the claim will attempt to unlock: scaled from the leaf's U256 amount.
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");
    let miden_claim_amount_u64 = miden_claim_amount.as_canonical_u64();

    // Native faucet: use the network-faucet pattern (bridge is not the owner).
    let faucet_owner_account_id =
        AccountId::dummy([3; 15], AccountIdVersion::Version1, AccountType::Private);
    let native_faucet = builder.add_existing_network_faucet(
        "NATIVE",
        miden_claim_amount_u64.saturating_mul(4),
        faucet_owner_account_id,
        // Seed enough native supply for the lock step's sender to bundle into the B2AGG note.
        Some(miden_claim_amount_u64.saturating_mul(2)),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;

    // Destination of the claim (derived from leaf data's destination_address). The mock account
    // is built directly from the destination ID encoded in the JSON test vector, since the claim
    // note targets this account ID.
    let destination_account_id = EthEmbeddedAccountId::try_from(leaf_data.destination_address)
        .expect("destination address is not an embedded Miden AccountId")
        .into_account_id();
    let destination_account =
        Account::mock(u128::from(destination_account_id), IncrNonceAuthComponent);
    builder.add_account(destination_account.clone())?;

    // Sender of the CLAIM note (any wallet — just a note creator).
    let claim_sender = {
        let account_builder =
            Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?
    };

    // Sender of the B2AGG note used to seed the bridge vault with the native asset.
    let lock_sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Register the native faucet with is_native = true.
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: native_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: true,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // B2AGG note that will seed the bridge's vault with `miden_claim_amount_u64` of native asset.
    let bridge_asset: Asset =
        FungibleAsset::new(native_faucet.id(), miden_claim_amount_u64).unwrap().into();
    let b2agg_destination_address =
        EthAddress::from_hex("0x1234567890abcdef1122334455667788990011aa")
            .expect("valid destination address");
    let b2agg_note = B2AggNote::create(
        1u32,
        b2agg_destination_address,
        NoteAssets::new(vec![bridge_asset])?,
        bridge_account.id(),
        lock_sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));

    // CLAIM note targeting the bridge.
    let serial_num = proof_data.to_commitment();
    let claim_inputs = ClaimNoteStorage {
        proof_data,
        leaf_data,
        miden_claim_amount,
    };
    let claim_note =
        ClaimNote::create(claim_inputs, bridge_account.id(), claim_sender.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(claim_note.clone()));

    // GER for the claim's Merkle proof.
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.clone().build()?;

    // TX0: CONFIG — registers native faucet with is_native = true.
    let config_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(config_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: LOCK — bridge consumes the B2AGG note, asset goes into bridge vault.
    let lock_executed = mock_chain
        .build_tx_context(bridge_account.clone(), &[b2agg_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    assert_eq!(
        lock_executed.output_notes().num_notes(),
        0,
        "Lock transaction should not emit any output note"
    );
    bridge_account.apply_delta(lock_executed.account_delta())?;
    assert_eq!(
        bridge_account.vault().get_balance(bridge_asset.vault_key())?,
        AssetAmount::new(miden_claim_amount_u64)?,
        "Bridge vault should hold the locked native asset before the claim"
    );
    mock_chain.add_pending_executed_transaction(&lock_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: UPDATE_GER.
    let update_ger_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(update_ger_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX3: CLAIM — bridge validates the proof, hits the is_native branch, unlocks and emits P2ID.
    let claim_executed = mock_chain
        .build_tx_context(bridge_account.clone(), &[], &[claim_note])?
        .build()?
        .execute()
        .await
        .context("CLAIM execution against bridge failed")?;

    // Exactly one output note — a PUBLIC P2ID carrying the native asset, sent by the bridge.
    assert_eq!(
        claim_executed.output_notes().num_notes(),
        1,
        "Unlock path should emit exactly one P2ID output note"
    );
    let output_note = match claim_executed.output_notes().get_note(0) {
        RawOutputNote::Full(note) => note.clone(),
        other => panic!("expected Full output note, got {other:?}"),
    };

    let expected_asset: Asset =
        FungibleAsset::new(native_faucet.id(), miden_claim_amount_u64).unwrap().into();

    assert_eq!(output_note.metadata().sender(), bridge_account.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);
    assert_eq!(
        output_note.recipient().script().root(),
        P2idNote::script().root(),
        "Output note should use the P2ID script"
    );
    assert_eq!(output_note.recipient().serial_num(), serial_num);

    let mut assets_iter = output_note.assets().iter_fungible();
    let unlocked_asset = assets_iter
        .next()
        .expect("P2ID output note should carry exactly one fungible asset");
    assert!(assets_iter.next().is_none(), "P2ID output note should carry only one asset");
    assert_eq!(Felt::from(unlocked_asset.amount()), miden_claim_amount);
    assert_eq!(unlocked_asset.faucet_id(), native_faucet.id());

    // Cross-check storage directly: it should encode the destination account ID the same way
    // `P2idNoteStorage::from` does ([suffix, prefix]).
    let expected_p2id_note = create_p2id_note_exact(
        bridge_account.id(),
        destination_account_id,
        vec![expected_asset],
        NoteType::Public,
        serial_num,
    )
    .unwrap();
    let actual_storage = output_note.recipient().storage();
    let expected_storage = expected_p2id_note.recipient().storage();
    assert_eq!(
        actual_storage, expected_storage,
        "P2ID note storage items (encoding the target account ID) should match \
         the standard P2idNoteStorage encoding for destination_account_id={destination_account_id:?}"
    );
    assert_eq!(
        output_note.recipient().digest(),
        expected_p2id_note.recipient().digest(),
        "Recipient digest should match an independently constructed P2ID to the destination"
    );

    // Bridge vault is drained after the unlock.
    bridge_account.apply_delta(claim_executed.account_delta())?;
    assert_eq!(
        bridge_account.vault().get_balance(expected_asset.vault_key())?,
        AssetAmount::ZERO,
        "Bridge vault should be empty after the unlock"
    );

    mock_chain.add_pending_executed_transaction(&claim_executed)?;
    mock_chain.prove_next_block()?;

    // TX4: destination consumes the P2ID note and receives the unlocked asset. Pass the account
    // directly since the JSON-encoded destination decodes to a private account ID.
    let consume_executed = mock_chain
        .build_tx_context(destination_account.clone(), &[], slice::from_ref(&expected_p2id_note))?
        .build()?
        .execute()
        .await?;

    let mut destination_account = destination_account;
    destination_account.apply_delta(consume_executed.account_delta())?;
    assert_eq!(
        destination_account.vault().get_balance(expected_asset.vault_key())?,
        AssetAmount::new(miden_claim_amount_u64)?,
        "Destination account should receive the unlocked asset from the P2ID"
    );

    Ok(())
}

/// Tests that a second CLAIM reusing the same leaf against the native unlock path is rejected.
///
/// The native unlock path in `bridge_in_output::unlock_and_send` uses a deterministic P2ID serial
/// number derived from `CLAIM_PROOF_DATA_KEY`. Replay safety therefore depends on the claim
/// nullifier check in `bridge_in::claim` running before the branch into `unlock_and_send`. This
/// test seeds the bridge vault with enough native supply to serve two unlocks, then confirms the
/// second CLAIM with the same proof data is rejected with `ERR_CLAIM_ALREADY_SPENT` rather than
/// draining the vault a second time.
#[tokio::test]
async fn bridge_in_unlock_native_duplicate_rejected() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let mut bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();
    let origin_token_address = leaf_data.origin_token_address;
    let origin_network = leaf_data.origin_network;
    let metadata_hash = leaf_data.metadata_hash;
    let scale = 10u8;

    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");
    let miden_claim_amount_u64 = miden_claim_amount.as_canonical_u64();

    // Seed the native faucet and the lock sender with enough supply to cover two unlocks. If the
    // nullifier check is ever weakened, the second claim would otherwise succeed and drain the
    // vault a second time.
    let faucet_owner_account_id =
        AccountId::dummy([3; 15], AccountIdVersion::Version1, AccountType::Private);
    let native_faucet = builder.add_existing_network_faucet(
        "NATIVE",
        miden_claim_amount_u64.saturating_mul(4),
        faucet_owner_account_id,
        Some(miden_claim_amount_u64.saturating_mul(4)),
        MintPolicyConfig::OwnerOnly,
        [],
    )?;

    // Destination of the claim, built directly from the destination ID encoded in the JSON test
    // vector so the mock account matches the account ID the claim note targets.
    let destination_account_id = EthEmbeddedAccountId::try_from(leaf_data.destination_address)
        .expect("destination address is not an embedded Miden AccountId")
        .into_account_id();
    let destination_account =
        Account::mock(u128::from(destination_account_id), IncrNonceAuthComponent);
    builder.add_account(destination_account)?;

    let claim_sender = {
        let account_builder =
            Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?
    };

    let lock_sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: native_faucet.id(),
            origin_token_address,
            scale,
            origin_network,
            is_native: true,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    // Lock 2x the claim amount so the bridge vault could (if nullifier were broken) serve the
    // replayed claim.
    let bridge_asset: Asset =
        FungibleAsset::new(native_faucet.id(), miden_claim_amount_u64.saturating_mul(2))
            .unwrap()
            .into();
    let b2agg_destination_address =
        EthAddress::from_hex("0x1234567890abcdef1122334455667788990011aa")
            .expect("valid destination address");
    let b2agg_note = B2AggNote::create(
        1u32,
        b2agg_destination_address,
        NoteAssets::new(vec![bridge_asset])?,
        bridge_account.id(),
        lock_sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(b2agg_note.clone()));

    let claim_inputs_1 = ClaimNoteStorage {
        proof_data: proof_data.clone(),
        leaf_data: leaf_data.clone(),
        miden_claim_amount,
    };
    let claim_note_1 = ClaimNote::create(
        claim_inputs_1,
        bridge_account.id(),
        claim_sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note_1.clone()));

    let claim_inputs_2 = ClaimNoteStorage {
        proof_data: proof_data.clone(),
        leaf_data: leaf_data.clone(),
        miden_claim_amount,
    };
    let claim_note_2 = ClaimNote::create(
        claim_inputs_2,
        bridge_account.id(),
        claim_sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(claim_note_2.clone()));

    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.clone().build()?;

    // TX0: CONFIG — register native faucet.
    let config_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(config_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: LOCK — seed bridge vault with 2x miden_claim_amount.
    let lock_executed = mock_chain
        .build_tx_context(bridge_account.clone(), &[b2agg_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(lock_executed.account_delta())?;
    assert_eq!(
        bridge_account.vault().get_balance(bridge_asset.vault_key())?,
        AssetAmount::new(miden_claim_amount_u64.saturating_mul(2))?,
    );
    mock_chain.add_pending_executed_transaction(&lock_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: UPDATE_GER.
    let update_ger_executed = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?
        .execute()
        .await?;
    bridge_account.apply_delta(update_ger_executed.account_delta())?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX3: FIRST CLAIM — should succeed and drain half the vault.
    let claim_executed_1 = mock_chain
        .build_tx_context(bridge_account.clone(), &[], &[claim_note_1])?
        .build()?
        .execute()
        .await?;
    assert_eq!(claim_executed_1.output_notes().num_notes(), 1);
    bridge_account.apply_delta(claim_executed_1.account_delta())?;
    assert_eq!(
        bridge_account.vault().get_balance(bridge_asset.vault_key())?,
        AssetAmount::new(miden_claim_amount_u64)?,
        "Bridge vault should hold exactly the remaining half after the first unlock"
    );
    mock_chain.add_pending_executed_transaction(&claim_executed_1)?;
    mock_chain.prove_next_block()?;

    // TX4: SECOND CLAIM with same proof data — should fail on the nullifier, before reaching
    // `unlock_and_send`. Vault still has enough to serve it, so a pass here would mean the
    // nullifier gate is broken.
    let result = mock_chain
        .build_tx_context(bridge_account, &[], &[claim_note_2])?
        .build()?
        .execute()
        .await;
    assert!(
        result.is_err(),
        "Second native-path claim with the same PROOF_DATA_KEY should fail"
    );
    let error_msg = result.unwrap_err().to_string();
    let expected_err_code = ERR_CLAIM_ALREADY_SPENT.code().to_string();
    assert!(
        error_msg.contains(&expected_err_code),
        "expected error code {expected_err_code} for 'claim note has already been spent', got: {error_msg}"
    );

    Ok(())
}

#[tokio::test]
async fn solidity_verify_merkle_proof_compatibility() -> anyhow::Result<()> {
    let merkle_paths = &*SOLIDITY_MERKLE_PROOF_VECTORS;

    assert_eq!(merkle_paths.leaves.len(), merkle_paths.roots.len());
    assert_eq!(merkle_paths.leaves.len() * 32, merkle_paths.merkle_paths.len());

    for leaf_index in 0..32 {
        let source = merkle_proof_verification_code(leaf_index, merkle_paths);

        let tx_script = CodeBuilder::new()
            .with_statically_linked_library(&agglayer_library())?
            .compile_tx_script(source)?;

        TransactionContextBuilder::with_existing_mock_account()
            .tx_script(tx_script.clone())
            .build()?
            .execute()
            .await
            .context(format!("failed to execute transaction with leaf index {leaf_index}"))?;
    }
    Ok(())
}

/// Regression test for issue #2799 (ported from agglayer in #2860).
///
/// Registers a faucet for `(origin_token_address, registered_origin_network)` then submits a
/// CLAIM whose leaf carries the same `origin_token_address` but a different `origin_network`.
/// Before the fix, `lookup_faucet_by_token_address` was keyed on the address alone and would
/// silently resolve to the registered faucet — letting a deposit on one network mint via a
/// faucet bound to another. With the registry keyed on the (address, network) pair, the lookup
/// now misses and the claim is rejected with `ERR_TOKEN_NOT_REGISTERED`.
#[tokio::test]
async fn test_claim_fails_when_origin_network_unregistered() -> anyhow::Result<()> {
    let data_source = ClaimDataSource::L1ToMiden;
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(
        bridge_seed,
        bridge_admin.id(),
        ger_manager.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge_account.clone())?;

    let (proof_data, leaf_data, ger, _cgi_chain_hash) = data_source.get_data();

    let token_symbol = "AGG";
    let decimals = 8u8;
    let max_supply: Felt = FungibleAsset::MAX_AMOUNT.into();
    let agglayer_faucet_seed = builder.rng_mut().draw_word();

    let origin_token_address = leaf_data.origin_token_address;
    let leaf_origin_network = leaf_data.origin_network;
    // The CLAIM's leaf carries `leaf_origin_network`; the bridge is configured to recognize
    // this faucet for a *different* origin_network, so token-registry lookup must miss.
    let registered_origin_network = leaf_origin_network.wrapping_add(1);
    assert_ne!(
        registered_origin_network, leaf_origin_network,
        "test setup: registered network must differ from the leaf's network"
    );
    let scale = 10u8;
    let metadata_hash = leaf_data.metadata_hash;

    let agglayer_faucet = create_existing_agglayer_faucet(
        agglayer_faucet_seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account.id(),
    );
    builder.add_account(agglayer_faucet.clone())?;

    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

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

    // Register the faucet under the WRONG origin network. The leaf in the CLAIM will carry
    // `leaf_origin_network`, so `lookup_faucet_by_token_address` will compute a different key
    // and find no entry.
    let config_note = ConfigAggBridgeNote::create(
        ConversionMetadata {
            faucet_account_id: agglayer_faucet.id(),
            origin_token_address,
            scale,
            origin_network: registered_origin_network,
            is_native: false,
            metadata_hash,
        },
        bridge_admin.id(),
        bridge_account.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(config_note.clone()));

    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(update_ger_note.clone()));

    let mut mock_chain = builder.clone().build()?;

    // TX0: register faucet for `registered_origin_network`.
    let config_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[config_note.id()], &[])?
        .build()?;
    let config_executed = config_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&config_executed)?;
    mock_chain.prove_next_block()?;

    // TX1: store the GER.
    let update_ger_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // TX2: attempt the CLAIM whose leaf carries `leaf_origin_network`. The lookup must miss.
    let faucet_foreign_inputs = mock_chain.get_foreign_account_inputs(agglayer_faucet.id())?;
    let claim_tx = mock_chain
        .build_tx_context(bridge_account.id(), &[], &[claim_note])?
        .foreign_accounts(vec![faucet_foreign_inputs])
        .build()?;

    let result = claim_tx.execute().await;
    assert!(result.is_err(), "CLAIM whose origin_network is not registered must fail");
    let error_msg = result.unwrap_err().to_string();
    let expected_err_code = ERR_TOKEN_NOT_REGISTERED.code().to_string();
    assert!(
        error_msg.contains(&expected_err_code),
        "expected error code {expected_err_code} for cross-network unregistered claim, got: {error_msg}"
    );

    Ok(())
}

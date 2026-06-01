extern crate alloc;

use miden_agglayer::errors::{
    ERR_B2AGG_DESTINATION_NETWORK_IS_MIDEN, ERR_BRIDGE_MSG_TARGET_ACCOUNT_MISMATCH,
};
use miden_agglayer::{
    AggLayerBridge, EthAddress, MessageNote, MetadataHash, create_existing_bridge_account,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests that consuming a Bridge Message note against the bridge account updates the LET.
///
/// This test exercises the bridge_message outbound path:
/// 1. Creates a bridge account (with bridge admin and GER manager)
/// 2. Creates a MessageNote with known parameters (no assets)
/// 3. Consumes the note against the bridge account
/// 4. Verifies:
///    - LET num_leaves incremented by 1
///    - LET root is non-zero (changed from initial empty state)
///    - No output notes were created (messages don't produce BURN notes)
///    - Bridge vault is empty (no assets locked)
#[tokio::test]
async fn bridge_message_updates_let() -> anyhow::Result<()> {
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
    let mut bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    // CREATE SENDER ACCOUNT (the user sending the message)
    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // CREATE THE MESSAGE NOTE
    let destination_network = 1u32;
    let destination_address =
        EthAddress::from_hex("0x1234567890abcdef1234567890abcdef12345678")
            .expect("valid Ethereum address");
    let metadata_hash = MetadataHash::new([0x42u8; 32]);

    let note = MessageNote::create(
        destination_network,
        destination_address,
        metadata_hash,
        bridge_account.id(),
        sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // CONSUME THE MESSAGE NOTE AGAINST THE BRIDGE ACCOUNT
    let executed_tx = mock_chain
        .build_tx_context(bridge_account.clone(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // VERIFY LET UPDATED
    bridge_account.apply_delta(executed_tx.account_delta())?;
    assert_eq!(
        AggLayerBridge::read_let_num_leaves(&bridge_account),
        1,
        "LET num_leaves should be 1 after consuming one message note"
    );

    let root = AggLayerBridge::read_local_exit_root(&bridge_account)?;
    assert!(
        root.iter().any(|f| f.as_canonical_u64() != 0),
        "LET root should be non-zero after message"
    );

    // VERIFY NO OUTPUT NOTES (no BURN note for messages)
    assert_eq!(
        executed_tx.output_notes().num_notes(),
        0,
        "Message notes should not produce any output notes"
    );

    // VERIFY BRIDGE VAULT IS EMPTY (no assets locked)
    assert!(
        bridge_account.vault().assets().next().is_none(),
        "Bridge vault should be empty after message (no assets involved)"
    );

    Ok(())
}

/// Tests that the on-chain LET root matches an independently computed Keccak256 leaf hash.
///
/// This test:
/// 1. Creates a bridge + sender, creates and consumes a MessageNote
/// 2. Reads the on-chain leaf hash from the LET frontier storage
/// 3. Independently computes the expected Keccak256 leaf hash in Rust using the Solidity
///    `abi.encodePacked` layout (113 bytes)
/// 4. Verifies the on-chain frontier[0] feeds into the MTF to produce the on-chain root
/// 5. Compares the on-chain leaf hash against the independently computed one
#[tokio::test]
async fn bridge_message_leaf_hash_matches_independent_computation() -> anyhow::Result<()> {
    use miden_agglayer::{EthEmbeddedAccountId, ExitRoot};
    use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
    use miden_processor::utils::packed_u32_elements_to_bytes;
    use miden_protocol::{Felt, Word};

    use super::merkle_tree_frontier::MerkleTreeFrontier32;

    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let mut bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let destination_network = 1u32;
    let destination_address =
        EthAddress::from_hex("0x1234567890abcdef1234567890abcdef12345678")
            .expect("valid Ethereum address");
    let metadata_hash = MetadataHash::new([0x42u8; 32]);

    let note = MessageNote::create(
        destination_network,
        destination_address,
        metadata_hash,
        bridge_account.id(),
        sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Consume the message note against the bridge account
    let executed_tx = mock_chain
        .build_tx_context(bridge_account.clone(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    bridge_account.apply_delta(executed_tx.account_delta())?;

    // Verify LET was updated
    assert_eq!(
        AggLayerBridge::read_let_num_leaves(&bridge_account),
        1,
        "LET num_leaves should be 1 after consuming one message note"
    );

    // Read on-chain frontier[0] (the leaf hash) from bridge storage.
    // The frontier is stored as a double_word_array in a map slot.
    // For index 0, keys are [0,0,0,0] (word 0) and [0,0,1,0] (word 1).
    let frontier_slot = AggLayerBridge::let_frontier_slot_name();
    let key_lo = Word::new([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let key_hi = Word::new([Felt::ZERO, Felt::ZERO, Felt::from(1u32), Felt::ZERO]);

    let frontier0_lo = bridge_account.storage().get_map_item(frontier_slot, key_lo)?;
    let frontier0_hi = bridge_account.storage().get_map_item(frontier_slot, key_hi)?;

    let on_chain_leaf_felts: Vec<Felt> =
        frontier0_lo.iter().chain(frontier0_hi.iter()).copied().collect();
    let on_chain_leaf_bytes = packed_u32_elements_to_bytes(&on_chain_leaf_felts);

    // Verify the MTF is consistent: MTF(frontier[0]) should equal the on-chain root.
    let on_chain_leaf_digest =
        Keccak256Digest::from(<[u8; 32]>::try_from(&on_chain_leaf_bytes[..]).unwrap());
    let mut mtf = MerkleTreeFrontier32::<32>::new();
    let root_from_frontier = mtf.append_and_update_frontier(on_chain_leaf_digest);
    let expected_root = ExitRoot::new(root_from_frontier.into());
    let on_chain_root = AggLayerBridge::read_local_exit_root(&bridge_account)?;

    assert_eq!(
        on_chain_root,
        expected_root.to_elements(),
        "MTF(frontier[0]) should match on-chain root"
    );

    // Independently compute the expected leaf hash.
    //
    // The leaf is the Keccak256 hash of 113 bytes packed as abi.encodePacked:
    //   byte 0:       leafType (1 byte) = 1 for messages
    //   bytes 1-4:    originNetwork (4 bytes, BE) = 77 (MIDEN_NETWORK_ID)
    //   bytes 5-24:   originTokenAddress (20 bytes) = sender's AccountId as Ethereum address
    //   bytes 25-28:  destinationNetwork (4 bytes, BE)
    //   bytes 29-48:  destinationAddress (20 bytes)
    //   bytes 49-80:  amount (32 bytes) = all zeros for messages
    //   bytes 81-112: metadataHash (32 bytes)
    let origin_address: EthAddress =
        EthEmbeddedAccountId::from_account_id(sender.id()).to_eth_address();

    let mut packed = Vec::with_capacity(113);
    packed.push(1u8); // leafType = 1 (message)
    packed.extend_from_slice(&77u32.to_be_bytes()); // originNetwork = MIDEN_NETWORK_ID
    packed.extend_from_slice(origin_address.as_bytes()); // 20 bytes
    packed.extend_from_slice(&destination_network.to_be_bytes()); // 4 bytes
    packed.extend_from_slice(destination_address.as_bytes()); // 20 bytes
    packed.extend_from_slice(&[0u8; 32]); // amount = 0
    packed.extend_from_slice(metadata_hash.as_bytes()); // 32 bytes
    assert_eq!(packed.len(), 113);

    let leaf_hash: Keccak256Digest = Keccak256::hash(&packed);

    // Compare the on-chain leaf hash against the independently computed one
    let expected_leaf_felts: Vec<Felt> =
        ExitRoot::new((*leaf_hash.as_bytes()).into()).to_elements();

    assert_eq!(
        on_chain_leaf_felts
            .iter()
            .map(|f| f.as_canonical_u64() as u32)
            .collect::<Vec<_>>(),
        expected_leaf_felts
            .iter()
            .map(|f| f.as_canonical_u64() as u32)
            .collect::<Vec<_>>(),
        "On-chain leaf hash should match independently computed Keccak256 leaf hash"
    );

    Ok(())
}

/// Tests that the reclaim path (sender consuming their own MessageNote) is a no-op.
///
/// When the sender consumes a MessageNote themselves (instead of the bridge consuming it),
/// the note script should detect the reclaim condition and skip all bridge logic:
/// - No output notes should be created
/// - The bridge's LET should remain unchanged (num_leaves = 0)
/// - The transaction should succeed
#[tokio::test]
async fn bridge_message_reclaim_is_noop() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let note = MessageNote::create(
        1u32,
        EthAddress::from_hex("0x1234567890abcdef1234567890abcdef12345678")
            .expect("valid Ethereum address"),
        MetadataHash::new([0x42u8; 32]),
        bridge_account.id(),
        sender.id(), // sender == consuming account in reclaim
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Sender consumes their own note (reclaim path)
    let executed_tx = mock_chain
        .build_tx_context(sender.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // No output notes
    assert_eq!(executed_tx.output_notes().num_notes(), 0);

    // LET unchanged on bridge (note wasn't consumed by bridge)
    assert_eq!(AggLayerBridge::read_let_num_leaves(&bridge_account), 0);

    Ok(())
}

/// Tests that consuming multiple MessageNotes consecutively updates the LET correctly.
///
/// Sends 3 messages with different parameters and verifies:
/// - LET num_leaves increments to 1, 2, 3
/// - LET root changes after each message (is different from the previous)
/// - No output notes after any consumption
#[tokio::test]
async fn bridge_message_consecutive() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let mut bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create 3 MessageNotes with different destinations and metadata hashes
    let destinations = [
        (
            1u32,
            "0x1111111111111111111111111111111111111111",
            [0x01u8; 32],
        ),
        (
            2u32,
            "0x2222222222222222222222222222222222222222",
            [0x02u8; 32],
        ),
        (
            3u32,
            "0x3333333333333333333333333333333333333333",
            [0x03u8; 32],
        ),
    ];

    let mut notes = Vec::with_capacity(3);
    for (dest_network, dest_addr, mh_bytes) in &destinations {
        let note = MessageNote::create(
            *dest_network,
            EthAddress::from_hex(dest_addr).expect("valid Ethereum address"),
            MetadataHash::new(*mh_bytes),
            bridge_account.id(),
            sender.id(),
            builder.rng_mut(),
        )?;
        builder.add_output_note(RawOutputNote::Full(note.clone()));
        notes.push(note);
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mut prev_root = AggLayerBridge::read_local_exit_root(&bridge_account)?;

    for (i, note) in notes.iter().enumerate() {
        let executed_tx = mock_chain
            .build_tx_context(bridge_account.clone(), &[note.id()], &[])?
            .build()?
            .execute()
            .await?;

        // No output notes for messages
        assert_eq!(
            executed_tx.output_notes().num_notes(),
            0,
            "Message note #{} should not produce any output notes",
            i + 1
        );

        bridge_account.apply_delta(executed_tx.account_delta())?;

        // LET num_leaves increments
        assert_eq!(
            AggLayerBridge::read_let_num_leaves(&bridge_account),
            (i + 1) as u64,
            "LET num_leaves should be {} after consuming message note #{}",
            i + 1,
            i + 1
        );

        // LET root changed from previous
        let current_root = AggLayerBridge::read_local_exit_root(&bridge_account)?;
        assert_ne!(
            current_root, prev_root,
            "LET root should change after consuming message note #{}",
            i + 1
        );
        prev_root = current_root;

        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    Ok(())
}

/// Tests that a MessageNote with destination_network == MIDEN_NETWORK_ID is rejected.
///
/// The bridge_message procedure in bridge_out.masm checks that the destination network
/// is not Miden's own network ID (77) and panics with ERR_B2AGG_DESTINATION_NETWORK_IS_MIDEN.
#[tokio::test]
async fn bridge_message_rejects_destination_miden() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a MessageNote with destination_network = MIDEN_NETWORK_ID (77)
    let note = MessageNote::create(
        AggLayerBridge::MIDEN_NETWORK_ID,
        EthAddress::from_hex("0x1234567890abcdef1234567890abcdef12345678")
            .expect("valid Ethereum address"),
        MetadataHash::new([0x42u8; 32]),
        bridge_account.id(),
        sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_tx_context(bridge_account.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_B2AGG_DESTINATION_NETWORK_IS_MIDEN);

    Ok(())
}

/// Tests that a non-target account cannot consume a MessageNote.
///
/// The bridge_message note script checks that the consuming account matches the target
/// specified in the note attachment. If neither the bridge (target) nor the sender (reclaim),
/// the transaction fails with ERR_BRIDGE_MSG_TARGET_ACCOUNT_MISMATCH.
#[tokio::test]
async fn bridge_message_non_target_cannot_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_account = create_existing_bridge_account(
        builder.rng_mut().draw_word(),
        bridge_admin.id(),
        ger_manager.id(),
    );
    builder.add_account(bridge_account.clone())?;

    let sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // Create a "other" account (neither bridge nor sender)
    let other_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let note = MessageNote::create(
        1u32,
        EthAddress::from_hex("0x1234567890abcdef1234567890abcdef12345678")
            .expect("valid Ethereum address"),
        MetadataHash::new([0x42u8; 32]),
        bridge_account.id(),
        sender.id(),
        builder.rng_mut(),
    )?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;

    // Try to consume with other_account (not bridge, not sender)
    let result = mock_chain
        .build_tx_context(other_account.id(), &[note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_BRIDGE_MSG_TARGET_ACCOUNT_MISMATCH);

    Ok(())
}

/// Standalone MASM unit test that mimics how `bridge_message` stores leaf data to memory,
/// calls `compute_leaf_value`, and compares the hash with an independently computed Keccak256.
///
/// This bypasses the full transaction pipeline and directly exercises the MASM memory layout
/// and hash computation to diagnose leaf hash mismatches.
#[tokio::test]
async fn bridge_message_leaf_hash_masm_unit_test() -> anyhow::Result<()> {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use miden_agglayer::agglayer_library;
    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core_lib::CoreLibrary;
    use miden_crypto::hash::keccak::Keccak256;
    use miden_processor::utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes};
    use miden_protocol::Felt;

    use super::test_utils::execute_program_with_default_host;

    // --- Rust: build the 113-byte packed representation ---
    let origin_address_bytes = [0u8; 20];
    let destination_address_bytes = [0u8; 20];
    let metadata_hash_bytes = [0x42u8; 32];

    let mut packed = Vec::with_capacity(113);
    packed.push(1u8); // leafType = 1 (message)
    packed.extend_from_slice(&77u32.to_be_bytes()); // originNetwork = MIDEN_NETWORK_ID
    packed.extend_from_slice(&origin_address_bytes); // 20 bytes
    packed.extend_from_slice(&1u32.to_be_bytes()); // destinationNetwork = 1
    packed.extend_from_slice(&destination_address_bytes); // 20 bytes
    packed.extend_from_slice(&[0u8; 32]); // amount = 0
    packed.extend_from_slice(&metadata_hash_bytes); // 32 bytes
    assert_eq!(packed.len(), 113);

    let expected_hash = Keccak256::hash(&packed);
    let expected_felts: Vec<Felt> = bytes_to_packed_u32_elements(expected_hash.as_bytes());

    // --- Compute the u32 felt values for each field as bridge_message would store them ---

    // leafType = 1, byte-swapped: swap_u32_bytes(1) = 0x01000000 = 16777216
    let leaf_type_swapped: u32 = 16777216;

    // originNetwork = 77, byte-swapped: swap_u32_bytes(77) = 0x4D000000 = 1291845632
    let origin_network_swapped: u32 = 1291845632;

    // originAddress = 5 zeros (all-zero address)
    // Each limb is bytes_to_packed_u32_elements([0,0,0,0]) = 0
    let origin_addr_felts = [0u32; 5];

    // destinationNetwork = 1, byte-swapped: swap_u32_bytes(1) = 0x01000000 = 16777216
    let dest_network_swapped: u32 = 16777216;

    // destinationAddress = 5 zeros
    let dest_addr_felts = [0u32; 5];

    // amount = 8 zeros
    // metadataHash: [0x42; 32] as packed u32 LE felts
    // [0x42, 0x42, 0x42, 0x42] -> u32::from_le_bytes = 0x42424242 = 1111638594
    let metadata_felts: Vec<Felt> = bytes_to_packed_u32_elements(&metadata_hash_bytes);
    assert_eq!(metadata_felts.len(), 8);

    // --- Build MASM program ---
    // Memory layout (start_ptr = 0):
    //   addr 0:     leafType (byte-swapped)
    //   addr 1:     originNetwork (byte-swapped)
    //   addr 2-6:   originAddress (5 felts)
    //   addr 7:     destinationNetwork (byte-swapped)
    //   addr 8-12:  destinationAddress (5 felts)
    //   addr 13-20: amount (8 felts, all zero)
    //   addr 21-28: metadataHash (8 felts)
    //   addr 29-31: padding (3 felts, all zero)

    let mh: Vec<u64> = metadata_felts.iter().map(|f| f.as_canonical_u64()).collect();

    let source = format!(
        r#"
            use miden::core::sys
            use agglayer::bridge::leaf_utils

            begin
                # Store leafType = 1 (byte-swapped)
                push.{leaf_type_swapped} push.0 mem_store

                # Store originNetwork = 77 (byte-swapped)
                push.{origin_network_swapped} push.1 mem_store

                # Store originAddress = 5 zeros
                push.{oa0} push.2 mem_store
                push.{oa1} push.3 mem_store
                push.{oa2} push.4 mem_store
                push.{oa3} push.5 mem_store
                push.{oa4} push.6 mem_store

                # Store destinationNetwork = 1 (byte-swapped)
                push.{dest_network_swapped} push.7 mem_store

                # Store destinationAddress = 5 zeros
                push.{da0} push.8 mem_store
                push.{da1} push.9 mem_store
                push.{da2} push.10 mem_store
                push.{da3} push.11 mem_store
                push.{da4} push.12 mem_store

                # Store amount = 8 zeros
                push.0 push.13 mem_store
                push.0 push.14 mem_store
                push.0 push.15 mem_store
                push.0 push.16 mem_store
                push.0 push.17 mem_store
                push.0 push.18 mem_store
                push.0 push.19 mem_store
                push.0 push.20 mem_store

                # Store metadataHash = 8 felts
                push.{mh0} push.21 mem_store
                push.{mh1} push.22 mem_store
                push.{mh2} push.23 mem_store
                push.{mh3} push.24 mem_store
                push.{mh4} push.25 mem_store
                push.{mh5} push.26 mem_store
                push.{mh6} push.27 mem_store
                push.{mh7} push.28 mem_store

                # Store padding = 3 zeros
                push.0 push.29 mem_store
                push.0 push.30 mem_store
                push.0 push.31 mem_store

                # Compute leaf value (start_ptr = 0)
                push.0
                exec.leaf_utils::compute_leaf_value

                exec.sys::truncate_stack
            end
        "#,
        leaf_type_swapped = leaf_type_swapped,
        origin_network_swapped = origin_network_swapped,
        oa0 = origin_addr_felts[0],
        oa1 = origin_addr_felts[1],
        oa2 = origin_addr_felts[2],
        oa3 = origin_addr_felts[3],
        oa4 = origin_addr_felts[4],
        dest_network_swapped = dest_network_swapped,
        da0 = dest_addr_felts[0],
        da1 = dest_addr_felts[1],
        da2 = dest_addr_felts[2],
        da3 = dest_addr_felts[3],
        da4 = dest_addr_felts[4],
        mh0 = mh[0],
        mh1 = mh[1],
        mh2 = mh[2],
        mh3 = mh[3],
        mh4 = mh[4],
        mh5 = mh[5],
        mh6 = mh[6],
        mh7 = mh[7],
    );

    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib)
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    // Note: pack_leaf_data modifies memory in-place, so post-execution memory contains the
    // packed result, not the original stored values. We focus on the hash comparison.
    let ctx = miden_processor::ContextId::root();

    // --- Compare hash output ---
    let computed_felts: Vec<Felt> = exec_output.stack[0..8].to_vec();
    let computed_u32s: Vec<u32> = computed_felts
        .iter()
        .map(|f| f.as_canonical_u64() as u32)
        .collect();
    let expected_u32s: Vec<u32> = expected_felts
        .iter()
        .map(|f| f.as_canonical_u64() as u32)
        .collect();

    if computed_u32s != expected_u32s {
        // Diagnostic: show both as bytes
        let computed_bytes = packed_u32_elements_to_bytes(&computed_felts);
        let expected_bytes = packed_u32_elements_to_bytes(&expected_felts);
        eprintln!("MASM hash (felts):     {:?}", computed_u32s);
        eprintln!("Expected hash (felts): {:?}", expected_u32s);
        eprintln!("MASM hash (bytes):     {:02x?}", computed_bytes);
        eprintln!("Expected hash (bytes): {:02x?}", expected_bytes);

        // Also dump the packed memory for diagnosis (after pack_leaf_data ran)
        let packed_mem: Vec<u32> = (0..29u32)
            .map(|addr| {
                exec_output
                    .memory
                    .read_element(ctx, Felt::from(addr))
                    .map(|f| f.as_canonical_u64() as u32)
                    .unwrap_or(0)
            })
            .collect();
        eprintln!("Packed memory (29 u32 felts): {:08x?}", packed_mem);

        // Convert packed memory to bytes for comparison with expected packed bytes
        let packed_mem_felts: Vec<Felt> = (0..29u32)
            .map(|addr| {
                exec_output
                    .memory
                    .read_element(ctx, Felt::from(addr))
                    .unwrap_or(Felt::ZERO)
            })
            .collect();
        let packed_mem_bytes = packed_u32_elements_to_bytes(&packed_mem_felts);
        eprintln!(
            "Packed memory bytes (first 113): {:02x?}",
            &packed_mem_bytes[..113.min(packed_mem_bytes.len())]
        );
        eprintln!("Expected packed bytes:           {:02x?}", &packed);
    }

    assert_eq!(
        computed_u32s, expected_u32s,
        "MASM compute_leaf_value output should match Rust Keccak256 of packed leaf data"
    );

    Ok(())
}

/// MASM unit test: verifies that `eth_address::from_account_id` produces the same 5 felts
/// as the Rust `EthEmbeddedAccountId::from_account_id().to_elements()`.
///
/// This isolates the origin-address conversion from the full bridge pipeline to diagnose
/// leaf hash mismatches.
#[tokio::test]
async fn test_from_account_id_matches_rust() -> anyhow::Result<()> {
    use miden_agglayer::EthEmbeddedAccountId;
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType};

    use super::test_utils::execute_masm_script;

    // Pick a deterministic AccountId
    let account_id = AccountId::dummy([42; 15], AccountIdVersion::Version1, AccountType::Public);

    // Rust: compute expected 5 felts
    let expected_elements = EthEmbeddedAccountId::from_account_id(account_id).to_elements();
    assert_eq!(expected_elements.len(), 5, "EthAddress should have 5 elements");

    // Get the raw felt values for MASM
    let prefix_val = account_id.prefix().as_u64();
    let suffix_val = account_id.suffix().as_canonical_u64();

    eprintln!("AccountId: prefix={prefix_val}, suffix={suffix_val}");
    eprintln!(
        "Expected elements (u32): {:?}",
        expected_elements
            .iter()
            .map(|f| f.as_canonical_u64() as u32)
            .collect::<Vec<_>>()
    );

    // MASM program: push prefix then suffix so stack is [suffix, prefix]
    // (push.A push.B gives [B, A] on stack, B on top)
    // from_account_id expects [suffix, prefix] with suffix on top
    let source = format!(
        r#"
            use miden::core::sys
            use agglayer::common::eth_address

            begin
                push.{prefix_val} push.{suffix_val}
                # => [suffix, prefix]  (suffix on top)
                exec.eth_address::from_account_id
                # => [limb0, limb1, limb2, limb3, limb4]
                exec.sys::truncate_stack
            end
        "#,
        prefix_val = prefix_val,
        suffix_val = suffix_val,
    );

    let exec_output = execute_masm_script(&source).await?;

    // Read the 5 felts from the stack (limb0 on top = stack[0])
    let actual: Vec<u64> = exec_output.stack[0..5]
        .iter()
        .map(|f| f.as_canonical_u64())
        .collect();

    let expected: Vec<u64> = expected_elements
        .iter()
        .map(|f| f.as_canonical_u64())
        .collect();

    eprintln!("MASM actual   (u64): {:?}", actual);
    eprintln!("Rust expected (u64): {:?}", expected);

    // Also show as u32 for easier reading
    let actual_u32: Vec<u32> = actual.iter().map(|v| *v as u32).collect();
    let expected_u32: Vec<u32> = expected.iter().map(|v| *v as u32).collect();
    eprintln!("MASM actual   (u32): {:?}", actual_u32);
    eprintln!("Rust expected (u32): {:?}", expected_u32);

    assert_eq!(
        actual, expected,
        "MASM from_account_id output should match Rust EthEmbeddedAccountId::to_elements()"
    );

    Ok(())
}

/// Tests that two messages with identical destinations but different metadata_hashes produce
/// different LET roots.
///
/// This verifies that the metadata_hash is included in the leaf hash computation, so
/// distinct messages produce distinct tree states.
#[tokio::test]
async fn bridge_message_distinct_metadata_produces_distinct_roots() -> anyhow::Result<()> {
    // Helper: build a fresh bridge, consume one MessageNote, return the final LET root.
    async fn consume_single_message(
        metadata_hash: MetadataHash,
    ) -> anyhow::Result<Vec<miden_protocol::Felt>> {
        let mut builder = MockChain::builder();

        let bridge_admin = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;
        let ger_manager = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;

        let mut bridge_account = create_existing_bridge_account(
            builder.rng_mut().draw_word(),
            bridge_admin.id(),
            ger_manager.id(),
        );
        builder.add_account(bridge_account.clone())?;

        let sender = builder.add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })?;

        let note = MessageNote::create(
            1u32,
            EthAddress::from_hex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("valid Ethereum address"),
            metadata_hash,
            bridge_account.id(),
            sender.id(),
            builder.rng_mut(),
        )?;
        builder.add_output_note(RawOutputNote::Full(note.clone()));

        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        let executed_tx = mock_chain
            .build_tx_context(bridge_account.clone(), &[note.id()], &[])?
            .build()?
            .execute()
            .await?;

        bridge_account.apply_delta(executed_tx.account_delta())?;
        let root = AggLayerBridge::read_local_exit_root(&bridge_account)?;
        Ok(root)
    }

    let root_a = consume_single_message(MetadataHash::new([0xAAu8; 32])).await?;
    let root_b = consume_single_message(MetadataHash::new([0xBBu8; 32])).await?;

    assert_ne!(
        root_a, root_b,
        "Different metadata_hashes should produce different LET roots"
    );

    Ok(())
}

extern crate alloc;

use miden_agglayer::{
    AggLayerBridge, EthAddress, MessageNote, MetadataHash, create_existing_bridge_account,
};
use miden_crypto::rand::FeltRng;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{Auth, MockChain};

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

extern crate alloc;

use alloc::slice;
use alloc::string::String;

use anyhow::Context;
use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::{
    ClaimNoteStorage,
    ExitRoot,
    SmtNode,
    UpdateGerNote,
    agglayer_library,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_testing::utils::create_p2id_note_exact;
use miden_testing::{AccountState, Auth, MockChain, TransactionContextBuilder};
use miden_tx::utils::hex_to_bytes;
use rand::Rng;

use super::test_utils::{
    ClaimDataSource,
    MerkleProofVerificationFile,
    SOLIDITY_MERKLE_PROOF_VECTORS,
};

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
            \tpush.{node_lo} mem_storew_be.{} dropw
            \tpush.{node_hi} mem_storew_be.{} dropw
    ",
            height * 8,
            height * 8 + 4
        ));
    }

    let root = ExitRoot::from(hex_to_bytes(&merkle_paths.roots[index]).unwrap());
    let [root_lo, root_hi] = root.to_words();

    let leaf = Keccak256Output::from(hex_to_bytes(&merkle_paths.leaves[index]).unwrap());
    let [leaf_lo, leaf_hi] = leaf.to_words();

    format!(
        r#"
        use miden::agglayer::bridge::bridge_in
        use miden::core::word

        begin
            {store_path_source}

            push.{root_lo} mem_storew_be.256 dropw
            push.{root_hi} mem_storew_be.260 dropw

            push.256
            push.{index}
            push.0
            push.{leaf_hi}
            exec.word::reverse
            push.{leaf_lo}
            exec.word::reverse

            exec.bridge_in::verify_merkle_proof
            assert.err="verification failed"
        end
    "#
    )
}

/// Tests the bridge-in flow: CLAIM note -> Aggfaucet (FPI to Bridge) -> P2ID note created.
///
/// Parameterized over two claim data sources:
/// - [`ClaimDataSource::Real`]: uses real [`ProofData`] and [`LeafData`] from
///   `claim_asset_vectors_real_tx.json`, captured from an actual on-chain `claimAsset` transaction.
/// - [`ClaimDataSource::Simulated`]: uses locally generated [`ProofData`] and [`LeafData`] from
///   `claim_asset_vectors_local_tx.json`, produced by simulating a `bridgeAsset()` call.
///
/// In both cases the claim note is processed against the agglayer faucet, which validates the
/// Merkle proof and creates a P2ID note for the destination address.
///
/// Note: Modifying anything in the real test vectors would invalidate the Merkle proof,
/// as the proof was computed for the original leaf data including the original destination.
#[rstest::rstest]
#[case::real(ClaimDataSource::Real)]
#[case::simulated(ClaimDataSource::Simulated)]
#[tokio::test]
async fn test_bridge_in_claim_to_p2id(#[case] data_source: ClaimDataSource) -> anyhow::Result<()> {
    use miden_protocol::account::auth::AuthScheme;

    let mut builder = MockChain::builder();

    // CREATE BRIDGE ADMIN ACCOUNT (not used in this test, but distinct from GER manager)
    // --------------------------------------------------------------------------------------------
    let bridge_admin =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Poseidon2 })?;

    // CREATE GER MANAGER ACCOUNT (sends the UPDATE_GER note)
    // --------------------------------------------------------------------------------------------
    let ger_manager =
        builder.add_existing_wallet(Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Poseidon2 })?;

    // CREATE BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account =
        create_existing_bridge_account(bridge_seed, bridge_admin.id(), ger_manager.id());
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON (source depends on the test case)
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger) = data_source.get_data();

    // CREATE AGGLAYER FAUCET ACCOUNT (with agglayer_faucet component)
    // Use the origin token address and network from the claim data.
    // --------------------------------------------------------------------------------------------
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
    );
    builder.add_account(agglayer_faucet.clone())?;

    // Get the destination account ID from the leaf data.
    // This requires the destination_address to be in the embedded Miden AccountId format
    // (first 4 bytes must be zero).
    let destination_account_id = leaf_data
        .destination_address
        .to_account_id()
        .expect("destination address is not an embedded Miden AccountId");

    // For the simulated case, create the destination account so we can consume the P2ID note
    let destination_account = if matches!(data_source, ClaimDataSource::Simulated) {
        use miden_standards::testing::mock_account::MockAccountExt;

        let dest =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, IncrNonceAuthComponent);
        // Ensure the mock account ID matches the destination embedded in the JSON test vector,
        // since the claim note targets this account ID.
        assert_eq!(
            dest.id(),
            destination_account_id,
            "mock destination account ID must match the destination_account_id from the claim data"
        );
        builder.add_account(dest.clone())?;
        Some(dest)
    } else {
        None
    };

    // CREATE SENDER ACCOUNT (for creating the claim note)
    // --------------------------------------------------------------------------------------------
    let sender_account_builder =
        Account::builder(builder.rng_mut().random()).with_component(BasicWallet);
    let sender_account = builder.add_account_from_builder(
        Auth::IncrNonce,
        sender_account_builder,
        AccountState::Exists,
    )?;

    // CREATE CLAIM NOTE
    // --------------------------------------------------------------------------------------------

    // The P2ID serial number is derived from the PROOF_DATA_KEY (RPO hash of proof data)
    let serial_num = proof_data.to_commitment();

    // Calculate the scaled-down Miden amount using the faucet's scale factor
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
        agglayer_faucet.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, ger_manager.id(), bridge_account.id(), builder.rng_mut())?;
    builder.add_output_note(OutputNote::Full(update_ger_note.clone()));

    // BUILD MOCK CHAIN WITH ALL ACCOUNTS
    // --------------------------------------------------------------------------------------------
    let mut mock_chain = builder.clone().build()?;

    // EXECUTE UPDATE_GER NOTE TO STORE GER IN BRIDGE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let update_ger_tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[update_ger_note.id()], &[])?
        .build()?;
    let update_ger_executed = update_ger_tx_context.execute().await?;

    mock_chain.add_pending_executed_transaction(&update_ger_executed)?;
    mock_chain.prove_next_block()?;

    // EXECUTE CLAIM NOTE AGAINST AGGLAYER FAUCET (with FPI to Bridge)
    // --------------------------------------------------------------------------------------------
    let foreign_account_inputs = mock_chain.get_foreign_account_inputs(bridge_account.id())?;

    let tx_context = mock_chain
        .build_tx_context(agglayer_faucet.id(), &[], &[claim_note])?
        .foreign_accounts(vec![foreign_account_inputs])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // VERIFY P2ID NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------

    // Check that exactly one P2ID note was created by the faucet
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    // Verify note metadata properties
    assert_eq!(output_note.metadata().sender(), agglayer_faucet.id());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    // Extract and verify P2ID asset contents
    let mut assets_iter = output_note.assets().unwrap().iter_fungible();
    let p2id_asset = assets_iter.next().unwrap();

    // Verify minted amount matches expected scaled value
    assert_eq!(
        Felt::new(p2id_asset.amount()),
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
        FungibleAsset::new(agglayer_faucet.id(), miden_claim_amount.as_int())
            .unwrap()
            .into();
    let expected_output_p2id_note = create_p2id_note_exact(
        agglayer_faucet.id(),
        destination_account_id,
        vec![expected_asset],
        NoteType::Public,
        serial_num,
    )
    .unwrap();

    assert_eq!(OutputNote::Full(expected_output_p2id_note.clone()), *output_note);

    // CONSUME THE P2ID NOTE WITH THE DESTINATION ACCOUNT (simulated case only)
    // --------------------------------------------------------------------------------------------
    // For the simulated case, we control the destination account and can verify the full
    // end-to-end flow including P2ID consumption and balance updates.
    if let Some(destination_account) = destination_account {
        // Add the faucet transaction to the chain and prove the next block so the P2ID note is
        // committed and can be consumed.
        mock_chain.add_pending_executed_transaction(&executed_transaction)?;
        mock_chain.prove_next_block()?;

        // Execute the consume transaction for the destination account
        let consume_tx_context = mock_chain
            .build_tx_context(
                destination_account.id(),
                &[],
                slice::from_ref(&expected_output_p2id_note),
            )?
            .build()?;
        let consume_executed_transaction = consume_tx_context.execute().await?;

        // Verify the destination account received the minted asset
        let mut destination_account = destination_account.clone();
        destination_account.apply_delta(consume_executed_transaction.account_delta())?;

        let balance = destination_account.vault().get_balance(agglayer_faucet.id())?;
        assert_eq!(
            balance,
            miden_claim_amount.as_int(),
            "destination account balance does not match"
        );
    }
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

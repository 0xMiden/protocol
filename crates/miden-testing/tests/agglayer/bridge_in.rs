extern crate alloc;

use core::slice;

use miden_agglayer::{
    ClaimNoteStorage,
    OutputNoteData,
    UpdateGerNote,
    create_claim_note,
    create_existing_agglayer_faucet,
    create_existing_bridge_account,
};
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, FieldElement};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::testing::account_component::IncrNonceAuthComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_testing::utils::create_p2id_note_exact;
use miden_testing::{AccountState, Auth, MockChain};
use rand::Rng;

use super::test_utils::{local_claim_data, real_claim_data};

/// Identifies the source of claim data used in the bridge-in test.
#[derive(Debug, Clone, Copy)]
enum ClaimDataSource {
    /// Real on-chain claimAsset data from claim_asset_vectors_real_tx.json.json.
    Real,
    /// Locally simulated bridgeAsset data from claim_asset_vectors_local_tx.json.
    Simulated,
}

/// Tests the bridge-in flow: CLAIM note -> Aggfaucet (FPI to Bridge) -> P2ID note created.
///
/// Parameterized over two claim data sources:
/// - [`ClaimDataSource::Real`]: uses real [`ProofData`] and [`LeafData`] from
///   `claim_asset_vectors.json`, captured from an actual on-chain `claimAsset` transaction.
/// - [`ClaimDataSource::Simulated`]: uses locally generated [`ProofData`] and [`LeafData`] from
///   `claim_asset_vectors_local_tx.json`, produced by simulating a `bridgeAsset()` call.
///
/// In both cases the claim note is processed against the agglayer faucet, which validates the
/// Merkle proof and creates a P2ID note for the destination address.
///
/// The simulated case additionally creates a destination account and consumes the P2ID note,
/// verifying the full end-to-end bridge-in flow including balance updates.
///
/// Note: Modifying anything in the real test vectors would invalidate the Merkle proof,
/// as the proof was computed for the original leaf data including the original destination.
#[rstest::rstest]
#[case::real(ClaimDataSource::Real)]
#[case::simulated(ClaimDataSource::Simulated)]
#[tokio::test]
async fn test_bridge_in_claim_to_p2id(#[case] data_source: ClaimDataSource) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // CREATE BRIDGE ACCOUNT (with bridge_out component for MMR validation)
    // --------------------------------------------------------------------------------------------
    let bridge_seed = builder.rng_mut().draw_word();
    let bridge_account = create_existing_bridge_account(bridge_seed);
    builder.add_account(bridge_account.clone())?;

    // GET CLAIM DATA FROM JSON (source depends on the test case)
    // --------------------------------------------------------------------------------------------
    let (proof_data, leaf_data, ger) = match data_source {
        ClaimDataSource::Real => real_claim_data(),
        ClaimDataSource::Simulated => local_claim_data(),
    };

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
        let dest =
            Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, IncrNonceAuthComponent);
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

    // Generate a serial number for the P2ID note
    let serial_num = builder.rng_mut().draw_word();

    // Calculate the scaled-down Miden amount using the faucet's scale factor
    let miden_claim_amount = leaf_data
        .amount
        .scale_to_token_amount(scale as u32)
        .expect("amount should scale successfully");

    let output_note_data = OutputNoteData {
        output_p2id_serial_num: serial_num,
        target_faucet_account_id: agglayer_faucet.id(),
        output_note_tag: NoteTag::with_account_target(destination_account_id),
        miden_claim_amount,
    };

    let claim_inputs = ClaimNoteStorage { proof_data, leaf_data, output_note_data };

    let claim_note = create_claim_note(claim_inputs, sender_account.id(), builder.rng_mut())?;

    // Add the claim note to the builder before building the mock chain
    builder.add_output_note(OutputNote::Full(claim_note.clone()));

    // CREATE UPDATE_GER NOTE WITH GLOBAL EXIT ROOT
    // --------------------------------------------------------------------------------------------
    let update_ger_note =
        UpdateGerNote::create(ger, sender_account.id(), bridge_account.id(), builder.rng_mut())?;
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

//! Verifies that the agglayer note scripts reject an account that is not their target.
//!
//! Each of these notes commits its target bridge in a `NetworkAccountTarget` attachment and
//! asserts it before doing anything else, so consuming one against another bridge has to abort.
//! The happy paths live with each note's own tests; this file covers the negative direction for
//! every agglayer note script that carries a target.

use miden_agglayer::{
    AgglayerNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    ConversionMetadata,
    DeregisterAggFaucetNote,
    ExitRoot,
    GlobalIndex,
    LeafData,
    MetadataHash,
    ProofData,
    RemoveGerNote,
    SmtNode,
    UpdateGerNote,
};
use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::errors::standards::ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT;
use miden_standards::interop::eth::{EthAddress, EthAmount};
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rstest::rstest;

use super::test_utils::{
    MIDEN_NETWORK_ID,
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles,
};

// TESTS
// ================================================================================================

/// A note addressed to one bridge cannot be consumed by another bridge that exposes the same
/// interface and the same roles, so the target attachment is the only thing standing in the way.
///
/// `B2AGG` is covered by `bridge_out::b2agg_note_non_target_account_cannot_consume`, which also
/// exercises its reclaim branch.
#[rstest]
#[case::claim(AgglayerNote::CLAIM)]
#[case::config_agg_bridge(AgglayerNote::CONFIG_AGG_BRIDGE)]
#[case::deregister_agg_faucet(AgglayerNote::DEREGISTER_AGG_FAUCET)]
#[case::remove_ger(AgglayerNote::REMOVE_GER)]
#[case::update_ger(AgglayerNote::UPDATE_GER)]
#[tokio::test]
async fn note_addressed_to_another_bridge_cannot_be_consumed(
    #[case] note_kind: AgglayerNote,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // the sender holds every bridge role, so nothing but the target check can reject the note
    let privileged_sender = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let target_bridge = add_bridge(&mut builder, privileged_sender.id())?;
    let decoy_bridge = add_bridge(&mut builder, privileged_sender.id())?;

    let note = build_note(note_kind, target_bridge, privileged_sender.id(), builder.rng_mut())?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));

    let mock_chain = builder.build()?;
    let result = mock_chain
        .build_transaction(decoy_bridge)
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );

    Ok(())
}

// HELPERS
// ================================================================================================

/// Adds a bridge account that grants every role to `role_holder`, and returns its ID.
fn add_bridge(builder: &mut MockChainBuilder, role_holder: AccountId) -> anyhow::Result<AccountId> {
    let bridge = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        bridge_admin_account_id(),
        role_holder,
        role_holder,
        role_holder,
        bridge_admin_account_id(),
        role_holder,
        MIDEN_NETWORK_ID,
    );
    let bridge_id = bridge.id();
    builder.add_account(bridge)?;

    Ok(bridge_id)
}

/// Builds a note of the given kind addressed at `target`.
///
/// The payloads are placeholders: every one of these scripts asserts the target attachment before
/// it reads its storage, so a note that reaches the storage checks has already lost the target
/// check this file is about.
fn build_note<R: FeltRng>(
    note_kind: AgglayerNote,
    target: AccountId,
    sender: AccountId,
    rng: &mut R,
) -> anyhow::Result<Note> {
    let note = match note_kind {
        AgglayerNote::CLAIM => {
            ClaimNote::create(placeholder_claim_storage()?, target, sender, rng)?
        },
        AgglayerNote::CONFIG_AGG_BRIDGE => ConfigAggBridgeNote::create(
            placeholder_conversion_metadata(sender)?,
            sender,
            target,
            rng,
        )?,
        AgglayerNote::DEREGISTER_AGG_FAUCET => {
            DeregisterAggFaucetNote::create(sender, sender, target, rng)?
        },
        AgglayerNote::REMOVE_GER => {
            RemoveGerNote::create(ExitRoot::new([0x11; 32]), sender, target, rng)?
        },
        AgglayerNote::UPDATE_GER => {
            UpdateGerNote::create(ExitRoot::new([0x22; 32]), sender, target, rng)?
        },
        AgglayerNote::B2AGG => {
            anyhow::bail!("B2AGG is covered by its own test, which needs note assets")
        },
    };

    Ok(note)
}

/// Returns a `ClaimNoteStorage` whose proof never has to verify.
fn placeholder_claim_storage() -> anyhow::Result<ClaimNoteStorage> {
    let eth_address = EthAddress::from_hex("0x1234567890abcdef1122334455667788990011aa")?;

    Ok(ClaimNoteStorage {
        proof_data: ProofData {
            smt_proof_local_exit_root: [SmtNode::new([0u8; 32]); 32],
            smt_proof_rollup_exit_root: [SmtNode::new([0u8; 32]); 32],
            global_index: GlobalIndex::new([0u8; 32]),
            mainnet_exit_root: ExitRoot::new([0u8; 32]),
            rollup_exit_root: ExitRoot::new([0u8; 32]),
        },
        leaf_data: LeafData {
            origin_network: 0,
            origin_token_address: eth_address,
            destination_network: MIDEN_NETWORK_ID,
            destination_address: eth_address,
            amount: EthAmount::new([0u8; 32]),
            metadata_hash: MetadataHash::from_token_info("Placeholder", "PLC", 8),
        },
        miden_claim_amount: Felt::new(1)?,
    })
}

/// Returns a `ConversionMetadata` that registers `faucet` under a placeholder token.
fn placeholder_conversion_metadata(faucet: AccountId) -> anyhow::Result<ConversionMetadata> {
    Ok(ConversionMetadata {
        faucet_account_id: faucet,
        origin_token_address: EthAddress::from_hex("0x1234567890abcdef1122334455667788990011aa")?,
        scale: 8,
        origin_network: 0,
        is_native: false,
        metadata_hash: MetadataHash::from_token_info("Placeholder", "PLC", 8),
    })
}

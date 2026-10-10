use miden_protocol::Word;
use miden_protocol::account::{AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::P2idNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use rstest::rstest;

use super::*;
use crate::{AccountState, Auth};

fn encode(snapshot: wire::MockChainSnapshotV1) -> Vec<u8> {
    wire::MockChainSnapshot {
        version: Some(wire::mock_chain_snapshot::Version::V1(snapshot)),
    }
    .encode_to_vec()
}

#[test]
fn snapshot_restores_genesis_and_can_produce_a_block() -> anyhow::Result<()> {
    let mut original = MockChain::new();
    let mut restored = MockChain::try_from_bytes(&original.to_bytes())?;

    assert_eq!(original.protocol_config, restored.protocol_config);
    assert_eq!(original.validator_secret_keys, restored.validator_secret_keys);
    assert_eq!(original.prove_next_block()?, restored.prove_next_block()?);

    original.prove_next_block_with_validator_config_rotation(vec![
        miden_protocol::testing::random_secret_key::random_secret_key(),
    ])?;
    let mut restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert_eq!(original.prove_next_block()?, restored.prove_next_block()?);
    Ok(())
}

#[test]
fn snapshot_preserves_genesis_fixture_constraints() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    builder.add_output_note(miden_protocol::transaction::RawOutputNote::Full(note));
    let mut original = builder.build()?;
    let mut restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert_eq!(original.blocks, restored.blocks);
    assert_eq!(original.committed_notes, restored.committed_notes);

    // The genesis exception must not admit duplicate output notes in subsequent blocks.
    let mut invalid = original.to_snapshot();
    let mut next = invalid.blocks[0].clone();
    let header = next.header.as_mut().unwrap();
    header.block_num.as_mut().unwrap().block_num = 1;
    header.chain_commitment = Some(original.chain.commitment().into());
    invalid.blocks.push(next);
    let Err(error) = MockChain::try_from_bytes(&encode(invalid)) else {
        panic!("a non-genesis block with duplicate output notes should be rejected");
    };
    assert!(format!("{error:#}").contains("appears twice in the block body"));

    assert_eq!(original.prove_next_block()?, restored.prove_next_block()?);
    Ok(())
}

#[tokio::test]
async fn snapshot_resumes_pending_transactions_and_batches() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let public = builder.add_existing_wallet(Auth::basic_falcon())?;
    let private = builder.add_account_from_builder(
        Auth::basic_ecdsa(),
        AccountBuilder::new([42; 32])
            .account_type(AccountType::Private)
            .with_component(BasicWallet),
        AccountState::Exists,
    )?;
    let public_note = builder.add_p2any_note(public.id(), NoteType::Public, [])?;
    let private_note = builder.add_p2any_note(private.id(), NoteType::Private, [])?;
    let next_note = builder.add_p2any_note(public.id(), NoteType::Public, [])?;
    let mut original = builder.build()?;

    // Restoring the genesis snapshot must retain the private account's commitment and the full
    // private genesis note, without putting the private account into committed_accounts.
    let restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert!(restored.committed_account(private.id()).is_err());
    assert_eq!(restored.account_tree.get(private.id()), private.to_commitment());
    assert_eq!(original.committed_notes, restored.committed_notes);

    let executed = restored
        .build_transaction(public.id())
        .authenticated_input_note(public_note.id())
        .build()?
        .execute()
        .await?;
    original.add_pending_executed_transaction(&executed)?;
    let batches = original.pending_transactions_to_batches()?;
    assert_eq!(batches.len(), 1);
    for batch in batches {
        original.add_pending_batch(batch);
    }

    // This executes with the ECDSA authenticator restored from its secret key.
    let executed = restored
        .build_transaction(private)
        .authenticated_input_note(private_note)
        .build()?
        .execute()
        .await?;
    original.add_pending_executed_transaction(&executed)?;

    let mut restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert_eq!(restored.pending_batches, original.pending_batches);
    assert_eq!(restored.pending_transactions, original.pending_transactions);
    assert_eq!(restored.pending_batches.len(), 1);
    assert_eq!(restored.pending_transactions.len(), 1);
    assert_eq!(original.prove_next_block()?, restored.prove_next_block()?);

    // Restore a non-genesis snapshot with spent nullifiers, then continue with a
    // Falcon-authenticated transaction. This also exercises regenerated MMR authentication
    // paths.
    let mut restored = MockChain::try_from_bytes(&restored.to_bytes())?;
    assert_eq!(original.nullifier_tree, restored.nullifier_tree);
    assert_eq!(original.account_tree, restored.account_tree);
    let executed = restored
        .build_transaction(public.id())
        .authenticated_input_note(next_note.id())
        .build()?
        .execute()
        .await?;
    restored.add_pending_executed_transaction(&executed)?;
    restored.prove_next_block()?;
    assert!(restored.pending_transactions.is_empty());
    assert!(restored.pending_batches.is_empty());
    Ok(())
}

#[test]
fn snapshot_distinguishes_absent_and_empty_authenticators() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::Noop)?;
    let mut original = builder.build()?;
    let restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert!(restored.account_authenticators[&account.id()].authenticator().is_none());

    original
        .account_authenticators
        .insert(account.id(), AccountAuthenticator::new(Some(BasicAuthenticator::new(&[]))));
    let restored = MockChain::try_from_bytes(&original.to_bytes())?;
    assert!(
        restored.account_authenticators[&account.id()]
            .authenticator()
            .unwrap()
            .keys()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_restores_private_note_inclusion() -> anyhow::Result<()> {
    use miden_protocol::note::{Note, PartialNote};
    use miden_protocol::transaction::RawOutputNote;

    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, 100)?.into();
    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet_with_assets(Auth::basic_ecdsa(), [asset])?;
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mut chain = builder.build()?;
    let note: Note = P2idNote::builder()
        .sender(sender.id())
        .target(target.id())
        .assets([asset])
        .note_type(NoteType::Private)
        .serial_number(Word::from([1u32; 4]))
        .build()?
        .into();
    let script = SendNotesTransactionScript::new(
        &sender.code_interface(),
        &[PartialNote::from(note.clone())],
    )?;
    let executed = chain
        .build_transaction(sender.id())
        .send_notes_script(&script)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;
    chain.add_pending_executed_transaction(&executed)?;
    chain.prove_next_block()?;

    // A valid inclusion proof for an opaque private note ID must not allow different metadata.
    let mut invalid = chain.to_snapshot();
    let Some(wire::mock_chain_note::Details::Private(private)) =
        &mut invalid.committed_notes[0].details
    else {
        unreachable!()
    };
    private.metadata.as_mut().unwrap().sender = Some(target.id().into());
    let error = MockChain::try_from_bytes(&encode(invalid)).unwrap_err();
    assert!(format!("{error:#}").contains("does not match its block output"));

    let mut restored = MockChain::try_from_bytes(&chain.to_bytes())?;
    assert_eq!(restored.committed_notes, chain.committed_notes);
    assert!(restored.committed_notes[&note.id()].note().is_none());
    let executed = restored
        .build_transaction(target.id())
        .authenticated_input_note(note)
        .build()?
        .execute()
        .await?;
    restored.add_pending_executed_transaction(&executed)?;
    restored.prove_next_block()?;
    Ok(())
}

#[rstest]
#[case::missing(&[])]
#[case::future(&[0x12, 0])]
#[case::malformed(&[0xff])]
fn snapshot_requires_a_known_version(#[case] bytes: &[u8]) {
    assert!(MockChain::try_from_bytes(bytes).is_err());
}

#[rstest]
#[case("empty_history", "genesis")]
#[case("non_genesis", "start at genesis")]
#[case("duplicate_block", "consecutive")]
#[case("chain_commitment", "chain commitment mismatch")]
#[case("note_index", "invalid genesis output note index")]
#[case("duplicate_note_index", "duplicate genesis output note index")]
#[case("account_root", "account root mismatch")]
#[case("duplicate_commitment", "duplicate account commitment")]
#[case("missing_account", "missing a committed public account")]
#[case("duplicate_account", "duplicate committed account")]
#[case("duplicate_authenticator", "duplicate account authenticator")]
#[case("duplicate_key", "duplicate authenticator key")]
#[case("validator_scheme", "validator key must use ECDSA")]
#[case("validator_key", "validator keys do not match")]
#[case("protocol_config", "protocol configuration mismatch")]
#[case("missing_note", "missing a committed note")]
#[case("duplicate_note", "duplicate committed note")]
#[case("note_id", "note ID mismatch")]
fn snapshot_rejects_inconsistent_state(
    #[case] mutation: &str,
    #[case] expected: &str,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_falcon())?;
    builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mut snapshot = builder.build()?.to_snapshot();
    match mutation {
        "empty_history" => snapshot.blocks.clear(),
        "non_genesis" => {
            snapshot.blocks[0].header.as_mut().unwrap().block_num =
                Some(miden_protocol::block::BlockNumber::from(1).into())
        },
        "duplicate_block" => snapshot.blocks.push(snapshot.blocks[0].clone()),
        "chain_commitment" => {
            snapshot.blocks[0].header.as_mut().unwrap().chain_commitment =
                Some(Word::from([1u32; 4]).into())
        },
        "note_index" => {
            snapshot.blocks[0].body.as_mut().unwrap().output_note_batches[0].notes[0]
                .note_index_in_batch = miden_protocol::MAX_OUTPUT_NOTES_PER_BATCH as u32;
        },
        "duplicate_note_index" => {
            let notes = &mut snapshot.blocks[0].body.as_mut().unwrap().output_note_batches[0].notes;
            notes.push(notes[0].clone());
        },
        "account_root" => snapshot.account_commitments[0].commitment = Some(Word::empty().into()),
        "duplicate_commitment" => {
            snapshot.account_commitments.push(snapshot.account_commitments[0].clone())
        },
        "missing_account" => snapshot.committed_accounts.clear(),
        "duplicate_account" => {
            snapshot.committed_accounts.push(snapshot.committed_accounts[0].clone())
        },
        "duplicate_authenticator" => {
            snapshot.account_authenticators.push(snapshot.account_authenticators[0].clone())
        },
        "duplicate_key" => {
            let keys = &mut snapshot.account_authenticators[0].authenticator.as_mut().unwrap().keys;
            keys.push(keys[0].clone());
        },
        "validator_scheme" => {
            snapshot.validator_secret_keys[0] =
                snapshot.account_authenticators[0].authenticator.as_ref().unwrap().keys[0].clone()
        },
        "validator_key" => {
            snapshot.validator_secret_keys[0] = AuthSecretKey::EcdsaK256Keccak(
                miden_protocol::testing::random_secret_key::random_secret_key(),
            )
            .into()
        },
        "protocol_config" => {
            snapshot
                .protocol_config
                .as_mut()
                .unwrap()
                .proof_verification
                .as_mut()
                .unwrap()
                .security_policy
                .as_mut()
                .unwrap()
                .minimum_bits += 1;
        },
        "missing_note" => snapshot.committed_notes.clear(),
        "duplicate_note" => snapshot.committed_notes.push(snapshot.committed_notes[0].clone()),
        "note_id" => {
            let Some(wire::mock_chain_note::Details::Full(full)) =
                &mut snapshot.committed_notes[0].details
            else {
                unreachable!()
            };
            full.proof.as_mut().unwrap().note_id =
                Some(proto::note::NoteId { id: Some(Word::empty().into()) });
        },
        _ => unreachable!(),
    }
    let Err(error) = MockChain::try_from_bytes(&encode(snapshot)) else {
        panic!("inconsistent snapshot should be rejected");
    };
    assert!(format!("{error:#}").contains(expected), "{mutation}: {error:#}");
    Ok(())
}

#[tokio::test]
async fn snapshot_rejects_inconsistent_spent_nullifiers() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mut chain = builder.build()?;
    let executed = chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    chain.add_pending_executed_transaction(&executed)?;
    chain.prove_next_block()?;

    let snapshot = chain.to_snapshot();
    assert_eq!(snapshot.spent_nullifiers.len(), 1);
    let restored = MockChain::try_from_bytes(&encode(snapshot.clone()))?;
    assert_eq!(chain.nullifier_tree, restored.nullifier_tree);

    for (mutation, expected) in [
        ("missing", "nullifier root mismatch"),
        ("duplicate", "duplicate nullifier"),
        ("genesis", "invalid spent nullifier block number"),
        ("future", "invalid spent nullifier block number"),
    ] {
        let mut invalid = snapshot.clone();
        match mutation {
            "missing" => invalid.spent_nullifiers.clear(),
            "duplicate" => invalid.spent_nullifiers.push(invalid.spent_nullifiers[0].clone()),
            "genesis" => invalid.spent_nullifiers[0].block_num.as_mut().unwrap().block_num = 0,
            "future" => invalid.spent_nullifiers[0].block_num.as_mut().unwrap().block_num = 2,
            _ => unreachable!(),
        }
        let Err(error) = MockChain::try_from_bytes(&encode(invalid)) else {
            panic!("inconsistent snapshot should be rejected");
        };
        assert!(format!("{error:#}").contains(expected), "{mutation}: {error:#}");
    }
    Ok(())
}

#[test]
fn snapshot_schema_is_not_exported_for_transport() {
    assert!(
        !miden_objects::FILE_DESCRIPTOR_SET
            .windows(b"mock_chain_snapshot".len())
            .any(|window| window == b"mock_chain_snapshot")
    );
}

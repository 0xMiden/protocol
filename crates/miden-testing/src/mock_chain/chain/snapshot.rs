use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use anyhow::{Context, ensure};
use miden_objects::prost::Message;
use miden_objects::{BuildUnchecked, DecodeMessage, Verify, proto};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockSignatures, Blockchain, ProvenBlock, ValidatorConfig};
use miden_protocol::note::{NoteMetadata, NoteType, Nullifier};
use miden_tx::auth::BasicAuthenticator;
use proto::mock_chain_snapshot as wire;

use super::{AccountAuthenticator, MockChain, MockChainNote};

#[cfg(test)]
mod tests;

impl MockChain {
    /// Encodes this chain as a versioned Protobuf snapshot.
    ///
    /// The snapshot contains unencrypted account and validator secret keys. It preserves pending
    /// transactions and batches as well as committed state.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::MockChainSnapshot {
            version: Some(wire::mock_chain_snapshot::Version::V1(self.to_snapshot())),
        }
        .encode_to_vec()
    }

    /// Restores a chain from a Protobuf snapshot produced by [`Self::to_bytes`].
    ///
    /// Checks the snapshot's structure, block history and consistency with its latest state
    /// roots. This does not re-execute transactions or establish trust in the genesis state.
    /// Snapshots can contain arbitrarily large histories, so callers must bound untrusted input
    /// before decoding. The previous Winterfell snapshot format is not accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot is malformed, has an unsupported version, contains
    /// duplicate entries, or has inconsistent state.
    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let snapshot = wire::MockChainSnapshot::decode(bytes)
            .context("failed to decode mock chain snapshot")?
            .decode_fields()
            .context("invalid mock chain snapshot")?;
        let wire::mock_chain_snapshot::DecodedVersion::V1(snapshot) = snapshot.version;
        Self::from_snapshot(snapshot)
    }

    fn to_snapshot(&self) -> wire::MockChainSnapshotV1 {
        wire::MockChainSnapshotV1 {
            blocks: self
                .blocks
                .iter()
                .map(|block| wire::ProvenBlock {
                    header: Some(block.header().into()),
                    body: Some(block.body().into()),
                    signatures: block.signatures().as_signatures().iter().map(Into::into).collect(),
                    proof: Some(block.proof().into()),
                })
                .collect(),
            account_commitments: self
                .account_tree
                .account_commitments()
                .map(|(id, commitment)| wire::AccountCommitment {
                    account_id: Some(id.into()),
                    commitment: Some(commitment.into()),
                })
                .collect(),
            spent_nullifiers: self
                .nullifier_tree
                .entries()
                .map(|(nullifier, block_num)| wire::SpentNullifier {
                    nullifier: Some(nullifier.as_word().into()),
                    block_num: Some(block_num.into()),
                })
                .collect(),
            pending_transactions: self.pending_transactions.iter().map(Into::into).collect(),
            pending_batches: self.pending_batches.iter().map(Into::into).collect(),
            committed_accounts: self.committed_accounts.values().map(Into::into).collect(),
            committed_notes: self.committed_notes.values().map(encode_note).collect(),
            account_authenticators: self
                .account_authenticators
                .iter()
                .map(|(id, auth)| wire::AccountAuthenticator {
                    account_id: Some((*id).into()),
                    authenticator: auth.authenticator().map(|auth| wire::Authenticator {
                        keys: auth.keys().values().map(|(key, _)| key.into()).collect(),
                    }),
                })
                .collect(),
            validator_secret_keys: self
                .validator_secret_keys
                .iter()
                .map(|key| AuthSecretKey::EcdsaK256Keccak(key.clone()).into())
                .collect(),
            protocol_config: Some((&self.protocol_config).into()),
        }
    }

    fn from_snapshot(snapshot: wire::DecodedMockChainSnapshotV1) -> anyhow::Result<Self> {
        let mut chain = Blockchain::new();
        let mut blocks: Vec<ProvenBlock> = Vec::new();
        for (index, block) in snapshot.blocks.into_inner().into_iter().enumerate() {
            let header = block.header.build_unchecked()?;
            ensure!(
                header.block_num().as_usize() == index,
                "snapshot blocks must start at genesis and be consecutive"
            );
            ensure!(
                header.chain_commitment() == chain.commitment(),
                "snapshot chain commitment mismatch at block {index}"
            );

            let body = block.body.build_unchecked()?;
            let signatures = BlockSignatures::new(block.signatures.verify_infallible())?;
            let block = ProvenBlock::new_unchecked(header, body, signatures, block.proof);
            block
                .validate(blocks.last().map(ProvenBlock::header))
                .with_context(|| format!("invalid snapshot block {index}"))?;
            chain.push(block.header().commitment());
            blocks.push(block);
        }
        let latest = blocks.last().context("snapshot must contain a genesis block")?.header();

        let mut commitments = BTreeMap::new();
        for entry in snapshot.account_commitments.into_inner() {
            insert_unique(
                &mut commitments,
                entry.account_id.verify()?,
                entry.commitment,
                "account commitment",
            )?;
        }
        let account_tree = AccountTree::with_entries(commitments)?;
        ensure!(account_tree.root() == latest.account_root(), "snapshot account root mismatch");

        let mut nullifiers = BTreeMap::new();
        for entry in snapshot.spent_nullifiers.into_inner() {
            let block_num = entry.block_num.verify()?;
            ensure!(
                block_num.as_u32() > 0 && block_num <= latest.block_num(),
                "invalid spent nullifier block number"
            );
            insert_unique(
                &mut nullifiers,
                Nullifier::from_raw(entry.nullifier),
                block_num,
                "nullifier",
            )?;
        }
        let nullifier_tree = NullifierTree::with_entries(nullifiers)?;
        ensure!(
            nullifier_tree.root() == latest.nullifier_root(),
            "snapshot nullifier root mismatch"
        );

        let mut committed_accounts = BTreeMap::new();
        for account in snapshot.committed_accounts.verify()? {
            ensure!(account.id().is_public(), "snapshot committed account must be public");
            ensure!(
                account_tree.get(account.id()) == account.to_commitment(),
                "snapshot account commitment mismatch"
            );
            insert_unique(&mut committed_accounts, account.id(), account, "committed account")?;
        }
        for (id, _) in account_tree.account_commitments().filter(|(id, _)| id.is_public()) {
            ensure!(
                committed_accounts.contains_key(&id),
                "snapshot is missing a committed public account"
            );
        }

        let output_notes: BTreeMap<_, _> = blocks
            .iter()
            .flat_map(|block| {
                block.body().output_notes().map(move |(index, note)| {
                    ((block.header().block_num(), index.leaf_index_value()), note)
                })
            })
            .collect();
        let mut committed_notes = BTreeMap::new();
        for note in snapshot.committed_notes.into_inner() {
            let note = decode_note(note)?;
            let proof = note.inclusion_proof();
            let block = blocks
                .get(proof.location().block_num().as_usize())
                .context("snapshot note references an unknown block")?;
            let output_note = output_notes
                .get(&(proof.location().block_num(), proof.location().block_note_tree_index()))
                .context("snapshot note references an unknown output note")?;
            ensure!(
                note.id() == output_note.id() && note.metadata() == output_note.metadata(),
                "snapshot note does not match its block output"
            );
            proof
                .note_path()
                .verify(
                    u64::from(proof.location().block_note_tree_index()),
                    note.id().as_word(),
                    &block.header().note_root(),
                )
                .context("snapshot note inclusion proof is invalid")?;
            insert_unique(&mut committed_notes, note.id(), note, "committed note")?;
        }

        let mut account_authenticators = BTreeMap::new();
        for entry in snapshot.account_authenticators.into_inner() {
            let authenticator = entry
                .authenticator
                .into_inner()
                .map(|auth| {
                    let keys = auth.keys.verify_infallible();
                    let authenticator = BasicAuthenticator::new(&keys);
                    ensure!(
                        authenticator.keys().len() == keys.len(),
                        "duplicate authenticator key"
                    );
                    Ok(authenticator)
                })
                .transpose()?;
            insert_unique(
                &mut account_authenticators,
                entry.account_id.verify()?,
                AccountAuthenticator::new(authenticator),
                "account authenticator",
            )?;
        }
        let validator_secret_keys = snapshot
            .validator_secret_keys
            .verify_infallible()
            .into_iter()
            .map(|key| match key {
                AuthSecretKey::EcdsaK256Keccak(key) => Ok(key),
                _ => anyhow::bail!("validator key must use ECDSA secp256k1"),
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let validator_config = ValidatorConfig::new(
            validator_secret_keys.iter().map(|key| key.public_key()).collect(),
            validator_secret_keys.len().try_into()?,
        )?;
        ensure!(
            &validator_config == latest.validator_config(),
            "snapshot validator keys do not match the latest block"
        );
        let protocol_config = snapshot.protocol_config.verify()?;
        ensure!(
            protocol_config.to_commitment() == latest.protocol_config_commitment(),
            "snapshot protocol configuration mismatch"
        );

        Ok(Self {
            chain,
            blocks,
            account_tree,
            nullifier_tree,
            pending_transactions: snapshot.pending_transactions.build_unchecked()?,
            pending_batches: snapshot.pending_batches.build_unchecked()?,
            committed_accounts,
            committed_notes,
            account_authenticators,
            validator_secret_keys,
            protocol_config,
        })
    }
}

fn encode_note(note: &MockChainNote) -> wire::MockChainNote {
    use wire::mock_chain_note::Details;
    let proof = Some((&note.id(), note.inclusion_proof()).into());
    let details = match note {
        MockChainNote::Public(note, _) => {
            Details::Full(proto::transaction::AuthenticatedInputNote {
                note: Some(note.into()),
                proof,
            })
        },
        MockChainNote::Private(_, metadata, attachments, _) => {
            Details::Private(wire::PrivateNote {
                metadata: Some((*metadata).into()),
                attachments: Some(attachments.into()),
                proof,
            })
        },
    };
    wire::MockChainNote { details: Some(details) }
}

fn decode_note(note: wire::DecodedMockChainNote) -> anyhow::Result<MockChainNote> {
    use wire::mock_chain_note::DecodedDetails;
    match note.details {
        DecodedDetails::Full(full) => {
            let note = full.note.verify()?;
            let (id, proof) = full.proof.verify()?;
            ensure!(id == note.id(), "snapshot note ID mismatch");
            Ok(MockChainNote::Public(note, proof))
        },
        DecodedDetails::Private(private) => {
            let metadata = private.metadata.verify()?;
            let attachments = private.attachments.verify()?;
            let (id, proof) = private.proof.verify()?;
            ensure!(
                metadata.note_type() == NoteType::Private,
                "snapshot private note has public metadata"
            );
            ensure!(
                metadata == NoteMetadata::new(*metadata.partial_metadata(), &attachments),
                "snapshot note attachments mismatch"
            );
            Ok(MockChainNote::Private(id, metadata, attachments, proof))
        },
    }
}

fn insert_unique<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    entry: &str,
) -> anyhow::Result<()> {
    ensure!(map.insert(key, value).is_none(), "duplicate {entry} in snapshot");
    Ok(())
}

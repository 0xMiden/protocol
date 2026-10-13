use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use anyhow::Context;
use miden_objects::prost::Message;
use miden_objects::{BuildUnchecked, DecodeMessage, Verify, proto};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::nullifier_tree::NullifierTree;
use miden_protocol::block::{BlockBody, BlockSignatures, Blockchain, ProvenBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OrderedTransactionHeaders;
use miden_tx::auth::BasicAuthenticator;
use proto::mock_chain as wire;

use super::{AccountAuthenticator, MockChain, MockChainNote};

impl MockChain {
    /// Encodes committed and pending state as Protobuf, including unencrypted secret keys.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::MockChain {
            version: Some(wire::mock_chain::Version::V1(self.to_snapshot())),
        }
        .encode_to_vec()
    }

    /// Restores a trusted local snapshot from [`Self::to_bytes`].
    /// The caller must ensure the snapshot is valid; chain consistency is not checked.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding or reconstructing the snapshot fails.
    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let snapshot = wire::MockChain::decode(bytes)
            .context("failed to decode mock chain snapshot")?
            .decode_fields()
            .context("invalid mock chain snapshot")?;
        let wire::mock_chain::DecodedVersion::V1(snapshot) = snapshot.version;
        Self::from_snapshot(snapshot)
    }

    fn to_snapshot(&self) -> wire::MockChainV1 {
        wire::MockChainV1 {
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
            committed_notes: self.committed_notes.values().map(MockChainNote::encode).collect(),
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

    // TODO: Use the trusted restoration API once available:
    // https://github.com/0xMiden/protocol/issues/3937.
    fn from_snapshot(snapshot: wire::DecodedMockChainV1) -> anyhow::Result<Self> {
        let mut chain = Blockchain::new();
        let mut blocks = Vec::new();
        for block in snapshot.blocks.into_inner() {
            let header = block.header.build_unchecked()?;
            // Trust the saved body, including MockChainBuilder's unchecked genesis fixtures.
            let body = BlockBody::new_unchecked(
                block.body.updated_accounts.verify()?,
                block.body.output_note_batches.verify()?,
                block.body.created_nullifiers.map(Nullifier::from_raw),
                block.body.log_details.into_inner(),
                OrderedTransactionHeaders::new_unchecked(
                    block.body.transactions.build_unchecked()?,
                ),
            );
            let signatures = BlockSignatures::new(block.signatures.verify_infallible())?;
            let block = ProvenBlock::new_unchecked(header, body, signatures, block.proof);
            chain.push(block.header().commitment());
            blocks.push(block);
        }

        let commitments = snapshot
            .account_commitments
            .into_inner()
            .into_iter()
            .map(|entry| Ok((entry.account_id.verify()?, entry.commitment)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let account_tree = AccountTree::with_entries(commitments)?;
        let nullifiers = snapshot
            .spent_nullifiers
            .into_inner()
            .into_iter()
            .map(|entry| Ok((Nullifier::from_raw(entry.nullifier), entry.block_num.verify()?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let nullifier_tree = NullifierTree::with_entries(nullifiers)?;
        let committed_accounts = snapshot
            .committed_accounts
            .verify()?
            .into_iter()
            .map(|account| (account.id(), account))
            .collect();
        let committed_notes = snapshot
            .committed_notes
            .into_inner()
            .into_iter()
            .map(|note| {
                let note = MockChainNote::decode(note)?;
                Ok((note.id(), note))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let account_authenticators = snapshot
            .account_authenticators
            .into_inner()
            .into_iter()
            .map(|entry| {
                let authenticator = entry
                    .authenticator
                    .into_inner()
                    .map(|auth| BasicAuthenticator::new(&auth.keys.verify_infallible()));
                Ok((entry.account_id.verify()?, AccountAuthenticator::new(authenticator)))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let validator_secret_keys = snapshot
            .validator_secret_keys
            .verify_infallible()
            .into_iter()
            .map(|key| match key {
                AuthSecretKey::EcdsaK256Keccak(key) => Ok(key),
                _ => anyhow::bail!("validator key must use ECDSA secp256k1"),
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

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
            protocol_config: snapshot.protocol_config.verify()?,
        })
    }
}

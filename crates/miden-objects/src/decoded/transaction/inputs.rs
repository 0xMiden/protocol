use alloc::collections::BTreeMap;

use miden_protobuf::unwrap_infallible;
pub use proto::transaction::DecodedForeignAccountSlotName as ForeignAccountSlotName;
use proto::transaction::auth_signature::DecodedSignature;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
pub(super) mod tests;

impl Verify for ForeignAccountSlotName {
    type Verified =
        (miden_protocol::account::StorageSlotId, miden_protocol::account::StorageSlotName);
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let id = unwrap_infallible(self.slot_id.verify());
        let name = miden_protocol::account::StorageSlotName::new(self.slot_name)?;
        if name.id() != id {
            return Err(ForeignAccountSlotNameError::IdMismatch {
                expected: name.id(),
                actual: id,
            }
            .into());
        }
        Ok((id, name))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ForeignAccountSlotNameError {
    #[error("storage slot ID {actual} does not match the name's ID {expected}")]
    IdMismatch {
        expected: miden_protocol::account::StorageSlotId,
        actual: miden_protocol::account::StorageSlotId,
    },
}

pub use proto::transaction::DecodedAuthSignature as AuthSignature;

/// Returns the canonical signature; authenticity is checked by the transaction kernel.
impl Verify for AuthSignature {
    type Verified = miden_protocol::account::auth::Signature;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(match self.signature {
            DecodedSignature::Falcon512Poseidon2(signature) => {
                Self::Verified::Falcon512Poseidon2(signature.into_inner())
            },
            DecodedSignature::EcdsaK256Keccak(signature) => {
                Self::Verified::EcdsaK256Keccak(signature.into_inner())
            },
        })
    }
}

pub use proto::transaction::DecodedSignatureEntry as SignatureEntry;

impl Verify for SignatureEntry {
    type Verified = (
        miden_protocol::account::auth::SignatureKey,
        miden_protocol::account::auth::Signature,
    );
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let key = miden_protocol::account::auth::SignatureKey::new(
            self.pub_key_commitment.into(),
            self.message,
        );
        Ok((key, unwrap_infallible(self.signature.verify())))
    }
}

pub use proto::transaction::DecodedTransactionInputsV1 as TransactionInputsV1;

/// Checks input consistency and note inclusion against supplied headers, without authenticating the
/// chain.
impl crate::BuildUnchecked for TransactionInputsV1 {
    type Output = miden_protocol::transaction::TransactionInputs;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let account = self.account.verify()?;
        let header = self.block_header.build_unchecked()?;
        let config = self.protocol_config.verify()?;
        let chain = self.partial_blockchain.build_unchecked()?;
        let notes = self.input_notes.verify()?;
        let args = self.tx_args.verify()?;
        let advice = self.advice_inputs.verify()?;
        let code = self.foreign_account_code.verify()?;
        let mut names = BTreeMap::new();
        for name in self.foreign_account_slot_names.into_inner() {
            let (id, name) = name.verify()?;
            if names.insert(id, name).is_some() {
                return Err(TransactionInputsError::DuplicateSlot(id).into());
            }
        }
        let note_scripts = self.note_scripts.verify()?;
        let mut signatures = BTreeMap::new();
        for entry in self.signatures.into_inner() {
            let (key, signature) = unwrap_infallible(entry.verify());
            if signatures.insert(key, signature).is_some() {
                return Err(TransactionInputsError::DuplicateSignature(key).into());
            }
        }
        Ok(Self::Output::builder()
            .account(account)
            .block_header(header)
            .protocol_config(config)
            .blockchain(chain)
            .input_notes(notes)
            .tx_args(args)
            .advice_inputs(advice)
            .foreign_account_code(code)
            .foreign_account_slot_names(names)
            .note_scripts(note_scripts)
            .signatures(signatures)
            .build()?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionInputsError {
    #[error("duplicate foreign account storage slot ID {0}")]
    DuplicateSlot(miden_protocol::account::StorageSlotId),
    #[error(
        "duplicate signature for public key commitment {} and message {}",
        .0.pub_key_commitment(),
        .0.message()
    )]
    DuplicateSignature(miden_protocol::account::auth::SignatureKey),
}

pub use proto::transaction::DecodedTransactionInputs as TransactionInputs;

/// Dispatches the decoded version without adding trust to the supplied headers or chain.
impl crate::BuildUnchecked for TransactionInputs {
    type Output = miden_protocol::transaction::TransactionInputs;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let proto::transaction::transaction_inputs::DecodedVersion::V1(inputs) = self.version;
        inputs.build_unchecked()
    }
}

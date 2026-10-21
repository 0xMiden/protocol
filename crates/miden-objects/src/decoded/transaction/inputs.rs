use miden_protobuf::unwrap_infallible;
use proto::transaction::auth_signature::DecodedSignature;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
pub(super) mod tests;

pub use proto::transaction::DecodedAccountInputs as AccountInputs;

impl Verify for AccountInputs {
    type Verified = miden_protocol::transaction::AccountInputs;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.account.verify()?, self.witness.verify()?))
    }
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

pub use proto::transaction::DecodedBoundSignature as BoundSignature;

/// Binds the signature to its key; authenticity is checked by the transaction kernel.
impl Verify for BoundSignature {
    type Verified = miden_protocol::account::auth::BoundSignature;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let key = miden_protocol::account::auth::SignatureKey::new(
            self.pub_key_commitment.into(),
            self.message,
        );
        Ok(Self::Verified::new(key, unwrap_infallible(self.signature.verify()))?)
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
        let foreign_accounts = self.foreign_accounts.verify()?;
        let note_scripts = self.note_scripts.verify()?;
        let signatures = self.signatures.verify()?;
        Ok(Self::Output::builder()
            .account(account)
            .block_header(header)
            .protocol_config(config)
            .blockchain(chain)
            .input_notes(notes)
            .tx_args(args)
            .foreign_accounts(foreign_accounts)
            .note_scripts(note_scripts)
            .signatures(signatures)
            .build()?)
    }
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

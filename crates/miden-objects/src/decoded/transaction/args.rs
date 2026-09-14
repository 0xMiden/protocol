use miden_protobuf::unwrap_infallible;
pub use proto::transaction::DecodedTransactionScript as TransactionScript;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for TransactionScript {
    type Verified = miden_protocol::transaction::TransactionScript;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mast = self.mast.verify()?;
        let entrypoint = miden_protocol::MastNodeId::from_u32_safe(self.entrypoint, &mast)?;
        Self::Verified::from_parts(alloc::sync::Arc::new(mast), entrypoint)
            .map_err(VerificationError::new)
    }
}

pub use proto::transaction::DecodedNoteArgument as NoteArgument;

impl Verify for NoteArgument {
    type Verified = (miden_protocol::note::NoteId, miden_protocol::Word);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.note_id.verify()?, self.args))
    }
}

pub use proto::transaction::DecodedTransactionArgs as TransactionArgs;

impl Verify for TransactionArgs {
    type Verified = miden_protocol::transaction::TransactionArgs;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let tx_script = self.tx_script.map(Verify::verify).transpose()?;
        let mut note_args = alloc::collections::BTreeMap::new();
        for argument in self.note_args {
            let (id, args) = unwrap_infallible(argument.verify());
            if note_args.insert(id, args).is_some() {
                return Err(TransactionArgsError::DuplicateNoteArgument(id).into());
            }
        }
        Ok(Self::Verified::from_parts(
            tx_script,
            self.tx_script_args,
            note_args,
            self.advice_inputs.verify()?,
            self.auth_args,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionArgsError {
    #[error("duplicate note argument {0}")]
    DuplicateNoteArgument(miden_protocol::note::NoteId),
}

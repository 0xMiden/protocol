mod account;
mod account_patch;
mod asset;
mod batch;
mod block;
mod merkle;
mod note;
mod primitives;
mod protocol_config;
mod transaction;
mod transaction_inputs;

use core::error::Error;
use core::marker::PhantomData;

pub(crate) use account::{
    decode_account_id,
    decode_partial_storage,
    decode_partial_storage_map,
    decode_partial_vault,
};
pub(crate) use account_patch::{
    decode_account_code,
    decode_account_storage_patch,
    decode_account_vault_patch,
};
pub use batch::{decode_proposed_batch, decode_proven_batch, decode_standalone_proven_batch};
pub(crate) use merkle::decode_mmr_delta;
pub(crate) use note::{
    decode_note_attachment,
    decode_note_script,
    decode_note_storage,
    validate_note_attachments,
};

use crate::ConversionError;

pub(crate) struct MessageDecoder<M>(PhantomData<M>);

impl<M: prost::Message> Default for MessageDecoder<M> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<M: prost::Message> MessageDecoder<M> {
    pub(crate) fn required<T, U>(
        &self,
        name: &'static str,
        value: Option<T>,
    ) -> Result<U, ConversionError>
    where
        T: TryInto<U>,
        T::Error: Error + Send + Sync + 'static,
    {
        value
            .ok_or_else(|| ConversionError::missing_field::<M>(name))?
            .try_into()
            .map_err(ConversionError::new)
            .map_err(|error: ConversionError| error.context(name))
    }
}

pub(crate) trait MessageDecodeExt: prost::Message + Sized {
    fn decoder(&self) -> MessageDecoder<Self> {
        MessageDecoder::default()
    }
}

impl<T: prost::Message> MessageDecodeExt for T {}

macro_rules! required {
    ($decoder:ident, $message:ident. $field:ident) => {
        $decoder.required(stringify!($field), $message.$field)
    };
    ($decoder:ident, $field:ident) => {
        $decoder.required(stringify!($field), $field)
    };
}

pub(crate) use required;

mod account;
mod account_patch;
mod batch;
mod block;
mod merkle;
mod note;
mod primitives;
mod transaction;

use core::marker::PhantomData;

pub use batch::{decode_proposed_batch, decode_proven_batch, decode_standalone_proven_batch};

use crate::ConversionError;

pub(crate) struct MessageDecoder<M>(PhantomData<M>);

impl<M: prost::Message> Default for MessageDecoder<M> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<M: prost::Message> MessageDecoder<M> {
    pub(crate) fn decode_field<T, U>(
        &self,
        name: &'static str,
        value: Option<T>,
    ) -> Result<U, ConversionError>
    where
        T: TryInto<U>,
        T::Error: Into<ConversionError>,
    {
        self.required(name, value)
    }

    pub(crate) fn required<T, U>(
        &self,
        name: &'static str,
        value: Option<T>,
    ) -> Result<U, ConversionError>
    where
        T: TryInto<U>,
        T::Error: Into<ConversionError>,
    {
        value
            .ok_or_else(|| ConversionError::missing_field::<M>(name))?
            .try_into()
            .map_err(Into::into)
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

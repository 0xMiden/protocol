#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod account_file;
pub mod conversion;
pub mod decoded;
pub mod error;
pub mod note_file;

#[cfg(test)]
pub(crate) mod test_utils;

pub use error::{ConversionError, ConversionResultExt};
pub use miden_protobuf::{
    BuildUnchecked,
    DecodeMessage,
    DecodeMessageExt,
    Decoded,
    Verify,
    VerifyWith,
};
pub use prost;

/// Generated canonical Protobuf messages.
pub mod proto {
    pub mod account {
        include!(concat!(env!("OUT_DIR"), "/account.rs"));
    }

    #[expect(clippy::module_inception)]
    pub mod account_file {
        include!(concat!(env!("OUT_DIR"), "/account_file.rs"));
    }

    pub mod asset {
        include!(concat!(env!("OUT_DIR"), "/asset.rs"));
    }

    pub mod blockchain {
        include!(concat!(env!("OUT_DIR"), "/blockchain.rs"));
    }

    pub mod note {
        include!(concat!(env!("OUT_DIR"), "/note.rs"));
    }

    #[expect(clippy::module_inception)]
    pub mod note_file {
        include!(concat!(env!("OUT_DIR"), "/note_file.rs"));
    }

    pub mod primitives {
        include!(concat!(env!("OUT_DIR"), "/primitives.rs"));
    }

    pub mod protocol_config {
        include!(concat!(env!("OUT_DIR"), "/protocol_config.rs"));
    }

    pub mod transaction {
        include!(concat!(env!("OUT_DIR"), "/transaction.rs"));
    }
}

/// Self-contained descriptor set for the canonical object schemas.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/miden_objects_descriptor.bin"));

/// Protobuf paths and their canonical generated Rust paths.
///
/// Service-binding build scripts should configure these as Prost external paths so that messages
/// imported from this descriptor are represented by this crate's generated Rust types.
pub const EXTERN_PATHS: &[(&str, &str)] = &[
    (".account", "::miden_objects::proto::account"),
    (".asset", "::miden_objects::proto::asset"),
    (".blockchain", "::miden_objects::proto::blockchain"),
    (".note", "::miden_objects::proto::note"),
    (".primitives", "::miden_objects::proto::primitives"),
    (".protocol_config", "::miden_objects::proto::protocol_config"),
    (".transaction", "::miden_objects::proto::transaction"),
];

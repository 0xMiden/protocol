#![no_std]

extern crate alloc;

pub mod conversion;
pub mod error;

pub use error::{ConversionError, ConversionResultExt};
pub use prost;

/// Generated canonical Protobuf messages.
pub mod proto {
    pub mod account {
        include!(concat!(env!("OUT_DIR"), "/account.rs"));
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

    pub mod primitives {
        include!(concat!(env!("OUT_DIR"), "/primitives.rs"));
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
    (".transaction", "::miden_objects::proto::transaction"),
];

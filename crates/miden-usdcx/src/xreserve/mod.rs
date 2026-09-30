//! `xreserve` product-root mirror modules.

pub mod encoding;

/// Circle's xReserve domain for Miden.
pub const MIDEN_DOMAIN: u32 = encoding::CircleDomain::MIDEN.as_u32();

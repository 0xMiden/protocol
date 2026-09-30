//! `xreserve` faucet account composition — the [`XReserveStablecoinBuilder`].

pub mod admin_authority;
pub mod builder;

pub use admin_authority::XReserveAdminAuthority;
pub use builder::{
    ATTEST_ADMIN_ROLE,
    ATTESTATION_MINT_POLICY_PROC_PATH,
    BLK_MANAGER_ROLE,
    DOM_PAUSER_ROLE,
    DOM_UNPAUSER_ROLE,
    MIN_BURN_SIZE_FLOOR,
    USDCX_DECIMALS,
    USDCX_TOKEN_SYMBOL,
    XRESERVE_SET_ATTESTER_PROC_PATH,
    XReserveFaucetExtension,
    XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError,
    build_faucet_account,
    record_used_nonces,
};

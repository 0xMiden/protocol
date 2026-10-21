//! Faucet-owned note constructors: the public burn-event note `XReserveBurnNote`, the production
//! mint-note factory `XUsdcMintNote`, and the `xreserve_admin` admin-note factories.
//!
//! All are producers only — nothing here consumes a note. Payloads are written with the shared
//! codecs in `crate::xreserve::encoding`, so the bytes a note carries are defined in exactly one
//! place.

use miden_protocol::account::AccountId;
use miden_protocol::errors::NoteError;
use miden_protocol::note::NoteAttachment;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

pub mod costs;
pub mod xreserve_admin;
pub mod xreserve_burn;
pub mod xreserve_mint;

/// The scheme-2 `NetworkAccountTarget` routing bind to the faucet network account (routing-only),
/// shared by every faucet-targeted note this module produces. Requires a PUBLIC faucet id.
pub(crate) fn network_routing_attachment(
    faucet_id: AccountId,
) -> Result<NoteAttachment, NoteError> {
    let target =
        NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
            NoteError::other_with_source("faucet id is not a public network account", err)
        })?;
    Ok(NoteAttachment::from(target))
}

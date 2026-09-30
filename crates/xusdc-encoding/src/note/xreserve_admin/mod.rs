//! Faucet-owned ADMIN note factories: the root-pinned, storage-param admin notes the faucet
//! network account consumes to drive its role-gated admin procs.
//!
//! Each admin note:
//!
//! * carries its parameters CREATOR-COMMITTED in `NoteStorage.items`;
//! * uses a FIXED, root-pinned note script, independent of the param values, so it can be
//!   allowlisted;
//! * carries a scheme-2 `NetworkAccountTarget` routing bind to the faucet (routing-only).
//!
//! The note script marshals the params onto the stack and `call`s the unchanged sender-gated admin
//! proc — the note sender is kernel-forced, so the proc's role gate is sound under permissionless
//! network execution.
//!
//! This module ships the one faucet-owned row of the note-script allowlist: the `set_attester`
//! reference op, which resolves, through the account-wide authority, to the `ATTEST_ADMIN` role.
//!
//! The other admin surfaces do NOT ship a faucet-owned note script, because a standard note
//! already covers each of them and calls the standard component the faucet installs. Pausing uses
//! the standard pause-action note directly, with no faucet wrapper at all, the max-supply cap
//! uses the standard faucet-metadata config note the same way, and the blocklist uses the
//! standard blocklist-config note. Role management uses the standard role-action note, whose
//! single script root carries grant, revoke, set-role-admin and renounce alike. One surface goes
//! through a thin factory that exists solely to refuse building a note the standard builder would
//! accept: the burn floor through [`XReserveMinBurnAmountNote`] (no zero floor).
//!
//! There is no ownership note either: the faucet installs no two-step ownership component, so
//! rotation is a grant and a revoke of the `ADMIN` role through the standard role-action note.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachments, NoteRecipient, NoteScript, NoteStorage, NoteTag, NoteType,
    PartialNoteMetadata,
};
use miden_protocol::Felt;

mod min_burn_amount;
mod set_attester;

pub use min_burn_amount::{XReserveMinBurnAmountNote, XReserveMinBurnAmountNoteError};
pub use set_attester::{XReserveSetAttesterNote, XReserveSetAttesterNoteStorage};

/// Assembles an admin note from its fixed-root `script` + the creator-committed storage `items`,
/// carrying the scheme-2 `NetworkAccountTarget` routing bind to `faucet_id` (routing-only). Shared by
/// every admin-note factory: the notes differ only in their script + the felt payload they commit;
/// the metadata (PUBLIC, faucet-tagged), the serial draw, the empty asset set, and the routing
/// attachment are identical. `sender` is the (kernel-forced) admin party the wrapped proc's gate reads.
pub(super) fn build_admin_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    script: NoteScript,
    items: Vec<Felt>,
    rng: &mut R,
) -> Result<Note, NoteError> {
    let storage = NoteStorage::new(items)?;
    let serial_num = rng.draw_word();
    let recipient = NoteRecipient::new(serial_num, script, storage);
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet_id));
    let attachments = NoteAttachments::new(vec![super::network_routing_attachment(faucet_id)?])?;
    Ok(Note::with_attachments(
        NoteAssets::new(vec![])?,
        metadata,
        recipient,
        attachments,
    ))
}

// ROLE MANAGEMENT — NO FACTORY (the standard role-action note covers it)
// ================================================================================================
// There is no faucet-owned role note. The standard role-action note is allowlisted instead, and its
// single script root carries all four of the standard role component's management actions: grant,
// revoke, set-role-admin and renounce. Admitting the root admits all four, so the role-admin graph
// the build seeds is runtime-mutable rather than frozen, and a role holder can drop its own
// membership. That exposure is deliberate and human-ratified; the allowlist doc in
// `account::xreserve::builder` states what it means for the account.
//
// Authorization is unchanged by the move: every action is gated by the standard role component
// against the note sender — grant, revoke and set-role-admin on the target role's effective admin
// role, renounce on the sender's own membership.

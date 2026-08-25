use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{AccountIdError, NoteError};
use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteType};
use miden_protocol::{Felt, Word};

use crate::note::{NoteExecutionHint, StandardNoteAttachment};

// NETWORK ACCOUNT TARGET
// ================================================================================================

/// A [`NoteAttachment`] for notes targeted at network accounts.
///
/// It can be encoded to and from a single-word attachment content with the following layout:
///
/// ```text
/// - 0th felt: [target_id_suffix (56 bits) | 8 zero bits]
/// - 1st felt: [target_id_prefix (64 bits)]
/// - 2nd felt: [24 zero bits | exec_hint_payload (32 bits) | exec_hint_tag (8 bits)]
/// - 3rd felt: [32 zero bits | expiry_block (32 bits)]
/// ```
///
/// The expiry block is the last block at which the note may be included into the chain;
/// [`BlockNumber::GENESIS`] encodes "never expires" and is the value a target without an expiry is
/// serialized with. Enforcement lives in the note script, which is expected to call
/// `miden::standards::attachments::network_account_target::assert_not_expired`; that procedure also
/// caps the transaction expiration block delta, without which the expiry would not bind, since the
/// reference block a script reads is chosen by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAccountTarget {
    target_id: AccountId,
    exec_hint: NoteExecutionHint,
    expiry: Option<BlockNumber>,
}

impl NetworkAccountTarget {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of [`NetworkAccountTarget`] attachments.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::NetworkAccountTarget.attachment_scheme();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NetworkAccountTarget`] from the provided parts.
    ///
    /// The returned target never expires; add an expiry with [`NetworkAccountTarget::with_expiry`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided `target_id` does not have
    ///   [`AccountType::Public`](miden_protocol::account::AccountType::Public).
    pub fn new(
        target_id: AccountId,
        exec_hint: NoteExecutionHint,
    ) -> Result<Self, NetworkAccountTargetError> {
        if !target_id.is_public() {
            return Err(NetworkAccountTargetError::TargetNotPublic(target_id));
        }

        Ok(Self { target_id, exec_hint, expiry: None })
    }

    /// Sets the block after which the note carrying this target can no longer take effect.
    ///
    /// The note remains consumable in the sense that a transaction can be built for it, but a note
    /// script honouring the attachment aborts rather than applying the note's effect. Choose the
    /// expiry from how long the note's effect should stay pre-authorized, not from how long it may
    /// take to be included: the enforcing procedure separately caps the transaction expiration
    /// block delta, so the expiry block is the last block at which the note can take effect.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `expiry` is [`BlockNumber::GENESIS`], which encodes "never expires" and so cannot express
    ///   an expiry.
    pub fn with_expiry(mut self, expiry: BlockNumber) -> Result<Self, NetworkAccountTargetError> {
        if expiry == BlockNumber::GENESIS {
            return Err(NetworkAccountTargetError::ExpiryIsGenesis);
        }

        self.expiry = Some(expiry);
        Ok(self)
    }

    /// Ensures `attachments` carries a [`NetworkAccountTarget`] for `target_id` expiring at
    /// `expiry`, appending one with [`NoteExecutionHint::Always`] if none is present.
    ///
    /// This lets a note that is always targeted at a single network account derive its target from
    /// that account, while leaving the caller free to supply the target themselves, e.g. to pick a
    /// different execution hint, and to add any number of unrelated attachments in their own order.
    /// A caller-supplied target must agree with `expiry`, so the expiry the note carries is never
    /// quietly different from the one its builder was given.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - an attachment with the [`NetworkAccountTarget::ATTACHMENT_SCHEME`] does not decode as a
    ///   [`NetworkAccountTarget`], targets an account other than `target_id`, or expires at a block
    ///   other than `expiry`.
    /// - no such attachment is present and `target_id` is not
    ///   [`AccountType::Public`](miden_protocol::account::AccountType::Public), since a network
    ///   account must be public.
    /// - no such attachment is present and `expiry` is [`BlockNumber::GENESIS`], which encodes
    ///   "never expires" and so cannot express an expiry.
    pub(crate) fn ensure_presence(
        attachments: &mut Vec<NoteAttachment>,
        target_id: AccountId,
        expiry: Option<BlockNumber>,
    ) -> Result<(), NetworkAccountTargetError> {
        // Every attachment of the scheme is validated, so no attachment can claim a target or an
        // expiry other than the requested one.
        let mut is_present = false;
        for attachment in attachments
            .iter()
            .filter(|attachment| attachment.attachment_scheme() == Self::ATTACHMENT_SCHEME)
        {
            let attached = Self::try_from(attachment)?;
            if attached.target_id() != target_id {
                return Err(NetworkAccountTargetError::TargetMismatch {
                    expected: target_id,
                    actual: attached.target_id(),
                });
            }
            if attached.expiry() != expiry {
                return Err(NetworkAccountTargetError::ExpiryMismatch {
                    expected: expiry,
                    actual: attached.expiry(),
                });
            }

            is_present = true;
        }

        if !is_present {
            let target = Self::new(target_id, NoteExecutionHint::Always)?;
            let target = match expiry {
                Some(expiry) => target.with_expiry(expiry)?,
                None => target,
            };
            attachments.push(NoteAttachment::from(target));
        }

        Ok(())
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountId`] at which the note is targeted.
    pub fn target_id(&self) -> AccountId {
        self.target_id
    }

    /// Returns the [`NoteExecutionHint`] of the note.
    pub fn execution_hint(&self) -> NoteExecutionHint {
        self.exec_hint
    }

    /// Returns the last block at which the note may take effect, or `None` if it never expires.
    pub fn expiry(&self) -> Option<BlockNumber> {
        self.expiry
    }
}

impl From<NetworkAccountTarget> for NoteAttachment {
    fn from(network_attachment: NetworkAccountTarget) -> Self {
        let mut word = Word::empty();
        word[0] = network_attachment.target_id.suffix();
        word[1] = network_attachment.target_id.prefix().as_felt();
        word[2] = network_attachment.exec_hint.into();
        // `None` and `BlockNumber::GENESIS` share the zero encoding; `with_expiry` rejects the
        // latter so the two can never be confused.
        word[3] = network_attachment.expiry.map_or(Felt::from(0u32), Felt::from);

        NoteAttachment::with_word(NetworkAccountTarget::ATTACHMENT_SCHEME, word)
    }
}

impl TryFrom<&NoteAttachments> for NetworkAccountTarget {
    type Error = NetworkAccountTargetError;

    fn try_from(attachments: &NoteAttachments) -> Result<Self, Self::Error> {
        // Find the first matching attachment. In case of multiple network account target
        // attachments, we pick the first one as the canonical one.
        let attachment = attachments
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .ok_or_else(|| NetworkAccountTargetError::MissingAttachmentScheme)?;

        Self::try_from(attachment)
    }
}
impl TryFrom<&NoteAttachment> for NetworkAccountTarget {
    type Error = NetworkAccountTargetError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        if attachment.attachment_scheme() != Self::ATTACHMENT_SCHEME {
            return Err(NetworkAccountTargetError::AttachmentSchemeMismatch(
                attachment.attachment_scheme(),
            ));
        }

        let words = attachment.content().as_words();
        if words.len() != 1 {
            return Err(NetworkAccountTargetError::AttachmentContentNumWordsMismatch(
                attachment.content().num_words(),
            ));
        }
        let word = words[0];

        let id_suffix = word[0];
        let id_prefix = word[1];
        let exec_hint = word[2];
        let expiry = word[3];

        let target_id = AccountId::try_from_elements(id_suffix, id_prefix)
            .map_err(NetworkAccountTargetError::DecodeTargetId)?;

        let exec_hint = NoteExecutionHint::try_from(exec_hint.as_canonical_u64())
            .map_err(NetworkAccountTargetError::DecodeExecutionHint)?;

        let expiry = u32::try_from(expiry.as_canonical_u64())
            .map_err(|_| NetworkAccountTargetError::DecodeExpiryBlock(expiry.as_canonical_u64()))?;

        let target = NetworkAccountTarget::new(target_id, exec_hint)?;
        match expiry {
            0 => Ok(target),
            expiry => target.with_expiry(BlockNumber::from(expiry)),
        }
    }
}

// NETWORK ACCOUNT TARGET ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountTargetError {
    #[error("note attachments do not contain a network account target scheme")]
    MissingAttachmentScheme,
    #[error("target account ID must have public account type")]
    TargetNotPublic(AccountId),
    #[error("attached network account target {actual} does not match expected target {expected}")]
    TargetMismatch { expected: AccountId, actual: AccountId },
    #[error(
        "attached network account target expiry {actual:?} does not match expected expiry {expected:?}"
    )]
    ExpiryMismatch {
        expected: Option<BlockNumber>,
        actual: Option<BlockNumber>,
    },
    #[error("network account target expiry must not be the genesis block, which encodes no expiry")]
    ExpiryIsGenesis,
    #[error("failed to decode expiry block: {0} does not fit into a u32")]
    DecodeExpiryBlock(u64),
    #[error(
        "attachment scheme {0} did not match expected type {expected}",
        expected = NetworkAccountTarget::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    #[error("network account target expects attachment content with one word, got {0}")]
    AttachmentContentNumWordsMismatch(u16),
    #[error("failed to decode target account ID")]
    DecodeTargetId(#[source] AccountIdError),
    #[error("failed to decode execution hint")]
    DecodeExecutionHint(#[source] NoteError),
    #[error("network note must be public, but was {0:?}")]
    NoteNotPublic(NoteType),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::testing::account_id::AccountIdBuilder;

    use super::*;

    fn public_account_id() -> AccountId {
        AccountIdBuilder::new()
            .account_type(AccountType::Public)
            .build_with_rng(&mut rand::rng())
    }

    #[test]
    fn network_account_target_serde() -> anyhow::Result<()> {
        let id = public_account_id();
        let network_account_target = NetworkAccountTarget::new(id, NoteExecutionHint::Always)?;
        assert_eq!(
            network_account_target,
            NetworkAccountTarget::try_from(&NoteAttachment::from(network_account_target))?
        );

        Ok(())
    }

    /// A caller-supplied target for the same account is kept as-is, so its execution hint survives
    /// and no duplicate attachment is added.
    #[test]
    fn ensure_presence_keeps_matching_target() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let supplied = NetworkAccountTarget::new(target_id, NoteExecutionHint::None)?;
        let mut attachments = vec![NoteAttachment::from(supplied)];

        NetworkAccountTarget::ensure_presence(&mut attachments, target_id, None)?;

        assert_eq!(attachments.len(), 1);
        assert_eq!(NetworkAccountTarget::try_from(&attachments[0])?, supplied);

        Ok(())
    }

    /// A caller-supplied target for another account is rejected instead of being silently
    /// shadowed by the note's own target.
    #[test]
    fn ensure_presence_rejects_mismatched_target() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let other_id = public_account_id();
        let supplied = NetworkAccountTarget::new(other_id, NoteExecutionHint::Always)?;
        let mut attachments = vec![NoteAttachment::from(supplied)];

        let err =
            NetworkAccountTarget::ensure_presence(&mut attachments, target_id, None).unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::TargetMismatch { expected, actual }
                if expected == target_id && actual == other_id
        );

        Ok(())
    }

    /// The appended target is placed after the caller's attachments, leaving their order intact.
    #[test]
    fn ensure_presence_appends_missing_target() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let unrelated =
            NoteAttachment::with_word(NoteAttachmentScheme::new(64)?, Word::from([7u32, 0, 0, 0]));
        let mut attachments = vec![unrelated.clone()];

        NetworkAccountTarget::ensure_presence(&mut attachments, target_id, None)?;

        assert_eq!(
            attachments,
            vec![
                unrelated,
                NoteAttachment::from(NetworkAccountTarget::new(
                    target_id,
                    NoteExecutionHint::Always
                )?)
            ]
        );

        Ok(())
    }

    #[test]
    fn network_account_target_fails_on_private_target_account() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .account_type(AccountType::Private)
            .build_with_rng(&mut rand::rng());
        let err = NetworkAccountTarget::new(id, NoteExecutionHint::Always).unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::TargetNotPublic(account_id) if account_id == id
        );

        Ok(())
    }

    /// An expiry survives the round trip through the attachment encoding, so the block the script
    /// reads is the block the builder was given.
    #[test]
    fn expiry_round_trips_through_the_attachment() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?
            .with_expiry(BlockNumber::from(1234))?;

        let decoded = NetworkAccountTarget::try_from(&NoteAttachment::from(target))?;

        assert_eq!(decoded, target);
        assert_eq!(decoded.expiry(), Some(BlockNumber::from(1234)));

        Ok(())
    }

    /// A target built without an expiry decodes back as one, rather than as an expiry at the
    /// genesis block, which shares its zero encoding.
    #[test]
    fn absent_expiry_round_trips_as_absent() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?;

        let decoded = NetworkAccountTarget::try_from(&NoteAttachment::from(target))?;

        assert_eq!(decoded.expiry(), None);

        Ok(())
    }

    /// The genesis block is the "never expires" encoding, so it is rejected as an expiry rather
    /// than silently producing a note that never expires.
    #[test]
    fn with_expiry_rejects_the_genesis_block() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?;

        let err = target.with_expiry(BlockNumber::GENESIS).unwrap_err();

        assert_matches!(err, NetworkAccountTargetError::ExpiryIsGenesis);

        Ok(())
    }

    /// A hand-crafted attachment whose expiry felt exceeds a u32 is rejected on decoding, matching
    /// the `u32assert` the note script applies before comparing it against the block number.
    #[test]
    fn decoding_rejects_an_expiry_that_is_not_a_u32() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let mut word = Word::empty();
        word[0] = target_id.suffix();
        word[1] = target_id.prefix().as_felt();
        word[2] = NoteExecutionHint::Always.into();
        word[3] = Felt::new(u32::MAX as u64 + 1)?;
        let attachment = NoteAttachment::with_word(NetworkAccountTarget::ATTACHMENT_SCHEME, word);

        let err = NetworkAccountTarget::try_from(&attachment).unwrap_err();

        assert_matches!(err, NetworkAccountTargetError::DecodeExpiryBlock(_));

        Ok(())
    }

    /// A caller-supplied target whose expiry differs from the requested one is rejected, so a
    /// builder cannot be told one expiry and emit a note carrying another.
    #[test]
    fn ensure_presence_rejects_mismatched_expiry() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let supplied = NetworkAccountTarget::new(target_id, NoteExecutionHint::Always)?
            .with_expiry(BlockNumber::from(50))?;
        let mut attachments = vec![NoteAttachment::from(supplied)];

        let err = NetworkAccountTarget::ensure_presence(
            &mut attachments,
            target_id,
            Some(BlockNumber::from(70)),
        )
        .unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::ExpiryMismatch { expected, actual }
                if expected == Some(BlockNumber::from(70))
                    && actual == Some(BlockNumber::from(50))
        );

        Ok(())
    }

    /// The appended target carries the requested expiry.
    #[test]
    fn ensure_presence_appends_target_with_expiry() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let mut attachments = vec![];

        NetworkAccountTarget::ensure_presence(
            &mut attachments,
            target_id,
            Some(BlockNumber::from(99)),
        )?;

        assert_eq!(attachments.len(), 1);
        assert_eq!(
            NetworkAccountTarget::try_from(&attachments[0])?.expiry(),
            Some(BlockNumber::from(99))
        );

        Ok(())
    }
}

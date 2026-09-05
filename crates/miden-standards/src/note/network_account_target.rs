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
/// - 3rd felt: [32 zero bits | expiration_block_num (32 bits)]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAccountTarget {
    target_id: AccountId,
    exec_hint: NoteExecutionHint,
    expiration_block_num: Option<BlockNumber>,
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
    /// The returned target never expires; add an expiration block number with
    /// [`NetworkAccountTarget::with_expiration_block_num`].
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

        Ok(Self {
            target_id,
            exec_hint,
            expiration_block_num: None,
        })
    }

    /// Sets the block after which the note carrying this target can no longer take effect.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `expiration_block_num` is [`BlockNumber::GENESIS`], which encodes "never expires" and so
    ///   cannot express an expiration.
    pub fn with_expiration_block_num(
        mut self,
        expiration_block_num: BlockNumber,
    ) -> Result<Self, NetworkAccountTargetError> {
        if expiration_block_num == BlockNumber::GENESIS {
            return Err(NetworkAccountTargetError::ExpirationBlockNumIsGenesis);
        }

        self.expiration_block_num = Some(expiration_block_num);
        Ok(self)
    }

    /// Ensures `attachments` carries a [`NetworkAccountTarget`] for `target_id` expiring at
    /// `expiration_block_num`, appending one with [`NoteExecutionHint::Always`] if none is present.
    ///
    /// This lets a note that is always targeted at a single network account derive its target from
    /// that account, while leaving the caller free to supply the target themselves, e.g. to pick a
    /// different execution hint, and to add any number of unrelated attachments in their own order.
    /// A caller-supplied target must agree with `expiration_block_num`, so the expiration the note
    /// carries is never quietly different from the one its builder was given.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - an attachment with the [`NetworkAccountTarget::ATTACHMENT_SCHEME`] does not decode as a
    ///   [`NetworkAccountTarget`], targets an account other than `target_id`, or expires at a block
    ///   other than `expiration_block_num`.
    /// - no such attachment is present and `target_id` is not
    ///   [`AccountType::Public`](miden_protocol::account::AccountType::Public), since a network
    ///   account must be public.
    pub(crate) fn ensure_presence(
        attachments: &mut Vec<NoteAttachment>,
        target_id: AccountId,
        expiration_block_num: Option<BlockNumber>,
    ) -> Result<(), NetworkAccountTargetError> {
        if !Self::validate_target(attachments, target_id, expiration_block_num)? {
            let target = Self::new(target_id, NoteExecutionHint::Always)?;
            let target = match expiration_block_num {
                Some(expiration_block_num) => {
                    target.with_expiration_block_num(expiration_block_num)?
                },
                None => target,
            };
            attachments.push(NoteAttachment::from(target));
        }

        Ok(())
    }

    /// Behaves like [`Self::ensure_presence`], except that a non-public `target_id` is accepted
    /// without appending a target.
    ///
    /// A private account is never a network account, so it has no routing target to derive. This
    /// lets a note whose target may be either kind of account carry the target exactly when it is
    /// meaningful, while a caller-supplied target for another account is rejected either way.
    ///
    /// The target never expires: the notes deriving their target this way are not bound to an
    /// expiration by their script, so a caller-supplied target carrying one is rejected rather
    /// than left unenforced.
    ///
    /// # Errors
    ///
    /// Returns an error if an attachment with the [`NetworkAccountTarget::ATTACHMENT_SCHEME`] does
    /// not decode as a [`NetworkAccountTarget`], targets an account other than `target_id`, or
    /// carries an expiration block number.
    pub(crate) fn ensure_presence_if_public(
        attachments: &mut Vec<NoteAttachment>,
        target_id: AccountId,
    ) -> Result<(), NetworkAccountTargetError> {
        if target_id.is_public() {
            return Self::ensure_presence(attachments, target_id, None);
        }

        // No target is derived, but any attachment the caller supplied under the scheme is still
        // validated against `target_id`.
        Self::validate_target(attachments, target_id, None).map(|_| ())
    }

    /// Validates every attachment carrying the [`NetworkAccountTarget::ATTACHMENT_SCHEME`] against
    /// `target_id` and `expiration_block_num`, returning whether one of them is present.
    ///
    /// Every such attachment is validated, so none can claim a target or an expiration block
    /// number other than the requested one.
    ///
    /// # Errors
    ///
    /// Returns an error if such an attachment does not decode as a [`NetworkAccountTarget`], which
    /// is the case for one naming a non-public account, targets an account other than `target_id`,
    /// or expires at a block other than `expiration_block_num`.
    fn validate_target(
        attachments: &[NoteAttachment],
        target_id: AccountId,
        expiration_block_num: Option<BlockNumber>,
    ) -> Result<bool, NetworkAccountTargetError> {
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
            if attached.expiration_block_num() != expiration_block_num {
                return Err(NetworkAccountTargetError::ExpirationBlockNumMismatch {
                    expected: expiration_block_num,
                    actual: attached.expiration_block_num(),
                });
            }

            is_present = true;
        }

        Ok(is_present)
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
    pub fn expiration_block_num(&self) -> Option<BlockNumber> {
        self.expiration_block_num
    }
}

impl From<NetworkAccountTarget> for NoteAttachment {
    fn from(network_attachment: NetworkAccountTarget) -> Self {
        let mut word = Word::empty();
        word[0] = network_attachment.target_id.suffix();
        word[1] = network_attachment.target_id.prefix().as_felt();
        word[2] = network_attachment.exec_hint.into();
        word[3] = network_attachment.expiration_block_num.map_or(Felt::from(0u32), Felt::from);

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
        let expiration_block_num = word[3];

        let target_id = AccountId::try_from_elements(id_suffix, id_prefix)
            .map_err(NetworkAccountTargetError::DecodeTargetId)?;

        let exec_hint = NoteExecutionHint::try_from(exec_hint.as_canonical_u64())
            .map_err(NetworkAccountTargetError::DecodeExecutionHint)?;

        let expiration_block_num =
            u32::try_from(expiration_block_num.as_canonical_u64()).map_err(|_| {
                NetworkAccountTargetError::DecodeExpirationBlockNum(
                    expiration_block_num.as_canonical_u64(),
                )
            })?;

        let target = NetworkAccountTarget::new(target_id, exec_hint)?;
        match expiration_block_num {
            0 => Ok(target),
            expiration_block_num => {
                target.with_expiration_block_num(BlockNumber::from(expiration_block_num))
            },
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
        "attached network account target expiration block number {actual:?} does not match expected expiration block number {expected:?}"
    )]
    ExpirationBlockNumMismatch {
        expected: Option<BlockNumber>,
        actual: Option<BlockNumber>,
    },
    #[error(
        "network account target expiration block number must not be the genesis block, which encodes no expiration"
    )]
    ExpirationBlockNumIsGenesis,
    #[error("failed to decode expiration block number: {0} does not fit into a u32")]
    DecodeExpirationBlockNum(u64),
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

    /// A non-public target has no network routing target, so none is appended, but a
    /// caller-supplied target for another account is still rejected.
    #[test]
    fn ensure_presence_if_public_skips_private_target() -> anyhow::Result<()> {
        let private_id = AccountIdBuilder::new()
            .account_type(AccountType::Private)
            .build_with_rng(&mut rand::rng());
        let mut attachments = vec![];

        NetworkAccountTarget::ensure_presence_if_public(&mut attachments, private_id)?;
        assert!(attachments.is_empty());

        let other_id = public_account_id();
        let supplied = NetworkAccountTarget::new(other_id, NoteExecutionHint::Always)?;
        let mut attachments = vec![NoteAttachment::from(supplied)];

        let err = NetworkAccountTarget::ensure_presence_if_public(&mut attachments, private_id)
            .unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::TargetMismatch { expected, actual }
                if expected == private_id && actual == other_id
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

    #[test]
    fn expiration_block_num_round_trips_through_the_attachment() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?
            .with_expiration_block_num(BlockNumber::from(1234))?;

        let decoded = NetworkAccountTarget::try_from(&NoteAttachment::from(target))?;

        assert_eq!(decoded, target);
        assert_eq!(decoded.expiration_block_num(), Some(BlockNumber::from(1234)));

        Ok(())
    }

    #[test]
    fn absent_expiration_block_num_round_trips_as_absent() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?;

        let decoded = NetworkAccountTarget::try_from(&NoteAttachment::from(target))?;

        assert_eq!(decoded.expiration_block_num(), None);

        Ok(())
    }

    #[test]
    fn with_expiration_block_num_rejects_the_genesis_block() -> anyhow::Result<()> {
        let target = NetworkAccountTarget::new(public_account_id(), NoteExecutionHint::Always)?;

        let err = target.with_expiration_block_num(BlockNumber::GENESIS).unwrap_err();

        assert_matches!(err, NetworkAccountTargetError::ExpirationBlockNumIsGenesis);

        Ok(())
    }

    #[test]
    fn decoding_rejects_an_expiration_block_num_that_is_not_a_u32() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let mut word = Word::empty();
        word[0] = target_id.suffix();
        word[1] = target_id.prefix().as_felt();
        word[2] = NoteExecutionHint::Always.into();
        word[3] = Felt::new(u32::MAX as u64 + 1)?;
        let attachment = NoteAttachment::with_word(NetworkAccountTarget::ATTACHMENT_SCHEME, word);

        let err = NetworkAccountTarget::try_from(&attachment).unwrap_err();

        assert_matches!(err, NetworkAccountTargetError::DecodeExpirationBlockNum(_));

        Ok(())
    }

    /// A caller-supplied target whose expiration block number differs from the requested one is
    /// rejected.
    #[test]
    fn ensure_presence_rejects_mismatched_expiration_block_num() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let supplied = NetworkAccountTarget::new(target_id, NoteExecutionHint::Always)?
            .with_expiration_block_num(BlockNumber::from(50))?;
        let mut attachments = vec![NoteAttachment::from(supplied)];

        let err = NetworkAccountTarget::ensure_presence(
            &mut attachments,
            target_id,
            Some(BlockNumber::from(70)),
        )
        .unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::ExpirationBlockNumMismatch { expected, actual }
                if expected == Some(BlockNumber::from(70))
                    && actual == Some(BlockNumber::from(50))
        );

        Ok(())
    }

    /// The appended target carries the requested expiration block number.
    #[test]
    fn ensure_presence_appends_target_with_expiration_block_num() -> anyhow::Result<()> {
        let target_id = public_account_id();
        let mut attachments = vec![];

        NetworkAccountTarget::ensure_presence(
            &mut attachments,
            target_id,
            Some(BlockNumber::from(99)),
        )?;

        assert_eq!(attachments.len(), 1);
        assert_eq!(
            NetworkAccountTarget::try_from(&attachments[0])?.expiration_block_num(),
            Some(BlockNumber::from(99))
        );

        Ok(())
    }
}

use alloc::vec::Vec;

use crate::Felt;
use crate::account::AccountCode;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// Describes the update to the [`AccountCode`] of an account.
///
/// It carries the code of a new or upgraded account and is empty if the code did not change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountCodePatch {
    patch: Option<AccountCode>,
}

impl AccountCodePatch {
    /// The domain of the code section in the patch and delta commitments.
    const DOMAIN: Felt = Felt::from_u8(4);

    /// Returns a new [`AccountCodePatch`] that updates the account code to `code`, or an empty one
    /// if `code` is `None`.
    pub fn new(code: Option<AccountCode>) -> Self {
        Self { patch: code }
    }

    /// Returns `true` if this patch does not update the account code.
    pub fn is_empty(&self) -> bool {
        self.patch.is_none()
    }

    /// Returns a reference to the new account code, if present.
    pub fn as_code(&self) -> Option<&AccountCode> {
        self.patch.as_ref()
    }

    /// Consumes self and returns the new account code, if present.
    pub fn into_code(self) -> Option<AccountCode> {
        self.patch
    }

    /// Merges `other` into this patch. The code of `other`, if present, replaces the code of
    /// `self`, since `other` describes the later state.
    pub fn merge(&mut self, other: Self) {
        if other.patch.is_some() {
            self.patch = other.patch;
        }
    }

    /// Appends the code section of the patch and delta commitments to `elements`, if the code is
    /// present.
    pub(in crate::account) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        if let Some(code) = &self.patch {
            elements.extend_from_slice(&[Self::DOMAIN, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
            elements.extend_from_slice(code.commitment().as_elements());
        }
    }
}

impl Serializable for AccountCodePatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.patch.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.patch.get_size_hint()
    }
}

impl Deserializable for AccountCodePatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        <Option<AccountCode>>::read_from(source).map(Self::new)
    }
}

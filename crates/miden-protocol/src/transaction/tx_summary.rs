use alloc::vec::Vec;

use crate::account::AccountDelta;
use crate::block::BlockNumber;
use crate::crypto::SequentialCommit;
use crate::errors::TransactionSummaryError;
use crate::transaction::{InputNote, InputNotes, RawOutputNotes};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, WORD_SIZE, Word};

// TRANSACTION SUMMARY
// ================================================================================================

/// The summary of the changes that result from executing a transaction.
///
/// These are the account delta, the consumed and created notes, the block the summary binds (see
/// [`TransactionSummaryMetadata`]) together with that block's commitment, the transaction's
/// expiration block delta and the user-defined parameters (see [`TransactionSummaryUserParams`]).
///
/// Because this data is intended to be signed, the user-defined parameters give an account's
/// authentication procedure a way to bind arbitrary additional data to that signature, for example
/// a salt providing replay protection or a maximum fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: RawOutputNotes,
    block_number: BlockNumber,
    block_commitment: Word,
    expiration_delta: u16,
    user_params: TransactionSummaryUserParams,
}

impl TransactionSummary {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The layout version of the commitment preimage produced by
    /// [`TransactionSummary::to_elements`].
    pub(crate) const VERSION: u8 = 1;

    /// The index of the packed [`TransactionSummaryMetadata`] element in the commitment preimage.
    const METADATA_IDX: usize = 0;

    /// The number of elements in the preimage of a [`TransactionSummary`] commitment, i.e. the
    /// length of the vector returned by [`TransactionSummary::to_elements`]: the metadata element,
    /// the user parameters and the four commitment words.
    pub const NUM_ELEMENTS: usize = 1 + TransactionSummaryUserParams::NUM_ELEMENTS + 4 * WORD_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummary`] from the provided parts.
    ///
    /// `block_commitment` must be the commitment of the block identified by `block_number`, which
    /// is what the kernel guarantees for the summaries it builds.
    pub fn new(
        account_delta: AccountDelta,
        input_notes: InputNotes<InputNote>,
        output_notes: RawOutputNotes,
        block_number: BlockNumber,
        block_commitment: Word,
        expiration_delta: u16,
        user_params: TransactionSummaryUserParams,
    ) -> Self {
        Self {
            account_delta,
            input_notes,
            output_notes,
            block_number,
            block_commitment,
            expiration_delta,
            user_params,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account delta of this transaction summary.
    pub fn account_delta(&self) -> &AccountDelta {
        &self.account_delta
    }

    /// Returns the input notes of this transaction summary.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        &self.input_notes
    }

    /// Returns the output notes of this transaction summary.
    pub fn output_notes(&self) -> &RawOutputNotes {
        &self.output_notes
    }

    /// Returns the number of the block bound by this transaction summary.
    pub fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the commitment to the block bound by this transaction summary.
    pub fn block_commitment(&self) -> Word {
        self.block_commitment
    }

    /// Returns the expiration block delta of the transaction, or 0 if it has not been set.
    pub fn expiration_delta(&self) -> u16 {
        self.expiration_delta
    }

    /// Returns the metadata packed into the first element of the commitment preimage.
    pub fn metadata(&self) -> TransactionSummaryMetadata {
        TransactionSummaryMetadata::new(self.block_number, self.expiration_delta)
    }

    /// Returns the user-defined parameters bound by this transaction summary.
    pub fn user_params(&self) -> TransactionSummaryUserParams {
        self.user_params
    }

    /// Returns the elements this transaction summary commits to, i.e. the preimage of
    /// [`TransactionSummary::to_commitment`].
    ///
    /// The returned vector contains [`TransactionSummary::NUM_ELEMENTS`] elements laid out as:
    ///
    /// ```text
    /// [
    ///     [metadata, user_param0, user_param1, user_param2],
    ///     [user_param3, user_param4, user_param5, user_param6],
    ///     ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT,
    ///     OUTPUT_NOTES_COMMITMENT, BLOCK_COMMITMENT,
    /// ]
    /// ```
    ///
    /// The metadata element comes first so that a reader encounters the layout version before
    /// anything that depends on it.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Computes the commitment to the [`TransactionSummary`].
    ///
    /// This can be used to sign the transaction.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    // PARAMETER DECODING
    // --------------------------------------------------------------------------------------------

    /// Decodes the [`TransactionSummaryMetadata`] and the [`TransactionSummaryUserParams`] from the
    /// preimage of a transaction summary commitment.
    ///
    /// `elements` must be a full preimage as returned by [`TransactionSummary::to_elements`]. The
    /// four commitments are not decoded because they cannot be inverted: a caller reconstructing a
    /// summary from a preimage must rebuild the committed data from its own state, pass it to
    /// [`TransactionSummary::new`] alongside the decoded values and check the result against
    /// [`TransactionSummary::to_commitment`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `elements` does not contain exactly [`TransactionSummary::NUM_ELEMENTS`] elements.
    /// - the metadata element is not a valid [`TransactionSummaryMetadata`].
    pub fn try_params_from_elements(
        elements: &[Felt],
    ) -> Result<(TransactionSummaryMetadata, TransactionSummaryUserParams), TransactionSummaryError>
    {
        if elements.len() != Self::NUM_ELEMENTS {
            return Err(TransactionSummaryError::InvalidPreimageLength {
                actual: elements.len(),
                expected: Self::NUM_ELEMENTS,
            });
        }

        let metadata = TransactionSummaryMetadata::try_from_felt(elements[Self::METADATA_IDX])?;

        let user_params_end = Self::METADATA_IDX + 1 + TransactionSummaryUserParams::NUM_ELEMENTS;
        let user_params = elements[Self::METADATA_IDX + 1..user_params_end]
            .try_into()
            .expect("preimage length was validated above");

        Ok((metadata, TransactionSummaryUserParams::new(user_params)))
    }
}

/// The auth library absorbs the preimage word by word, so its length must stay word-aligned.
const _: () = assert!(TransactionSummary::NUM_ELEMENTS.is_multiple_of(WORD_SIZE));

impl SequentialCommit for TransactionSummary {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(Self::NUM_ELEMENTS);
        elements.push(self.metadata().to_felt());
        elements.extend_from_slice(self.user_params.as_elements());
        elements.extend_from_slice(self.account_delta.to_commitment().as_elements());
        elements.extend_from_slice(self.input_notes.commitment().as_elements());
        elements.extend_from_slice(self.output_notes.commitment().as_elements());
        elements.extend_from_slice(self.block_commitment.as_elements());
        elements
    }
}

impl Serializable for TransactionSummary {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_delta.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.block_number.write_into(target);
        self.block_commitment.write_into(target);
        self.expiration_delta.write_into(target);
        self.user_params.write_into(target);
    }
}

impl Deserializable for TransactionSummary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        let block_number = source.read()?;
        let block_commitment = source.read()?;
        let expiration_delta = source.read()?;
        let user_params = source.read()?;

        Ok(Self::new(
            account_delta,
            input_notes,
            output_notes,
            block_number,
            block_commitment,
            expiration_delta,
            user_params,
        ))
    }
}

// TRANSACTION SUMMARY METADATA
// ================================================================================================

/// The metadata packed into the first element of a [`TransactionSummary`] commitment preimage.
///
/// It binds the layout version of the preimage, the number of the block whose commitment the
/// summary contains, and the transaction's expiration block delta. Packing them into one element
/// keeps the preimage word-aligned without spending a word on three small values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSummaryMetadata {
    block_number: BlockNumber,
    expiration_delta: u16,
}

impl TransactionSummaryMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The bit offsets of the packed fields.
    const BLOCK_NUMBER_SHIFT: u32 = u8::BITS;
    const EXPIRATION_DELTA_SHIFT: u32 = Self::BLOCK_NUMBER_SHIFT + u32::BITS;

    /// The number of bits the packed metadata occupies.
    const NUM_BITS: u32 = Self::EXPIRATION_DELTA_SHIFT + u16::BITS;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates new metadata for the current version.
    pub fn new(block_number: BlockNumber, expiration_delta: u16) -> Self {
        Self { block_number, expiration_delta }
    }

    /// Decodes the metadata from its packed representation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `metadata` sets bits above the packed fields.
    /// - the encoded version is not supported.
    pub fn try_from_felt(metadata: Felt) -> Result<Self, TransactionSummaryError> {
        let packed = metadata.as_canonical_u64();
        if packed >> Self::NUM_BITS != 0 {
            return Err(TransactionSummaryError::MetadataOutOfRange(metadata));
        }

        let version = packed as u8;
        if version != TransactionSummary::VERSION {
            return Err(TransactionSummaryError::UnsupportedVersion {
                actual: version,
                expected: TransactionSummary::VERSION,
            });
        }

        // The `as` casts truncate to exactly the bits of the respective field.
        let block_number = BlockNumber::from((packed >> Self::BLOCK_NUMBER_SHIFT) as u32);
        let expiration_delta = (packed >> Self::EXPIRATION_DELTA_SHIFT) as u16;

        Ok(Self::new(block_number, expiration_delta))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of the block bound by the transaction summary.
    pub fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the expiration block delta of the transaction, or 0 if it has not been set.
    pub fn expiration_delta(&self) -> u16 {
        self.expiration_delta
    }

    /// Returns the packed representation of the metadata.
    pub fn to_felt(&self) -> Felt {
        let packed = (u64::from(self.expiration_delta) << Self::EXPIRATION_DELTA_SHIFT)
            | (u64::from(self.block_number.as_u32()) << Self::BLOCK_NUMBER_SHIFT)
            | u64::from(TransactionSummary::VERSION);

        // The packed value occupies NUM_BITS bits, so it is always a canonical field element.
        Felt::try_from(packed).expect("packed metadata should fit in felt")
    }
}

// TRANSACTION SUMMARY USER PARAMS
// ================================================================================================

/// The user-defined parameters bound by a [`TransactionSummary`].
///
/// These are [`TransactionSummaryUserParams::NUM_ELEMENTS`] elements supplied by the account's
/// authentication procedure when the summary is created.
///
/// The parameters are opaque: they are bound by the signature over the summary, but no meaning is
/// enforced for any of them at the protocol level. Any semantics - using some of them as a salt for
/// replay protection or binding a maximum fee, for example - must be implemented by the account
/// component that supplies them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionSummaryUserParams {
    elements: [Felt; Self::NUM_ELEMENTS],
}

impl TransactionSummaryUserParams {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of user-defined elements bound by a [`TransactionSummary`].
    pub const NUM_ELEMENTS: usize = 7;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates new [`TransactionSummaryUserParams`] from the provided elements.
    pub fn new(elements: [Felt; Self::NUM_ELEMENTS]) -> Self {
        Self { elements }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the user-defined elements in the order in which they are hashed into the
    /// [`TransactionSummary`] commitment.
    pub fn as_elements(&self) -> &[Felt; Self::NUM_ELEMENTS] {
        &self.elements
    }
}

impl Serializable for TransactionSummaryUserParams {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.elements.write_into(target);
    }
}

impl Deserializable for TransactionSummaryUserParams {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(source.read()?))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::ONE;
    use crate::account::{AccountId, AccountStoragePatch, AccountVaultDelta};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;

    /// The block number, expiration delta and user parameters used by the tests below.
    const BLOCK_NUMBER: u32 = 123;
    const EXPIRATION_DELTA: u16 = 42;
    const USER_PARAMS: [u32; TransactionSummaryUserParams::NUM_ELEMENTS] = [1, 2, 3, 4, 5, 6, 7];

    /// Builds a transaction summary over an empty delta and no notes, binding the parameters above.
    fn mock_summary() -> TransactionSummary {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let account_delta = AccountDelta::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            None,
            ONE,
        )
        .unwrap();

        TransactionSummary::new(
            account_delta,
            InputNotes::new(Vec::new()).unwrap(),
            RawOutputNotes::new(Vec::new()).unwrap(),
            BlockNumber::from(BLOCK_NUMBER),
            Word::from([9u32, 10, 11, 12].map(Felt::from)),
            EXPIRATION_DELTA,
            TransactionSummaryUserParams::new(USER_PARAMS.map(Felt::from)),
        )
    }

    #[test]
    fn tx_summary_params_element_roundtrip() -> anyhow::Result<()> {
        let summary = mock_summary();
        let elements = summary.to_elements();

        assert_eq!(elements.len(), TransactionSummary::NUM_ELEMENTS);
        assert_eq!(
            &elements[..TransactionSummary::METADATA_IDX + 1 + USER_PARAMS.len()],
            [
                summary.metadata().to_felt(),
                Felt::from(USER_PARAMS[0]),
                Felt::from(USER_PARAMS[1]),
                Felt::from(USER_PARAMS[2]),
                Felt::from(USER_PARAMS[3]),
                Felt::from(USER_PARAMS[4]),
                Felt::from(USER_PARAMS[5]),
                Felt::from(USER_PARAMS[6]),
            ]
        );

        let (metadata, user_params) = TransactionSummary::try_params_from_elements(&elements)?;
        assert_eq!(metadata, summary.metadata());
        assert_eq!(user_params, summary.user_params());

        Ok(())
    }

    #[test]
    fn tx_summary_serde_roundtrip() -> anyhow::Result<()> {
        let summary = mock_summary();

        let deserialized = TransactionSummary::read_from_bytes(&summary.to_bytes())?;
        assert_eq!(deserialized, summary);

        Ok(())
    }

    #[rstest::rstest]
    #[case::genesis(0, 0)]
    #[case::typical(BLOCK_NUMBER, EXPIRATION_DELTA)]
    #[case::maximum(u32::MAX, u16::MAX)]
    fn tx_summary_metadata_roundtrip(
        #[case] block_number: u32,
        #[case] expiration_delta: u16,
    ) -> anyhow::Result<()> {
        let metadata =
            TransactionSummaryMetadata::new(BlockNumber::from(block_number), expiration_delta);

        let decoded = TransactionSummaryMetadata::try_from_felt(metadata.to_felt())?;
        assert_eq!(decoded, metadata);
        assert_eq!(decoded.block_number().as_u32(), block_number);
        assert_eq!(decoded.expiration_delta(), expiration_delta);

        Ok(())
    }

    #[test]
    fn tx_summary_metadata_rejects_unsupported_version() {
        let metadata = mock_summary().metadata().to_felt().as_canonical_u64();
        let unsupported_version = u64::from(TransactionSummary::VERSION) + 1;

        assert_matches!(
            TransactionSummaryMetadata::try_from_felt(Felt::new_unchecked(
                metadata - u64::from(TransactionSummary::VERSION) + unsupported_version
            )),
            Err(TransactionSummaryError::UnsupportedVersion { actual, expected })
                if u64::from(actual) == unsupported_version
                    && expected == TransactionSummary::VERSION
        );
    }

    #[test]
    fn tx_summary_metadata_rejects_bits_above_packed_fields() {
        let out_of_range = 1u64 << TransactionSummaryMetadata::NUM_BITS;

        assert_matches!(
            TransactionSummaryMetadata::try_from_felt(Felt::new_unchecked(
                out_of_range | u64::from(TransactionSummary::VERSION)
            )),
            Err(TransactionSummaryError::MetadataOutOfRange(_))
        );
    }

    #[test]
    fn tx_summary_params_reject_preimage_of_wrong_length() {
        let mut elements = mock_summary().to_elements();
        elements.pop();

        assert_matches!(
            TransactionSummary::try_params_from_elements(&elements),
            Err(TransactionSummaryError::InvalidPreimageLength { actual, expected })
                if actual == TransactionSummary::NUM_ELEMENTS - 1
                    && expected == TransactionSummary::NUM_ELEMENTS
        );
    }
}

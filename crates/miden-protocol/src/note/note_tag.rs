use core::fmt;

use miden_crypto::Felt;

use super::{
    AccountId,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteError,
    NoteType,
    Serializable,
};
use crate::account::AccountStorageMode;

// CONSTANTS
// ================================================================================================
const NETWORK_EXECUTION: u8 = 0;
const LOCAL_EXECUTION: u8 = 1;

// The 2 most significant bits are set to `0b00`.
const NETWORK_ACCOUNT: u32 = 0;
// The 2 most significant bits are set to `0b01`.
const NETWORK_PUBLIC_USECASE: u32 = 0x4000_0000;
// The 2 most significant bits are set to `0b10`.
const LOCAL_PUBLIC_ANY: u32 = 0x8000_0000;
// The 2 most significant bits are set to `0b11`.
const LOCAL_ANY: u32 = 0xc000_0000;

/// [super::Note]'s execution mode hints.
///
/// The execution hints are _not_ enforced, therefore function only as hints. For example, if a
/// note's tag is created with the [NoteExecutionMode::Network], further validation is necessary to
/// check the account_id is known, that the account's state is public on chain, and the account is
/// controlled by the network.
///
/// The goal of the hint is to allow for a network node to quickly filter notes that are not
/// intended for network execution, and skip the validation steps mentioned above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteExecutionMode {
    Network = NETWORK_EXECUTION,
    Local = LOCAL_EXECUTION,
}

// NOTE TAG
// ================================================================================================

/// [NoteTag]`s are best effort filters for notes registered with the network.
///
/// Tags are light-weight values used to speed up queries. The 2 most significant bits of the tags
/// have the following interpretation:
///
/// | Prefix | Name                   | [`NoteExecutionMode`] | Target                   | Allowed [`NoteType`] |
/// | :----: | :--------------------: | :-------------------: | :----------------------: | :------------------: |
/// | `0b00` | `NetworkAccount`       | Network               | Network Account          | [`NoteType::Public`] |
/// | `0b01` | `NetworkUseCase`       | Network               | Use case                 | [`NoteType::Public`] |
/// | `0b10` | `LocalPublicAny`       | Local                 | Any                      | [`NoteType::Public`] |
/// | `0b11` | `LocalAny`             | Local                 | Any                      | Any                  |
///
/// Where:
///
/// - [`NoteExecutionMode`] is set to [`NoteExecutionMode::Network`] to hint a [`Note`](super::Note)
///   should be consumed by the network. These notes will be further validated and if possible
///   consumed by it.
/// - Target describes how to further interpret the bits in the tag.
///   - For tags with a specific target, the rest of the tag is interpreted as a partial
///     [`AccountId`]. For network accounts these are the first 30 bits of the ID while for local
///     account targets, the first 14 bits are used - a trade-off between privacy and uniqueness.
///   - For use case values, the meaning of the rest of the tag is not specified by the protocol and
///     can be used by applications built on top of the rollup.
///
/// The note type is the only value enforced by the protocol. The rationale is that any note
/// intended to be consumed by the network must be public to have all the details available. The
/// public note for local execution is intended to allow users to search for notes that can be
/// consumed right away, without requiring an off-band communication channel.
///
/// **Note on Type Safety**
///
/// Each enum variant contains the raw encoding of the note tag, where the first two bits
/// _should_ correspond to the variant's prefix (as defined in the table above). However, because
/// enum variants are always public, it is possible to instantiate this enum where this invariant
/// does not hold, e.g. `NoteTag::NetworkAccount(0b11...)`. For that reason, the enum variants
/// should take precedence in case of such a mismatch and the inner value **should not be accessed
/// directly**. Instead, only rely on [`NoteTag::as_u32`] to access the encoded value, which will
/// always return the correct value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NoteTag {
    /// Represents a tag for a note intended for network execution, targeted at a network account.
    /// The note must be public.
    NetworkAccount(u32),
    /// Represents a tag for a note intended for network execution for a public use case. The note
    /// must be public.
    NetworkUseCase(u16, u16),
    /// Represents a tag for a note intended for local execution.
    ///
    /// This is used for two purposes:
    /// - A public use case.
    /// - A note targeted at any type of account.
    ///
    /// In all cases, the note must be **public**.
    LocalPublicAny(u32),
    /// Represents a tag for a note intended for local execution.
    ///
    /// This is used for two purposes:
    /// - A private use case.
    /// - A note targeted at any type of account.
    ///
    /// In all cases, the note can be of any type.
    LocalAny(u32),
}

impl NoteTag {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The exponent of the maximum allowed use case id. In other words, 2^exponent is the maximum
    /// allowed use case id.
    pub(crate) const MAX_USE_CASE_ID_EXPONENT: u8 = 14;
    /// The default note tag length for an account ID with local execution.
    pub const DEFAULT_LOCAL_TAG_LENGTH: u8 = 14;
    /// The default note tag length for an account ID with network execution.
    pub const DEFAULT_NETWORK_TAG_LENGTH: u8 = 30;
    /// The maximum number of bits that can be encoded into the tag for local accounts.
    pub const MAX_LOCAL_TAG_LENGTH: u8 = 30;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [NoteTag::NetworkAccount] or [NoteTag::LocalAny] instantiated from the
    /// specified account ID.
    ///
    /// The tag is constructed as follows:
    ///
    /// - For local execution ([`AccountStorageMode::Private`] or [`AccountStorageMode::Public`]),
    ///   the two most significant bits are set to `0b11`, which allows for any note type to be
    ///   used. The following 14 bits are set to the most significant bits of the account ID, and
    ///   the remaining 16 bits are set to 0.
    /// - For network execution ([`AccountStorageMode::Network`]), the most significant bits are set
    ///   to `0b00` and the remaining bits are set to the 30 most significant bits of the account
    ///   ID.
    pub fn from_account_id(account_id: AccountId) -> Self {
        match account_id.storage_mode() {
            AccountStorageMode::Network => Self::from_network_account_id(account_id),
            AccountStorageMode::Private | AccountStorageMode::Public => {
                // safe to unwrap since DEFAULT_LOCAL_TAG_LENGTH < MAX_LOCAL_TAG_LENGTH
                Self::from_local_account_id(account_id, Self::DEFAULT_LOCAL_TAG_LENGTH).unwrap()
            },
        }
    }

    /// Constructs a [`NoteTag::LocalAny`] from the given `account_id` and `tag_len`.
    ///
    /// The tag is constructed as follows:
    ///
    /// - The two most significant bits are set to `0b11` to indicate a [LOCAL_ANY] tag.
    /// - The next `tag_len` bits are set to the most significant bits of the account ID prefix.
    /// - The remaining bits are set to zero.
    ///
    /// # Errors
    ///
    /// Returns an error if `tag_len` is larger than [`NoteTag::MAX_LOCAL_TAG_LENGTH`].
    pub(crate) fn from_local_account_id(
        account_id: AccountId,
        tag_len: u8,
    ) -> Result<Self, NoteError> {
        if tag_len > Self::MAX_LOCAL_TAG_LENGTH {
            return Err(NoteError::NoteTagLengthTooLarge(tag_len));
        }

        let prefix_id: u64 = account_id.prefix().into();

        // Shift the high bits of the account ID such that they are laid out as:
        // [34 zero bits | remaining high bits (30 bits)].
        let high_bits = prefix_id >> 34;

        // This is equivalent to the following layout, interpreted as a u32:
        // [2 zero bits | remaining high bits (30 bits)].
        let high_bits = high_bits as u32;

        // Select the top `tag_len` bits of the account ID, i.e.:
        // [2 zero bits | remaining high bits (tag_len bits) | (30 - tag_len) zero bits].
        let high_bits = high_bits & (u32::MAX << (32 - 2 - tag_len));

        // Set the local execution tag in the two most significant bits.
        Ok(Self::LocalAny(LOCAL_ANY | high_bits))
    }

    /// Constructs a [`NoteTag::NetworkAccount`] from the specified `account_id`.
    ///
    /// The tag is constructed as follows:
    ///
    /// - The two most significant bits are set to `0b00` to indicate a [NETWORK_ACCOUNT] tag.
    /// - The remaining bits are set to the 30 most significant bits of the account ID.
    pub(crate) fn from_network_account_id(account_id: AccountId) -> Self {
        let prefix_id: u64 = account_id.prefix().into();

        // Shift the high bits of the account ID such that they are laid out as:
        // [34 zero bits | remaining high bits (30 bits)].
        let high_bits = prefix_id >> 34;

        // This is equivalent to the following layout, interpreted as a u32:
        // [2 zero bits | remaining high bits (30 bits)].
        // The two most significant zero bits match the tag we need for network
        Self::NetworkAccount(high_bits as u32)
    }

    /// Returns a new [`NoteTag::NetworkUseCase`] or [`NoteTag::LocalPublicAny`]
    /// instantiated for a custom use case which requires a public note.
    ///
    /// The public use_case tag requires a [NoteType::Public] note.
    ///
    /// The two high bits are set to the `b10` or `b01` depending on the execution hint, the next 14
    /// bits are set to the `use_case_id`, and the low 16 bits are set to `payload`.
    ///
    /// # Errors
    ///
    /// - If `use_case_id` is larger than or equal to $2^{14}$.
    pub fn for_public_use_case(
        use_case_id: u16,
        payload: u16,
        execution: NoteExecutionMode,
    ) -> Result<Self, NoteError> {
        if (use_case_id >> 14) != 0 {
            return Err(NoteError::NoteTagUseCaseTooLarge(use_case_id));
        }

        match execution {
            NoteExecutionMode::Network => {
                let use_case_bits = (NETWORK_PUBLIC_USECASE >> 16) as u16 | use_case_id;
                Ok(Self::NetworkUseCase(use_case_bits, payload))
            },
            NoteExecutionMode::Local => {
                let tag_u32 = LOCAL_PUBLIC_ANY | ((use_case_id as u32) << 16) | (payload as u32);
                Ok(Self::LocalPublicAny(tag_u32))
            },
        }
    }

    /// Returns a new [`NoteTag::LocalAny`] instantiated for a custom local use case.
    ///
    /// The local use_case tag is the only tag type that allows for [NoteType::Private] notes.
    ///
    /// The two high bits are set to the `b11`, the next 14 bits are set to the `use_case_id`, and
    /// the low 16 bits are set to `payload`.
    ///
    /// # Errors
    ///
    /// - If `use_case_id` is larger than or equal to 2^14.
    pub fn for_local_use_case(use_case_id: u16, payload: u16) -> Result<Self, NoteError> {
        if (use_case_id >> NoteTag::MAX_USE_CASE_ID_EXPONENT) != 0 {
            return Err(NoteError::NoteTagUseCaseTooLarge(use_case_id));
        }

        let use_case_bits = (use_case_id as u32) << 16;
        let payload_bits = payload as u32;

        Ok(Self::LocalAny(LOCAL_ANY | use_case_bits | payload_bits))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns true if the note is intended for execution by a specific account, i.e.
    /// [`NoteTag::NetworkAccount`]
    pub fn is_single_target(&self) -> bool {
        matches!(self, NoteTag::NetworkAccount(_))
    }

    /// Returns note execution mode defined by this tag.
    ///
    /// If the most significant bit of the tag is 0 the note is intended for local execution;
    /// otherwise, the note is intended for network execution.
    pub fn execution_mode(&self) -> NoteExecutionMode {
        match self {
            NoteTag::NetworkAccount(_) | NoteTag::NetworkUseCase(..) => NoteExecutionMode::Network,
            NoteTag::LocalAny(_) | NoteTag::LocalPublicAny(..) => NoteExecutionMode::Local,
        }
    }

    /// Returns the inner u32 value of this tag.
    pub fn as_u32(&self) -> u32 {
        // Note that we always set the two most significant bits to the prefix corresponding to the
        // enum variant. See the note on type safety on the NoteTag docs.

        /// Masks out the two most significant bits, leaving all lower bits untouched.
        const LOW_BITS_MASK: u32 = 0x3fff_ffff;
        match self {
            NoteTag::NetworkAccount(tag) => *tag & LOW_BITS_MASK,
            NoteTag::NetworkUseCase(use_case_bits, payload_bits) => {
                ((*use_case_bits as u32) << 16 | *payload_bits as u32) & LOW_BITS_MASK
                    | NETWORK_PUBLIC_USECASE
            },
            NoteTag::LocalPublicAny(tag) => (*tag & LOW_BITS_MASK) | LOCAL_PUBLIC_ANY,
            NoteTag::LocalAny(tag) => (*tag & LOW_BITS_MASK) | LOCAL_ANY,
        }
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns an error if this tag is not consistent with the specified note type, and self
    /// otherwise.
    pub fn validate(&self, note_type: NoteType) -> Result<Self, NoteError> {
        if self.execution_mode() == NoteExecutionMode::Network && note_type != NoteType::Public {
            return Err(NoteError::NetworkExecutionRequiresPublicNote(note_type));
        }

        // Ensure the note is public if the note tag requires it.
        if self.requires_public_note() && note_type != NoteType::Public {
            Err(NoteError::PublicNoteRequired(note_type))
        } else {
            Ok(*self)
        }
    }

    /// Returns `true` if the note tag requires a public note.
    fn requires_public_note(&self) -> bool {
        matches!(
            self,
            NoteTag::NetworkAccount(_) | NoteTag::NetworkUseCase(_, _) | NoteTag::LocalPublicAny(_)
        )
    }
}

impl fmt::Display for NoteTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_u32())
    }
}

// CONVERSIONS INTO NOTE TAG
// ================================================================================================

impl From<u32> for NoteTag {
    fn from(value: u32) -> Self {
        // Mask out the two most significant bits.
        match value & 0xc0000000 {
            NETWORK_ACCOUNT => Self::NetworkAccount(value),
            NETWORK_PUBLIC_USECASE => Self::NetworkUseCase((value >> 16) as u16, value as u16),
            LOCAL_ANY => Self::LocalAny(value),
            LOCAL_PUBLIC_ANY => Self::LocalPublicAny(value),
            _ => {
                // This branch should be unreachable because `prefix` is derived from
                // the top 2 bits of a u32, which can only be 0, 1, 2, or 3.
                unreachable!("Invalid value encountered: {:b}", value);
            },
        }
    }
}

// CONVERSIONS FROM NOTE TAG
// ================================================================================================

impl From<NoteTag> for u32 {
    fn from(value: NoteTag) -> Self {
        value.as_u32()
    }
}

impl From<NoteTag> for Felt {
    fn from(value: NoteTag) -> Self {
        Felt::new(u64::from(value.as_u32()))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteTag {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_u32().write_into(target);
    }
}

impl Deserializable for NoteTag {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = u32::read_from(source)?;
        Ok(Self::from(tag))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;

    use super::{NoteExecutionMode, NoteTag};
    use crate::NoteError;
    use crate::account::AccountId;
    use crate::note::NoteType;
    use crate::note::note_tag::{
        LOCAL_ANY,
        LOCAL_PUBLIC_ANY,
        NETWORK_ACCOUNT,
        NETWORK_PUBLIC_USECASE,
    };
    use crate::testing::account_id::{
        ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET,
        ACCOUNT_ID_NETWORK_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE_ON_CHAIN_2,
        ACCOUNT_ID_SENDER,
    };

    #[test]
    fn from_account_id() {
        let private_accounts = [
            AccountId::try_from(ACCOUNT_ID_SENDER).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap(),
            AccountId::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap(),
        ];
        let public_accounts = [
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap(),
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2).unwrap(),
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE).unwrap(),
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE_ON_CHAIN_2)
                .unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET).unwrap(),
            AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1).unwrap(),
        ];
        let network_accounts = [
            AccountId::try_from(ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE).unwrap(),
            AccountId::try_from(ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET).unwrap(),
            AccountId::try_from(ACCOUNT_ID_NETWORK_NON_FUNGIBLE_FAUCET).unwrap(),
        ];

        for account_id in network_accounts {
            let tag = NoteTag::from_account_id(account_id);
            assert!(tag.is_single_target());
            assert_eq!(tag.execution_mode(), NoteExecutionMode::Network);

            tag.validate(NoteType::Public)
                .expect("network execution should require notes to be public");
            assert_matches!(
                tag.validate(NoteType::Private),
                Err(NoteError::NetworkExecutionRequiresPublicNote(NoteType::Private))
            );
            assert_matches!(
                tag.validate(NoteType::Encrypted),
                Err(NoteError::NetworkExecutionRequiresPublicNote(NoteType::Encrypted))
            );
        }

        for account_id in private_accounts {
            let tag = NoteTag::from_account_id(account_id);
            assert!(!tag.is_single_target());
            assert_eq!(tag.execution_mode(), NoteExecutionMode::Local);

            // for local execution[`NoteExecutionMode::Local`], all notes are allowed
            tag.validate(NoteType::Public)
                .expect("local execution should support public notes");
            tag.validate(NoteType::Private)
                .expect("local execution should support private notes");
            tag.validate(NoteType::Encrypted)
                .expect("local execution should support encrypted notes");
        }

        for account_id in public_accounts {
            let tag = NoteTag::from_account_id(account_id);
            assert!(!tag.is_single_target());
            assert_eq!(tag.execution_mode(), NoteExecutionMode::Local);

            // for local execution[`NoteExecutionMode::Local`], all notes are allowed
            tag.validate(NoteType::Public)
                .expect("local execution should support public notes");
            tag.validate(NoteType::Private)
                .expect("local execution should support private notes");
            tag.validate(NoteType::Encrypted)
                .expect("local execution should support encrypted notes");
        }

        for account_id in network_accounts {
            let tag = NoteTag::from_account_id(account_id);
            assert!(tag.is_single_target());
            assert_eq!(tag.execution_mode(), NoteExecutionMode::Network);

            // for network execution[`NoteExecutionMode::Network`], only public notes are allowed
            tag.validate(NoteType::Public)
                .expect("network execution should support public notes");
            assert_matches!(
                tag.validate(NoteType::Private),
                Err(NoteError::NetworkExecutionRequiresPublicNote(NoteType::Private))
            );
            assert_matches!(
                tag.validate(NoteType::Encrypted),
                Err(NoteError::NetworkExecutionRequiresPublicNote(NoteType::Encrypted))
            );
        }
    }

    #[test]
    fn from_private_account_id() {
        /// Private Account ID with the following bit pattern in the first and second byte:
        /// 0b11001100_01010101
        ///   ^^^^^^^^ ^^^^^^  <- 14 bits of the local tag.
        const PRIVATE_ACCOUNT_INT: u128 = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE
            | 0x0055_0000_0000_0000_0000_0000_0000_0000;
        let private_account_id = AccountId::try_from(PRIVATE_ACCOUNT_INT).unwrap();

        // Expected private tag of variant `NoteTag::LocalAny`.
        let expected_private_tag = 0b11110011_00010101_00000000_00000000;

        assert_eq!(NoteTag::from_account_id(private_account_id).as_u32(), expected_private_tag);
    }

    #[test]
    fn from_public_account_id() {
        /// Public Account ID with the following bit pattern in the first and second byte:
        /// 0b10101010_01010101
        ///   ^^^^^^^^ ^^^^^^  <- 14 bits of the local tag.
        const PUBLIC_ACCOUNT_INT: u128 = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
            | 0x0055_ccaa_0000_0000_0000_0000_0000_0000;
        let public_account_id = AccountId::try_from(PUBLIC_ACCOUNT_INT).unwrap();

        // Expected public tag of variant `NoteTag::LocalAny`.
        let expected_public_local_tag = 0b11101010_10010101_00000000_00000000u32;

        assert_eq!(NoteTag::from_account_id(public_account_id).as_u32(), expected_public_local_tag);
    }

    #[test]
    fn from_network_account_id() {
        /// Network Account ID with the following bit pattern in the first four bytes:
        /// 0b10101010_11001100_01110111_11001100
        ///   ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^  <- 30 bits of the network tag.
        const NETWORK_ACCOUNT_INT: u128 = ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE
            | 0x00cc_77cc_0000_0000_0000_0000_0000_0000;
        let network_account_id = AccountId::try_from(NETWORK_ACCOUNT_INT).unwrap();

        // Expected network tag of variant `NoteTag::NetworkAccount`.
        let expected_network_tag = 0b00101010_10110011_00011101_11110011;

        assert_eq!(NoteTag::from_account_id(network_account_id).as_u32(), expected_network_tag);
    }

    #[test]
    fn for_public_use_case() {
        // NETWORK
        // ----------------------------------------------------------------------------------------
        let tag = NoteTag::for_public_use_case(0b0, 0b0, NoteExecutionMode::Network).unwrap();
        assert_eq!(tag.as_u32(), 0b01000000_00000000_00000000_00000000u32);

        tag.validate(NoteType::Public).unwrap();

        assert_matches!(
            tag.validate(NoteType::Private).unwrap_err(),
            NoteError::NetworkExecutionRequiresPublicNote(NoteType::Private)
        );
        assert_matches!(
            tag.validate(NoteType::Encrypted).unwrap_err(),
            NoteError::NetworkExecutionRequiresPublicNote(NoteType::Encrypted)
        );

        let tag = NoteTag::for_public_use_case(0b1, 0b0, NoteExecutionMode::Network).unwrap();
        assert_eq!(tag.as_u32(), 0b01000000_00000001_00000000_00000000u32);

        let tag = NoteTag::for_public_use_case(0b0, 0b1, NoteExecutionMode::Network).unwrap();
        assert_eq!(tag.as_u32(), 0b01000000_00000000_00000000_00000001u32);

        let tag = NoteTag::for_public_use_case(1 << 13, 0b0, NoteExecutionMode::Network).unwrap();
        assert_eq!(tag.as_u32(), 0b01100000_00000000_00000000_00000000u32);

        // LOCAL
        // ----------------------------------------------------------------------------------------
        let tag = NoteTag::for_public_use_case(0b0, 0b0, NoteExecutionMode::Local).unwrap();
        assert_eq!(tag.as_u32(), 0b10000000_00000000_00000000_00000000u32);

        tag.validate(NoteType::Public).unwrap();
        assert_matches!(
            tag.validate(NoteType::Private).unwrap_err(),
            NoteError::PublicNoteRequired(NoteType::Private)
        );
        assert_matches!(
            tag.validate(NoteType::Encrypted).unwrap_err(),
            NoteError::PublicNoteRequired(NoteType::Encrypted)
        );

        let tag = NoteTag::for_public_use_case(0b0, 0b1, NoteExecutionMode::Local).unwrap();
        assert_eq!(tag.as_u32(), 0b10000000_00000000_00000000_00000001u32);

        let tag = NoteTag::for_public_use_case(0b1, 0b0, NoteExecutionMode::Local).unwrap();
        assert_eq!(tag.as_u32(), 0b10000000_00000001_00000000_00000000u32);

        let tag = NoteTag::for_public_use_case(1 << 13, 0b0, NoteExecutionMode::Local).unwrap();
        assert_eq!(tag.as_u32(), 0b10100000_00000000_00000000_00000000u32);

        assert_matches!(
          NoteTag::for_public_use_case(1 << 15, 0b0, NoteExecutionMode::Local).unwrap_err(),
          NoteError::NoteTagUseCaseTooLarge(use_case) if use_case == 1 << 15
        );
        assert_matches!(
          NoteTag::for_public_use_case(1 << 14, 0b0, NoteExecutionMode::Local).unwrap_err(),
          NoteError::NoteTagUseCaseTooLarge(use_case) if use_case == 1 << 14
        );
    }

    #[test]
    fn for_private_use_case() {
        let tag = NoteTag::for_local_use_case(0b0, 0b0).unwrap();
        assert_eq!(
            tag.as_u32() >> 30,
            LOCAL_ANY >> 30,
            "local use case prefix should be local any"
        );
        assert_eq!(tag.as_u32(), 0b11000000_00000000_00000000_00000000u32);

        tag.validate(NoteType::Public)
            .expect("local execution should support public notes");
        tag.validate(NoteType::Private)
            .expect("local execution should support private notes");
        tag.validate(NoteType::Encrypted)
            .expect("local execution should support encrypted notes");

        let tag = NoteTag::for_local_use_case(0b0, 0b1).unwrap();
        assert_eq!(tag.as_u32(), 0b11000000_00000000_00000000_00000001u32);

        let tag = NoteTag::for_local_use_case(0b1, 0b0).unwrap();
        assert_eq!(tag.as_u32(), 0b11000000_00000001_00000000_00000000u32);

        let tag = NoteTag::for_local_use_case(1 << 13, 0b0).unwrap();
        assert_eq!(tag.as_u32(), 0b11100000_00000000_00000000_00000000u32);

        assert_matches!(
          NoteTag::for_local_use_case(1 << 15, 0b0).unwrap_err(),
          NoteError::NoteTagUseCaseTooLarge(use_case) if use_case == 1 << 15
        );
        assert_matches!(
          NoteTag::for_local_use_case(1 << 14, 0b0).unwrap_err(),
          NoteError::NoteTagUseCaseTooLarge(use_case) if use_case == 1 << 14
        );
    }

    /// Tests that as_u32 returns the correct prefix independent of the inner value.
    #[test]
    fn note_tag_as_u32() {
        const HIGH_BITS_MASK: u32 = 0xc000_0000;

        assert_eq!(NoteTag::NetworkAccount(u32::MAX).as_u32() & HIGH_BITS_MASK, NETWORK_ACCOUNT);
        assert_eq!(
            NoteTag::NetworkUseCase(u16::MAX, u16::MAX).as_u32() & HIGH_BITS_MASK,
            NETWORK_PUBLIC_USECASE
        );
        assert_eq!(NoteTag::LocalPublicAny(u32::MAX).as_u32() & HIGH_BITS_MASK, LOCAL_PUBLIC_ANY);
        assert_eq!(NoteTag::LocalAny(0).as_u32() & HIGH_BITS_MASK, LOCAL_ANY);
    }
}

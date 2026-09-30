//! Circle's DepositIntent: the message that authorizes one mint, and the bytes it travels in.
//!
//! The wire form is a fixed 240-byte big-endian header followed by variable-length hookData. On
//! Miden it is carried as u32-little-endian-packed field elements, four wire bytes per element, so
//! the header occupies exactly 60 of them. Every field sits at a fixed offset, which is what lets
//! the MASM writer address fields directly instead of encoding sequentially.
//!
//! This module owns the BYTE format, in both directions: [`Serializable`] writes it and
//! [`Deserializable`] reads it. Its sibling `mint_intent` owns the felt format, and the two
//! conversions between the types. Nothing outside this module reads a wire offset — every access
//! goes through [`DepositIntentField::offset`].
//!
//! Decoding owns the STRUCTURAL checks — the ones answering "is this a well-formed DepositIntent
//! at all": the magic sentinel, the version, that the payload is not truncated, that the declared
//! total length equals 240 plus the declared hookData length, and that the amount, `localToken`
//! and `localDepositor` fields are non-zero.
//!
//! Validation order matters and is fixed, because the faucet's checks run in the same order and the
//! two must reject identically — a payload that fails here must fail on-chain for the same reason,
//! or off-chain pre-validation would pass work to the chain that then fails.
//!
//! Decoding also NARROWS every field to the domain type it has to hold for the deposit to be
//! mintable at all: the bytes32 identifiers to account ids, and the two uint256 amounts to the
//! units the faucet mints in. Circle's encoding leaves the identifier fields open — `remoteToken`
//! and `remoteRecipient` are opaque bytes32 there, and how a Miden AccountId packs into one is
//! still an open decision (`DEV-10`). That stays open as a LAYOUT question. What is not open is
//! that a deposit whose identifiers do not read as account ids under the shipped layout cannot be
//! minted under any of them: the faucet mints to an account id or not at all. Refusing it here
//! costs nothing and gives the rejection a name, while a later layout decision changes only the
//! packaging these conversions apply.
//!
//! WARNING: Do not deposit with more than 3,840 bytes of `hookData`. The deposit cannot be claimed
//! on Miden, and the USDC remains locked on the source chain.

use miden_protocol::account::{AccountId, StorageMapKey};
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};
use miden_protocol::{Felt, Word, MAX_NOTE_STORAGE_ITEMS};
use miden_standards::interop::eth::{EthAmount, EthEmbeddedAccountId};

use super::account_id::EthEmbeddedAccountIdExt;
use super::amount::uint256_to_asset_amount;
use super::bytes32::{bytes32_to_packed_felts, bytes32_to_storage_map_key};
use super::domain::CircleDomain;
use super::error::EncodingError;
use crate::note::xreserve_mint::XUSDC_MINT_TRANSPORT_HOOK_DATA_MAX_LEN;

// WIRE-SHAPE CONSTANTS
// ================================================================================================

/// Bytes per u32-LE-packed field element.
pub const BYTES_PER_PACKED_FELT: usize = 4;

/// A bytes32 wire field, and the widths of the values carried right-aligned inside one: an
/// AccountId as two big-endian u64s, an `AssetAmount` as a big-endian u64.
pub const BYTES32_LEN: usize = 32;
pub const ACCOUNT_ID_BYTES: usize = 16;
pub const ASSET_AMOUNT_BYTES: usize = AssetAmount::SERIALIZED_SIZE;

/// A whole bytes32 as packed field elements — the form the mint note's carried payload uses.
pub const BYTES32_PACKED_LIMBS: usize = BYTES32_LEN / BYTES_PER_PACKED_FELT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositIntentField {
    Magic,
    Version,
    Amount,
    RemoteDomain,
    RemoteToken,
    RemoteRecipient,
    LocalToken,
    LocalDepositor,
    MaxFee,
    Nonce,
    HookDataLen,
    HookData,
}

impl DepositIntentField {
    /// The field's byte position on the wire.
    pub const fn offset(self) -> usize {
        match self {
            Self::Magic => 0,
            Self::Version => 4,
            Self::Amount => 8,
            Self::RemoteDomain => 40,
            Self::RemoteToken => 44,
            Self::RemoteRecipient => 76,
            Self::LocalToken => 108,
            Self::LocalDepositor => 140,
            Self::MaxFee => 172,
            Self::Nonce => 204,
            Self::HookDataLen => 236,
            Self::HookData => 240,
        }
    }
}

// DEPOSIT NONCE
// ================================================================================================

/// Circle's unique per-deposit nonce.
///
/// It drives two derived values and nothing else: the `usedNonces` replay-guard key and the
/// attested output note's serial number, which are the same Word. Both go through the shared
/// `DC-4` hashing routine, so this type only names the value and delegates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositNonce([u8; BYTES32_LEN]);

impl DepositNonce {
    /// Wraps a raw nonce. Any 32 bytes are a valid nonce — the hashing keeps it total.
    pub const fn new(bytes: [u8; BYTES32_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; BYTES32_LEN] {
        &self.0
    }

    /// The 8 u32-LE-packed limbs the mint note's payload carries.
    pub fn to_packed_felts(&self) -> [Felt; BYTES32_PACKED_LIMBS] {
        bytes32_to_packed_felts(&self.0)
    }

    /// The replay-guard key and output-note serial (`DC-4`).
    pub fn to_word(&self) -> Word {
        self.to_storage_map_key().as_word()
    }

    /// The replay-guard key and output-note serial (`DC-4`).
    pub fn to_storage_map_key(&self) -> StorageMapKey {
        bytes32_to_storage_map_key(&self.0)
    }
}

// FOREIGN CHAIN ADDRESS
// ================================================================================================

/// An address on a foreign chain — the deposited token, the depositor or a contract address.
///
/// These are opaque 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignChainAddress([u8; BYTES32_LEN]);

impl ForeignChainAddress {
    /// Wraps a raw address. Any 32 bytes are one — the faucet places no structure on them.
    pub const fn new(bytes: [u8; BYTES32_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; BYTES32_LEN] {
        &self.0
    }

    /// The 8 u32-LE-packed limbs the mint note's payload carries.
    pub fn to_packed_felts(&self) -> [Felt; BYTES32_PACKED_LIMBS] {
        bytes32_to_packed_felts(&self.0)
    }
}

// HOOK DATA
// ================================================================================================

/// The DepositIntent's opaque trailing payload.
///
/// It is carried because the signature covers it, and for no other reason — nothing on-chain reads
/// it for effects. The length bound is checked here so that everything downstream, including the
/// faucet's fixed staging region, can treat it as already-bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookData(Vec<u8>);

impl HookData {
    /// Maximum hookData length supported by the mint note, in bytes.
    pub const MAX_LEN: usize = XUSDC_MINT_TRANSPORT_HOOK_DATA_MAX_LEN;

    /// Wraps hookData bytes.
    ///
    /// # Errors
    ///
    /// [`EncodingError::HookDataTooLarge`] past [`Self::MAX_LEN`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, EncodingError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(EncodingError::HookDataTooLarge);
        }
        Ok(Self(bytes))
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The declared wire length. Fits a u32 by the constructor's bound.
    pub fn len_u32(&self) -> u32 {
        u32::try_from(self.0.len()).expect("hook data length is bounded by HookData::MAX_LEN")
    }

    /// Whether there is any hookData at all (the common case is none).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `ceil(len / 4)` u32-LE-packed felts the mint note's payload carries, trailing bytes
    /// zero-filled.
    pub fn to_packed_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }
}

// The transport bound above is only the tighter ceiling as long as the rebuilt preimage — a longer
// fixed prefix than the transport's, plus the same hookData — still fits the faucet's staging
// region. If a future header or transport change inverts that, `MAX_LEN` is on the wrong side.
const _: () = assert!(
    DepositIntent::HEADER_NUM_FELTS + HookData::MAX_LEN / BYTES_PER_PACKED_FELT
        <= MAX_NOTE_STORAGE_ITEMS,
    "the rebuilt preimage of a max-length hookData must fit the protocol's note-storage limit"
);

// DEPOSIT INTENT HEADER
// ================================================================================================

/// The fixed header's fields, each in the domain type the deposit must hold for it to be mintable.
///
/// - `magic` and `version` are absent because they are scheme constants: decoding checks them and
///   encoding writes them.
/// - `hookDataLen` is derived from the hookData.
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct DepositIntentHeader {
    amount: AssetAmount,
    remote_domain: CircleDomain,
    remote_token: AccountId,
    remote_recipient: AccountId,
    local_token: ForeignChainAddress,
    local_depositor: ForeignChainAddress,
    max_fee: AssetAmount,
    nonce: DepositNonce,
}

impl DepositIntentHeader {
    /// The scheme sentinel and version the header carries.
    pub const MAGIC: u32 = 0x5a2e_0acd;
    pub const VERSION: u32 = 1;

    /// What [`Serializable`] writes: the header's own fields, `magic` through `nonce`. Circle's
    /// fixed prefix is four bytes longer — see [`DepositIntent::HEADER_SIZE`].
    pub const SERIALIZED_SIZE: usize = DepositIntentField::HookDataLen.offset();

    /// The deposit amount, in the units the faucet mints.
    pub fn amount(&self) -> AssetAmount {
        self.amount
    }

    /// The destination domain the consuming faucet must have configured.
    pub fn remote_domain(&self) -> CircleDomain {
        self.remote_domain
    }

    /// The destination token — the faucet the deposit is addressed to.
    pub fn remote_token(&self) -> AccountId {
        self.remote_token
    }

    /// The account the minted asset is destined for.
    pub fn remote_recipient(&self) -> AccountId {
        self.remote_recipient
    }

    /// The deposited token on the source chain.
    pub fn local_token(&self) -> ForeignChainAddress {
        self.local_token
    }

    /// The depositor on the source chain.
    pub fn local_depositor(&self) -> ForeignChainAddress {
        self.local_depositor
    }

    /// The depositor-authorized fee ceiling, in the same units as [`Self::amount`].
    pub fn max_fee(&self) -> AssetAmount {
        self.max_fee
    }

    /// The per-deposit nonce.
    pub fn nonce(&self) -> DepositNonce {
        self.nonce
    }

    /// The typed decode of the header block, leaving the reader on `hookDataLen`.
    fn read<R: ByteReader>(source: &mut R) -> Result<Self, EncodingError> {
        // the bounds guard necessarily precedes any field read (the TruncatedHeader case)
        let bytes: [u8; Self::SERIALIZED_SIZE] = source
            .read_array()
            .map_err(|_| EncodingError::TruncatedHeader)?;

        if be_u32(&bytes, DepositIntentField::Magic) != Self::MAGIC {
            return Err(EncodingError::BadMagic);
        }
        if be_u32(&bytes, DepositIntentField::Version) != Self::VERSION {
            return Err(EncodingError::BadVersion);
        }

        // the zero checks run on the raw bytes and before the narrowings, because zero is a
        // perfectly valid amount and a perfectly valid address: only the wire form distinguishes
        // "the depositor sent nothing" from "this field was never filled in"
        let amount = non_zero_bytes32(&bytes, DepositIntentField::Amount)?;
        let local_token = non_zero_bytes32(&bytes, DepositIntentField::LocalToken)?;
        let local_depositor = non_zero_bytes32(&bytes, DepositIntentField::LocalDepositor)?;

        Ok(Self {
            amount: reduce(amount, DepositIntentField::Amount)?,
            remote_domain: CircleDomain::new(be_u32(&bytes, DepositIntentField::RemoteDomain)),
            remote_token: account_id(&bytes, DepositIntentField::RemoteToken)?,
            remote_recipient: account_id(&bytes, DepositIntentField::RemoteRecipient)?,
            local_token: ForeignChainAddress::new(local_token),
            local_depositor: ForeignChainAddress::new(local_depositor),
            max_fee: reduce(
                bytes32_at(&bytes, DepositIntentField::MaxFee),
                DepositIntentField::MaxFee,
            )?,
            nonce: DepositNonce::new(bytes32_at(&bytes, DepositIntentField::Nonce)),
        })
    }
}

impl Serializable for DepositIntentHeader {
    /// Writes the header's fields at their frozen offsets. The `hookDataLen` that closes Circle's
    /// 240-byte prefix belongs to [`DepositIntent`], which appends it and the hookData itself.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut bytes = [0u8; Self::SERIALIZED_SIZE];

        write_u32(&mut bytes, DepositIntentField::Magic, Self::MAGIC);
        write_u32(&mut bytes, DepositIntentField::Version, Self::VERSION);
        write_bytes32(&mut bytes, DepositIntentField::Amount, &widen(self.amount));
        write_u32(
            &mut bytes,
            DepositIntentField::RemoteDomain,
            self.remote_domain.as_u32(),
        );
        write_bytes32(
            &mut bytes,
            DepositIntentField::RemoteToken,
            &EthEmbeddedAccountId::from_account_id(self.remote_token).to_bytes32(),
        );
        write_bytes32(
            &mut bytes,
            DepositIntentField::RemoteRecipient,
            &EthEmbeddedAccountId::from_account_id(self.remote_recipient).to_bytes32(),
        );
        write_bytes32(
            &mut bytes,
            DepositIntentField::LocalToken,
            self.local_token.as_bytes(),
        );
        write_bytes32(
            &mut bytes,
            DepositIntentField::LocalDepositor,
            self.local_depositor.as_bytes(),
        );
        write_bytes32(&mut bytes, DepositIntentField::MaxFee, &widen(self.max_fee));
        write_bytes32(&mut bytes, DepositIntentField::Nonce, self.nonce.as_bytes());

        target.write_bytes(&bytes);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for DepositIntentHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read(source).map_err(DeserializationError::from)
    }
}

// DEPOSIT INTENT
// ================================================================================================

/// A decoded Circle DepositIntent: the typed header plus its trailing hookData.
///
/// Every instance has been through [`Deserializable`] or was assembled from values that already
/// were, so holding one means the structural checks passed and every field is representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositIntent {
    header: DepositIntentHeader,
    hook_data: HookData,
}

impl DepositIntent {
    /// Circle's fixed prefix: the header's fields plus the `hookDataLen` that closes it.
    pub const HEADER_SIZE: usize = DepositIntentField::HookData.offset();

    /// The same prefix as u32-LE-packed field elements (four wire bytes per element, so 60 — not
    /// 30).
    pub const HEADER_NUM_FELTS: usize = Self::HEADER_SIZE / BYTES_PER_PACKED_FELT;

    /// Pairs a header with its hookData.
    pub fn new(header: DepositIntentHeader, hook_data: HookData) -> Self {
        Self { header, hook_data }
    }

    /// The header fields.
    pub fn header(&self) -> &DepositIntentHeader {
        &self.header
    }

    /// The opaque trailing payload.
    pub fn hook_data(&self) -> &HookData {
        &self.hook_data
    }

    /// The felt count of the u32-LE-packed preimage: `60 + ceil(hookDataLen / 4)`.
    pub fn preimage_felt_len(&self) -> usize {
        Self::HEADER_NUM_FELTS
            + self
                .hook_data
                .as_bytes()
                .len()
                .div_ceil(BYTES_PER_PACKED_FELT)
    }

    /// The u32-LE-packed on-chain preimage — the felts the attestation's digest is taken over.
    /// Within the protocol's `MAX_NOTE_STORAGE_ITEMS` bound by [`HookData`]'s own invariant.
    pub fn to_preimage_felts(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.to_bytes())
    }

    /// The shared decoding implementation.
    ///
    /// Trailing bytes are rejected: the payload declares its own total length, so anything past it
    /// means the sender and this decoder disagree about what was signed.
    fn read<R: ByteReader>(source: &mut R) -> Result<Self, EncodingError> {
        let header = DepositIntentHeader::read(source)?;

        // hookDataLen closes Circle's fixed 240-byte prefix, so a payload that stops inside it is
        // a truncated header rather than a length disagreement
        let hook_data_len = source
            .read_array::<BYTES_PER_PACKED_FELT>()
            .map(u32::from_be_bytes)
            .map_err(|_| EncodingError::TruncatedHeader)? as usize;

        // the bound is applied to the DECLARED length, before the tail is read, so an adversarial
        // length cannot drive an allocation
        if hook_data_len > HookData::MAX_LEN {
            return Err(EncodingError::HookDataTooLarge);
        }
        let hook_data = source
            .read_vec(hook_data_len)
            .map_err(|_| EncodingError::LengthMismatch)?;
        if source.has_more_bytes() {
            return Err(EncodingError::LengthMismatch);
        }

        Ok(Self::new(header, HookData::new(hook_data)?))
    }
}

impl Serializable for DepositIntent {
    /// Writes the canonical message the attestation signs: the header at its frozen offsets, then
    /// the declared hookData length, then hookData.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.header.write_into(target);
        target.write_bytes(&self.hook_data.len_u32().to_be_bytes());
        target.write_bytes(self.hook_data.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Self::HEADER_SIZE + self.hook_data.as_bytes().len()
    }
}

impl Deserializable for DepositIntent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read(source).map_err(DeserializationError::from)
    }
}

impl TryFrom<&[u8]> for DepositIntent {
    type Error = EncodingError;

    /// The entry point every off-chain caller takes, because it keeps the specific
    /// [`EncodingError`] the payload earned rather than the protocol trait's flattened spelling.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::read(&mut SliceReader::new(bytes))
    }
}

// HELPERS
// ================================================================================================

/// Reads a big-endian u32 wire field.
fn be_u32(bytes: &[u8; DepositIntentHeader::SERIALIZED_SIZE], field: DepositIntentField) -> u32 {
    let offset = field.offset();
    u32::from_be_bytes(
        bytes[offset..offset + BYTES_PER_PACKED_FELT]
            .try_into()
            .expect("4-byte window"),
    )
}

/// Copies a 32-byte wire field.
fn bytes32_at(
    bytes: &[u8; DepositIntentHeader::SERIALIZED_SIZE],
    field: DepositIntentField,
) -> [u8; BYTES32_LEN] {
    let offset = field.offset();
    bytes[offset..offset + BYTES32_LEN]
        .try_into()
        .expect("32-byte window")
}

/// Copies a 32-byte wire field the scheme requires to be non-zero.
fn non_zero_bytes32(
    bytes: &[u8; DepositIntentHeader::SERIALIZED_SIZE],
    field: DepositIntentField,
) -> Result<[u8; BYTES32_LEN], EncodingError> {
    let value = bytes32_at(bytes, field);
    if value.iter().all(|byte| *byte == 0) {
        return Err(EncodingError::ZeroField { field });
    }
    Ok(value)
}

/// Reduces one uint256 wire field to the `AssetAmount` it must hold, naming which of the two
/// amount-shaped fields failed rather than only why: the relayer has to tell an unmintable
/// `amount` from an unmintable `maxFee`.
fn reduce(
    value: [u8; BYTES32_LEN],
    field: DepositIntentField,
) -> Result<AssetAmount, EncodingError> {
    uint256_to_asset_amount(EthAmount::new(value))
        .map_err(|_| EncodingError::FieldNotAssetAmount { field })
}

/// Zero-extends a reduced amount back into the 32 big-endian bytes of its uint256 wire field.
/// Exact, because the reduction that produced it ran at a scale of zero.
fn widen(amount: AssetAmount) -> [u8; BYTES32_LEN] {
    let mut bytes = [0u8; BYTES32_LEN];
    bytes[BYTES32_LEN - ASSET_AMOUNT_BYTES..].copy_from_slice(&amount.as_u64().to_be_bytes());
    bytes
}

/// Decodes a bytes32 identifier as the packaged Miden account id it has to be for the deposit to be
/// mintable at all (`DEV-10`).
fn account_id(
    bytes: &[u8; DepositIntentHeader::SERIALIZED_SIZE],
    field: DepositIntentField,
) -> Result<AccountId, EncodingError> {
    Ok(EthEmbeddedAccountId::try_from_bytes32(bytes32_at(bytes, field))?.into_account_id())
}

/// Writes a 4-byte big-endian wire field at its layout offset.
fn write_u32(
    out: &mut [u8; DepositIntentHeader::SERIALIZED_SIZE],
    field: DepositIntentField,
    value: u32,
) {
    let offset = field.offset();
    out[offset..offset + BYTES_PER_PACKED_FELT].copy_from_slice(&value.to_be_bytes());
}

/// Writes a value into a bytes32 wire field, right-aligned behind a leading zero pad. A full
/// 32-byte value fills the field; a narrower one (an amount, a nonce) lands at the end, which is
/// the packaging every one of those fields uses.
fn write_bytes32(
    out: &mut [u8; DepositIntentHeader::SERIALIZED_SIZE],
    field: DepositIntentField,
    value: &[u8],
) {
    let start = field.offset() + BYTES32_LEN - value.len();
    out[start..start + value.len()].copy_from_slice(value);
}

// TESTS — TV-DI-1..9
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-DI-1 (happy path, written first): a full header + hookData decodes to the exact per-field
    /// values at the frozen wire offsets.
    ///
    /// The bytes32 fields are checked through the re-encoding rather than by comparing the decoded
    /// domain types against the vector's hex: the wire bytes are the contract, and asserting them
    /// at their offsets pins placement and value at once without re-deriving the packaging the
    /// decoder just applied.
    #[test]
    fn tv_di_1_positive_parse() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let bytes = vec.bytes();
            let intent = DepositIntent::try_from(bytes.as_slice())
                .unwrap_or_else(|e| panic!("vector {}: must parse, got {e}", vec.id));
            let header = intent.header();
            let f = vec.fields.as_ref().expect("accept vector carries fields");

            assert_eq!(
                header.remote_domain(),
                f.remote_domain,
                "vector {}: remoteDomain",
                vec.id
            );
            assert_eq!(
                intent.hook_data().len_u32(),
                f.hook_data_len,
                "vector {}: hookDataLen",
                vec.id
            );
            assert_eq!(
                u64::from(header.amount()),
                f.amount,
                "vector {}: amount",
                vec.id
            );
            assert_eq!(
                u64::from(header.max_fee()),
                f.max_fee,
                "vector {}: maxFee",
                vec.id
            );

            let written = intent.to_bytes();
            for (name, field, label) in [
                ("amount", DepositIntentField::Amount, "amount"),
                (
                    "remote_token",
                    DepositIntentField::RemoteToken,
                    "remoteToken",
                ),
                (
                    "remote_recipient",
                    DepositIntentField::RemoteRecipient,
                    "remoteRecipient",
                ),
                ("local_token", DepositIntentField::LocalToken, "localToken"),
                (
                    "local_depositor",
                    DepositIntentField::LocalDepositor,
                    "localDepositor",
                ),
                ("max_fee", DepositIntentField::MaxFee, "maxFee"),
                ("nonce", DepositIntentField::Nonce, "nonce"),
            ] {
                let offset = field.offset();
                assert_eq!(
                    &written[offset..offset + BYTES32_LEN],
                    &f.bytes32(name),
                    "vector {}: {label}",
                    vec.id
                );
            }
        }
    }

    /// The decode and the encode are inverses over every accept vector: what Circle signed is
    /// exactly what this crate writes back. Everything downstream rests on it, because the faucet
    /// verifies the signature over bytes it rebuilds rather than over bytes it was handed.
    #[test]
    fn round_trip_is_byte_exact() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let bytes = vec.bytes();
            let intent = DepositIntent::try_from(bytes.as_slice()).expect("accept vector decodes");
            assert_eq!(intent.to_bytes(), bytes, "vector {}: round trip", vec.id);
        }
    }

    /// TV-DI-2..6 (negative, parametrized): each structural violation rejects with its
    /// SPECIFIC variant (one named case per frozen harness row).
    #[rstest]
    #[case::tv_di_2_bad_magic("di-rej-bad-magic")]
    #[case::tv_di_3_bad_version("di-rej-bad-version")]
    #[case::tv_di_4_zero_amount("di-rej-zero-amount")]
    #[case::tv_di_5_zero_local_token("di-rej-zero-local-token")]
    #[case::tv_di_5_zero_local_depositor("di-rej-zero-local-depositor")]
    #[case::tv_di_6_length_mismatch("di-rej-length-mismatch")]
    #[case::tv_di_6_truncated_header("di-rej-truncated")]
    fn tv_di_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = DepositIntent::try_from(vec.bytes().as_slice());
        match vec.expected_variant.as_deref() {
            Some("BadMagic") => assert_matches!(result, Err(EncodingError::BadMagic), "{id}"),
            Some("BadVersion") => assert_matches!(result, Err(EncodingError::BadVersion), "{id}"),
            Some("ZeroField:Amount") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::Amount
                }),
                "{id}"
            ),
            Some("ZeroField:LocalToken") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalToken
                }),
                "{id}"
            ),
            Some("ZeroField:LocalDepositor") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalDepositor
                }),
                "{id}"
            ),
            Some("LengthMismatch") => {
                assert_matches!(result, Err(EncodingError::LengthMismatch), "{id}")
            }
            Some("TruncatedHeader") => {
                assert_matches!(result, Err(EncodingError::TruncatedHeader), "{id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// A payload that stops inside Circle's fixed 240-byte prefix is a truncated header, whichever
    /// side of the header/hookDataLen seam it stops on — the two are one block on the wire.
    #[test]
    fn a_payload_short_of_the_fixed_prefix_is_truncated() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-empty-hookdata")
            .expect("vector");
        let bytes = vec.bytes();
        for len in [
            DepositIntentHeader::SERIALIZED_SIZE,
            DepositIntent::HEADER_SIZE - 1,
        ] {
            assert_matches!(
                DepositIntent::try_from(&bytes[..len]),
                Err(EncodingError::TruncatedHeader),
                "a {len}-byte payload stops inside the fixed prefix"
            );
        }
    }

    /// A payload followed by bytes that are not part of it is refused rather than silently
    /// truncated to the message it claims to be — on both decode paths, since the check sits in the
    /// codec rather than in one entry point.
    #[test]
    fn trailing_bytes_reject() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-hookdata")
            .expect("vector");
        let mut bytes = vec.bytes();
        bytes.push(0x00);
        assert_matches!(
            DepositIntent::try_from(bytes.as_slice()),
            Err(EncodingError::LengthMismatch)
        );
        assert_eq!(
            DepositIntent::read_from_bytes(&bytes)
                .expect_err("the standard reader refuses the trailing byte too")
                .to_string(),
            DeserializationError::from(EncodingError::LengthMismatch).to_string()
        );
    }

    /// TV-DI-7 (boundary): the packed header is exactly 60 felts, equals the committed preimage,
    /// stays within the 1024-felt bound, and the overflow vector rejects with `HookDataTooLarge`
    /// (the hookData cap stays OPEN with Circle).
    #[test]
    fn tv_di_7_sixty_felts_and_1024_bound() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let intent =
                DepositIntent::try_from(vec.bytes().as_slice()).expect("accept vector decodes");
            let felts = intent.to_preimage_felts();
            let expected = vec.preimage_values();
            assert_eq!(
                felts.len(),
                expected.len(),
                "vector {}: total felts",
                vec.id
            );
            assert_eq!(
                felts.len(),
                intent.preimage_felt_len(),
                "vector {}: derived felt length",
                vec.id
            );
            assert_eq!(
                &felts[..DepositIntent::HEADER_NUM_FELTS],
                &expected[..DepositIntent::HEADER_NUM_FELTS],
                "vector {}: 60-felt header",
                vec.id
            );
            assert_eq!(felts, expected, "vector {}: full preimage", vec.id);
            assert!(
                felts.len() <= MAX_NOTE_STORAGE_ITEMS,
                "vector {}: NoteStorage bound",
                vec.id
            );
        }
        let overflow = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-rej-hookdata-overflow")
            .expect("vector");
        assert_matches!(
            DepositIntent::try_from(overflow.bytes().as_slice()),
            Err(EncodingError::HookDataTooLarge),
            "hookData past the 1024-felt bound must reject"
        );
    }

    /// TV-DI-8 (determinism/immutability): decoding borrows the input immutably and the
    /// bytes are unchanged afterwards (note-input immutability analogue).
    #[test]
    fn tv_di_8_input_immutable() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-hookdata")
            .expect("vector");
        let bytes = vec.bytes();
        let before = bytes.clone();
        let _ = DepositIntent::try_from(bytes.as_slice());
        assert_eq!(bytes, before, "input must be unchanged by parsing");
    }

    /// TV-DI-9 (layout table): every field offset equals the wire-format byte offset.
    #[test]
    fn tv_di_9_offsets_table() {
        let expected: [(DepositIntentField, usize); 12] = [
            (DepositIntentField::Magic, 0),
            (DepositIntentField::Version, 4),
            (DepositIntentField::Amount, 8),
            (DepositIntentField::RemoteDomain, 40),
            (DepositIntentField::RemoteToken, 44),
            (DepositIntentField::RemoteRecipient, 76),
            (DepositIntentField::LocalToken, 108),
            (DepositIntentField::LocalDepositor, 140),
            (DepositIntentField::MaxFee, 172),
            (DepositIntentField::Nonce, 204),
            (DepositIntentField::HookDataLen, 236),
            (DepositIntentField::HookData, 240),
        ];
        for (field, off) in expected {
            assert_eq!(field.offset(), off, "wire offset of {field:?}");
        }
    }

    /// hookData past the bound is refused at construction, so nothing downstream — including the
    /// faucet's fixed staging region — has to re-check it.
    #[test]
    fn hook_data_bound_is_enforced_at_construction() {
        assert_matches!(
            HookData::new(vec![0u8; HookData::MAX_LEN + 1]),
            Err(EncodingError::HookDataTooLarge)
        );
        assert!(HookData::new(vec![0u8; HookData::MAX_LEN]).is_ok());
    }
}

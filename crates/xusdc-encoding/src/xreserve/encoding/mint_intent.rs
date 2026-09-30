//! The mint note's carried payload, and its relationship to Circle's DepositIntent (`DC-14`).
//!
//! Circle's DepositIntent does not travel on the mint note. The note carries only the fields the
//! faucet has no other way to learn, and the faucet rebuilds the canonical message itself before
//! hashing it — so a field the faucet writes cannot disagree with the attestation, because a
//! divergent value changes the digest and the signature stops verifying.
//!
//! This module owns the FELT format — what the note actually carries — and the two conversions to
//! and from the byte format its sibling `deposit_intent` owns. [`MintIntent::from_deposit_intent`]
//! compresses a real Circle payload and refuses anything this faucet could not rebuild
//! byte-for-byte; [`MintIntent::to_deposit_intent`] is the mirror of the MASM writer
//! `xreserve::deposit_intent::rebuild`. What binds the two is the round trip, not a
//! field-by-field comparison.

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::packed_u32_elements_to_bytes;
use miden_protocol::Felt;

use super::bytes32::packed_felts_to_bytes32;
use super::deposit_intent::{
    DepositIntent, DepositIntentField, DepositIntentHeader, DepositNonce, ForeignChainAddress,
    HookData, BYTES32_LEN, BYTES32_PACKED_LIMBS, BYTES_PER_PACKED_FELT,
};
use super::domain::CircleDomain;
use super::error::EncodingError;

// MINT PAYLOAD
// ================================================================================================

/// Exactly the DepositIntent fields the mint note carries.
///
/// The faucet supplies the rest when it rebuilds the message: `magic` and `version` are scheme
/// constants, `amount` is the note's own asset value, `remoteDomain` its configured domain,
/// `remoteToken` its own account id, and `feeAmount` is always zero.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct MintIntent {
    nonce: DepositNonce,
    local_token: ForeignChainAddress,
    local_depositor: ForeignChainAddress,
    remote_recipient: AccountId,
    max_fee: AssetAmount,
    hook_data: HookData,
}

impl MintIntent {
    /// An AccountId is encoded as two felts.
    pub const ACCOUNT_ID_FELTS: usize = 2;

    // Felt offsets within the carried payload.
    pub const NONCE_FELT_OFF: usize = 0;

    pub const LOCAL_TOKEN_FELT_OFF: usize = Self::NONCE_FELT_OFF + BYTES32_PACKED_LIMBS;
    pub const LOCAL_DEPOSITOR_FELT_OFF: usize = Self::LOCAL_TOKEN_FELT_OFF + BYTES32_PACKED_LIMBS;

    /// The recipient is encoded as two felts.
    pub const REMOTE_RECIPIENT_FELT_OFF: usize =
        Self::LOCAL_DEPOSITOR_FELT_OFF + BYTES32_PACKED_LIMBS;
    pub const REMOTE_RECIPIENT_SUFFIX_FELT_OFF: usize = Self::REMOTE_RECIPIENT_FELT_OFF + 1;

    pub const MAX_FEE_FELT_OFF: usize = Self::REMOTE_RECIPIENT_FELT_OFF + Self::ACCOUNT_ID_FELTS;
    /// maxFee is a single `AssetAmount` felt.
    pub const HOOK_DATA_LEN_FELT_OFF: usize = Self::MAX_FEE_FELT_OFF + 1;

    /// The payload's content felts, which land on the word boundary exactly. hookData follows
    /// immediately, so this is also the offset of the first packed hookData felt.
    pub const NUM_FELTS: usize = Self::HOOK_DATA_LEN_FELT_OFF + 1;

    // COMPRESS
    // --------------------------------------------------------------------------------------------

    /// Compresses a Circle DepositIntent into what the mint note carries.
    ///
    /// `target` is the faucet meant to consume the note and `remote_domain` the domain that
    /// faucet has configured. Both are values the faucet writes into the message it rebuilds from
    /// its own state, so an intent naming different ones rebuilds a different digest and dies
    /// on-chain as an invalid signature. This is checked here before the note is ever submitted.
    /// Every other field is carried across as it was decoded.
    ///
    /// # Errors
    ///
    /// - [`EncodingError::RemoteTokenMismatch`] if the intent is addressed to another faucet.
    /// - [`EncodingError::RemoteDomainMismatch`] if it names another destination domain.
    pub fn from_deposit_intent(
        intent: &DepositIntent,
        target: AccountId,
        remote_domain: CircleDomain,
    ) -> Result<Self, EncodingError> {
        let header = intent.header();

        if header.remote_token() != target {
            return Err(EncodingError::RemoteTokenMismatch);
        }
        if header.remote_domain() != remote_domain {
            return Err(EncodingError::RemoteDomainMismatch {
                expected: remote_domain,
                actual: header.remote_domain(),
            });
        }

        Ok(Self {
            nonce: header.nonce(),
            local_token: header.local_token(),
            local_depositor: header.local_depositor(),
            remote_recipient: header.remote_recipient(),
            max_fee: header.max_fee(),
            hook_data: intent.hook_data().clone(),
        })
    }

    // EXPAND
    // --------------------------------------------------------------------------------------------

    /// Rebuilds the DepositIntent the attestation signed.
    ///
    /// Expands itself plus the three the [`MintIntent`] does not carry come from the faucet's own
    /// state.
    pub fn to_deposit_intent(
        &self,
        amount: AssetAmount,
        remote_domain: CircleDomain,
        remote_token: AccountId,
    ) -> DepositIntent {
        let header = DepositIntentHeader::builder()
            .amount(amount)
            .remote_domain(remote_domain)
            .remote_token(remote_token)
            .remote_recipient(self.remote_recipient)
            .local_token(self.local_token)
            .local_depositor(self.local_depositor)
            .max_fee(self.max_fee)
            .nonce(self.nonce)
            .build();
        DepositIntent::new(header, self.hook_data.clone())
    }

    // FELT ENCODING
    // --------------------------------------------------------------------------------------------

    /// The felt encoding: the fixed felts followed by the packed hookData.
    ///
    /// Word padding of the hookData tail is not done here.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(Self::NUM_FELTS);
        out.extend_from_slice(&self.nonce.to_packed_felts());
        out.extend_from_slice(&self.local_token.to_packed_felts());
        out.extend_from_slice(&self.local_depositor.to_packed_felts());
        out.push(self.remote_recipient.prefix().as_felt());
        out.push(self.remote_recipient.suffix());
        out.push(Felt::from(self.max_fee));
        out.push(Felt::from(self.hook_data.len_u32()));
        out.extend(self.hook_data.to_packed_elements());
        out
    }

    /// Inverse of [`Self::to_elements`].
    ///
    /// # Errors
    ///
    /// A payload that is the wrong length, carries a non-u32 packed limb, or declares a hookData
    /// length that disagrees with the felts present returns [`EncodingError::LengthMismatch`] or
    /// [`EncodingError::LimbNotU32`]. `maxFee` and the recipient raise the same typed field errors
    /// the byte decode raises for them.
    pub fn from_elements(felts: &[Felt]) -> Result<Self, EncodingError> {
        if felts.len() < Self::NUM_FELTS {
            return Err(EncodingError::LengthMismatch);
        }

        let hook_data_len = u32_at(felts, Self::HOOK_DATA_LEN_FELT_OFF)?;
        let hook_data_felts = felts.len() - Self::NUM_FELTS;
        if hook_data_felts != (hook_data_len as usize).div_ceil(BYTES_PER_PACKED_FELT) {
            return Err(EncodingError::LengthMismatch);
        }

        let mut hook_data = unpack_bytes(&felts[Self::NUM_FELTS..])?;
        hook_data.truncate(hook_data_len as usize);

        Ok(Self {
            nonce: DepositNonce::new(bytes32_at_felts(felts, Self::NONCE_FELT_OFF)?),
            local_token: ForeignChainAddress::new(bytes32_at_felts(
                felts,
                Self::LOCAL_TOKEN_FELT_OFF,
            )?),
            local_depositor: ForeignChainAddress::new(bytes32_at_felts(
                felts,
                Self::LOCAL_DEPOSITOR_FELT_OFF,
            )?),
            remote_recipient: AccountId::try_from_elements(
                felts[Self::REMOTE_RECIPIENT_FELT_OFF + 1],
                felts[Self::REMOTE_RECIPIENT_FELT_OFF],
            )
            .map_err(|_| EncodingError::NonCanonicalAccountId)?,
            max_fee: AssetAmount::new(felts[Self::MAX_FEE_FELT_OFF].as_canonical_u64()).map_err(
                |_| EncodingError::FieldNotAssetAmount {
                    field: DepositIntentField::MaxFee,
                },
            )?,
            hook_data: HookData::new(hook_data)?,
        })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn nonce(&self) -> DepositNonce {
        self.nonce
    }

    pub fn local_token(&self) -> ForeignChainAddress {
        self.local_token
    }

    pub fn local_depositor(&self) -> ForeignChainAddress {
        self.local_depositor
    }

    pub fn remote_recipient(&self) -> AccountId {
        self.remote_recipient
    }

    pub fn max_fee(&self) -> AssetAmount {
        self.max_fee
    }

    pub fn hook_data(&self) -> &HookData {
        &self.hook_data
    }
}

// HELPERS
// ================================================================================================

/// Reads a felt as a u32-LE-packed limb, fail-closed rather than truncating.
fn u32_at(felts: &[Felt], index: usize) -> Result<u32, EncodingError> {
    u32::try_from(felts[index].as_canonical_u64()).map_err(|_| EncodingError::LimbNotU32)
}

/// Unpacks a run of u32-LE-packed limbs back to bytes, guarding each limb first.
fn unpack_bytes(felts: &[Felt]) -> Result<Vec<u8>, EncodingError> {
    for index in 0..felts.len() {
        u32_at(felts, index)?;
    }
    Ok(packed_u32_elements_to_bytes(felts))
}

/// Reads the bytes32 whose 8 packed limbs start at a carried-payload offset.
fn bytes32_at_felts(felts: &[Felt], offset: usize) -> Result<[u8; BYTES32_LEN], EncodingError> {
    let limbs: [Felt; BYTES32_PACKED_LIMBS] = felts[offset..offset + BYTES32_PACKED_LIMBS]
        .try_into()
        .expect("the caller's length check guarantees the window");
    packed_felts_to_bytes32(&limbs)
}

// TESTS — TV-DUAL-6 (the Rust half; the MASM half is in tests/masm_mint_shell.rs)
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::utils::serde::Serializable;

    use super::*;
    use crate::vectors::{load, MiVector};

    fn accepts() -> impl Iterator<Item = &'static MiVector> {
        load().families.mi.iter().filter(|v| v.kind == "accept")
    }

    /// Decodes an accept vector's payload the way the relayer does.
    fn intent(vec: &MiVector) -> DepositIntent {
        DepositIntent::try_from(vec.payload().as_slice())
            .unwrap_or_else(|e| panic!("vector {}: payload must decode: {e}", vec.id))
    }

    /// Compresses an accept vector against the faucet and domain it is addressed to.
    fn carried(vec: &MiVector) -> MintIntent {
        MintIntent::from_deposit_intent(&intent(vec), vec.faucet_id(), vec.remote_domain)
            .unwrap_or_else(|e| panic!("vector {}: compress failed: {e}", vec.id))
    }

    /// TV-DUAL-6 (happy path, written first): the reconstruction is exact.
    ///
    /// This is the law the whole transport rests on. Everything the faucet no longer checks, it
    /// checks by rebuilding these bytes and letting the signature verify over them — so if the
    /// round trip is not byte-exact, no mint can ever succeed.
    #[test]
    fn tv_dual_6_round_trip_is_byte_exact() {
        for vec in accepts() {
            assert_eq!(
                carried(vec)
                    .to_deposit_intent(vec.amount(), vec.remote_domain, vec.faucet_id())
                    .to_bytes(),
                vec.payload(),
                "vector {}: the rebuilt preimage must equal what Circle signed",
                vec.id
            );
        }
    }

    /// The carried felts and the felts the writer must produce, both pinned to the artifact —
    /// these are the rows the MASM writer is checked against, so a change on this side that the
    /// MASM side does not follow shows up as a vector diff rather than a silent divergence.
    #[test]
    fn tv_dual_6_carried_and_rebuilt_felts_match_the_vectors() {
        for vec in accepts() {
            let carried = carried(vec);
            assert_eq!(
                carried.to_elements(),
                vec.carried_values(),
                "vector {}: carried felts",
                vec.id
            );
            assert_eq!(
                carried
                    .to_deposit_intent(vec.amount(), vec.remote_domain, vec.faucet_id())
                    .to_preimage_felts(),
                vec.rebuilt_preimage_values(),
                "vector {}: rebuilt preimage felts",
                vec.id
            );
        }
    }

    /// The felt form is lossless: what the note carries decodes back to the payload that built it.
    #[test]
    fn tv_dual_6_carried_felts_are_lossless() {
        for vec in accepts() {
            let carried = carried(vec);
            assert_eq!(
                MintIntent::from_elements(&carried.to_elements()).expect("round trip"),
                carried,
                "vector {}: carried felts must round-trip",
                vec.id
            );
        }
    }

    /// Every narrowing DC-14 applies, one vector each, asserting the exact variant. These are the
    /// deposits the transport cannot express — the relayer has to reject them here, because
    /// on-chain they would all fail identically as an invalid signature. The narrowing itself
    /// happens in the byte decode, so a reject vector fails at whichever of the two steps owns it.
    #[test]
    fn tv_dual_6_rejects_what_the_transport_cannot_carry() {
        let rejects = load().families.mi.iter().filter(|v| v.kind == "reject");
        for vec in rejects {
            let id = &vec.id;
            let result = DepositIntent::try_from(vec.payload().as_slice()).and_then(|intent| {
                MintIntent::from_deposit_intent(&intent, vec.faucet_id(), vec.remote_domain)
            });
            match vec.expected_variant.as_deref().expect("reject vector") {
                "FieldNotAssetAmount" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::FieldNotAssetAmount { .. }),
                        "vector {id}"
                    )
                }
                "RemoteTokenMismatch" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::RemoteTokenMismatch),
                        "vector {id}"
                    )
                }
                "AccountIdOutOfRange" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::AccountIdOutOfRange),
                        "vector {id}"
                    )
                }
                "NonCanonicalAccountId" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::NonCanonicalAccountId),
                        "vector {id}"
                    )
                }
                other => panic!("vector {id}: unexpected expected_variant {other:?}"),
            }
        }
    }

    /// The faucet writes its OWN configured domain into the message it rebuilds, so an intent
    /// naming a different one can never verify on-chain. It is refused here, where the reason is
    /// still legible.
    #[test]
    fn compress_rejects_a_foreign_remote_domain() {
        let vec = accepts().next().expect("an accept vector");
        assert_matches!(
            MintIntent::from_deposit_intent(
                &intent(vec),
                vec.faucet_id(),
                CircleDomain::new(vec.remote_domain.as_u32().wrapping_add(1))
            ),
            Err(EncodingError::RemoteDomainMismatch { .. })
        );
    }

    /// A source-chain address that fills its whole bytes32 survives the transport.
    ///
    /// This is the case the carried payload used to be unable to express: it dropped each address's
    /// leading 12 bytes on the assumption they were an EVM address's zero pad, so a source chain
    /// with wider addresses was unmintable. Every byte must now come back, including the bytes that
    /// pad would have covered.
    #[test]
    fn a_source_chain_address_wider_than_an_evm_address_round_trips() {
        let vec = accepts().next().expect("an accept vector");
        let wide = ForeignChainAddress::new(core::array::from_fn(|i| 0xf0 ^ i as u8));
        assert_ne!(wide.as_bytes()[..12], [0u8; 12], "not an EVM address");

        let carried = MintIntent::builder()
            .nonce(carried(vec).nonce())
            .local_token(wide)
            .local_depositor(wide)
            .remote_recipient(vec.faucet_id())
            .max_fee(vec.amount())
            .hook_data(HookData::default())
            .build();

        let back = MintIntent::from_elements(&carried.to_elements()).expect("round trip");
        assert_eq!(back.local_token(), wide);
        assert_eq!(back.local_depositor(), wide);
    }

    /// A carried-felt run whose declared hookData length disagrees with the felts present is
    /// refused rather than silently truncated: on-chain that length picks the keccak extent.
    #[test]
    fn from_felts_rejects_a_hook_data_length_lie() {
        let vec = accepts()
            .find(|v| v.id == "mi-pos-empty-hookdata")
            .expect("vector present");
        let mut felts = vec.carried_values();
        felts[MintIntent::HOOK_DATA_LEN_FELT_OFF] = Felt::from(4u32);
        assert_matches!(
            MintIntent::from_elements(&felts),
            Err(EncodingError::LengthMismatch)
        );
    }
}

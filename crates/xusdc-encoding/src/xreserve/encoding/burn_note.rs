//! Burn-note item codec: the burn-note withdrawal payload
//! `(destDomain, destRecipient)`.
//!
//! The burn note factory uses this codec to encode the destination fields. The off-chain
//! withdrawal attester uses the same codec to decode them.
//!
//! The `destRecipient` field is packed and unpacked with the shared bytes32 codec in both
//! directions, so there is one definition of how 32 bytes become field elements.

use miden_protocol::Felt;

use super::bytes32::packed_felts_to_bytes32;
use super::deposit_intent::ForeignChainAddress;
use super::domain::CircleDomain;
use super::error::EncodingError;

/// Felt width of the burn-note withdrawal payload: `destDomain` (1) then `destRecipient`
/// (8 u32-LE), totalling 9 felts (≤ 1024, the note-model felt bound).
pub const BURN_NOTE_ITEMS_FELTS: usize = 9;

/// The destination domain and recipient carried in the burn note's withdrawal attachment.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct XReserveBurnItems {
    pub dest_domain: CircleDomain,
    pub dest_recipient: ForeignChainAddress,
}

impl XReserveBurnItems {
    /// Encodes `(destDomain, destRecipient)` into the payload felt layout
    /// (`destDomain` at `[0]`, `destRecipient` at `[1..9]`). Infallible: `destDomain` is a u32 [`CircleDomain`],
    /// and the bytes32 field packs via the shared `bytes32` codec.
    pub fn encode(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(BURN_NOTE_ITEMS_FELTS);
        out.push(Felt::from(self.dest_domain)); // [0]
        out.extend_from_slice(&self.dest_recipient.to_packed_felts()); // [1..9]
        out
    }

    /// Decodes the withdrawal payload, reversing [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::BurnItemsMalformed`] on any wrong length, out-of-range field, or
    /// non-u32 limb.
    pub fn decode(items: &[Felt]) -> Result<Self, EncodingError> {
        if items.len() != BURN_NOTE_ITEMS_FELTS {
            return Err(EncodingError::BurnItemsMalformed);
        }
        let dest_domain = u32::try_from(items[0].as_canonical_u64())
            .map(CircleDomain::new)
            .map_err(|_| EncodingError::BurnItemsMalformed)?;
        // The length was checked above, so each slice is exactly 8 felts. Unpacking goes through the
        // shared bytes32 inverse; a limb that is not a valid u32 is reported as a malformed payload
        // rather than being truncated into a plausible-looking address.
        let recipient_felts: [Felt; 8] = items[1..9]
            .try_into()
            .expect("len == 9 ⇒ items[1..9] is exactly 8 felts");
        let dest_recipient = packed_felts_to_bytes32(&recipient_felts)
            .map(ForeignChainAddress::new)
            .map_err(|_| EncodingError::BurnItemsMalformed)?;
        Ok(Self {
            dest_domain,
            dest_recipient,
        })
    }
}

// TESTS — TV-BN-1..4
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-BN-1 (round-trip + golden layout): `encode` matches the golden felts and
    /// `decode(encode(x)) == x` across the accept vectors (incl. boundary values).
    #[test]
    fn tv_bn_1_round_trip() {
        let v = load();
        let accept: Vec<_> = v
            .families
            .bn
            .iter()
            .filter(|x| x.kind == "accept")
            .collect();
        assert!(!accept.is_empty(), "bn accept vectors present");
        for vec in accept {
            let x = vec.expected_struct();
            let encoded = x.encode();
            assert_eq!(encoded.len(), 9, "{}: width", vec.id);
            assert_eq!(
                encoded,
                vec.items_values(),
                "{}: encode matches the golden layout",
                vec.id
            );
            assert_eq!(
                XReserveBurnItems::decode(&encoded).expect("round-trip decode"),
                x,
                "{}: decode∘encode",
                vec.id
            );
            assert_eq!(
                XReserveBurnItems::decode(&vec.items_values()).expect("golden decode"),
                x,
                "{}: decode golden felts",
                vec.id
            );
        }
    }

    /// TV-BN-2 (destination-in-items): the destination fields land in the
    /// payload felt layout (`destDomain` at `[0]`, `destRecipient` at `[1..9]`). `encode` has no
    /// metadata path — its only output is `Vec<Felt>`, so `metadata.sender` is structurally reserved
    /// for the depositor.
    #[test]
    fn tv_bn_2_destination_in_items() {
        let v = load();
        for vec in v.families.bn.iter().filter(|x| x.kind == "accept") {
            let items = vec.expected_struct().encode();
            let golden = vec.items_values();
            assert_eq!(items[0], golden[0], "{}: destDomain in items[0]", vec.id);
            assert_eq!(
                &items[1..9],
                &golden[1..9],
                "{}: destRecipient in items[1..9]",
                vec.id
            );
        }
    }

    /// TV-BN-3 (note-model placement): the payload fits the note-model felt bound
    /// (≤ 1024 felts), not `NoteInputs`/`aux`.
    #[test]
    fn tv_bn_3_note_storage_placement() {
        let v = load();
        for vec in v.families.bn.iter().filter(|x| x.kind == "accept") {
            let n = vec.expected_struct().encode().len();
            assert_eq!(n, BURN_NOTE_ITEMS_FELTS, "{}: fixed width", vec.id);
            assert!(n <= 1024, "{}: within the note-model felt bound", vec.id);
        }
    }

    /// TV-BN-4 (malformed → exact error): every malformed-items vector decodes to the exact
    /// `BurnItemsMalformed` (wrong length, out-of-range domain, or a non-u32 limb).
    #[rstest]
    #[case("bn-rej-len-short")]
    #[case("bn-rej-len-long")]
    #[case("bn-rej-domain-over-u32")]
    #[case("bn-rej-recipient-limb-not-u32")]
    fn tv_bn_4_malformed_burn_items(#[case] id: &str) {
        let vec = load()
            .families
            .bn
            .iter()
            .find(|x| x.id == id)
            .unwrap_or_else(|| panic!("vector {id} present"));
        assert_matches!(
            XReserveBurnItems::decode(&vec.items_values()),
            Err(EncodingError::BurnItemsMalformed),
            "{id}",
        );
    }
}

//! Burn-note item codec: the burn-note withdrawal payload
//! `(destDomain, destRecipient)`.
//!
//! The burn note factory uses this codec to encode the destination fields. The off-chain
//! withdrawal attester uses the same codec to decode them.
//!
//! The `destRecipient` field is packed and unpacked with the shared bytes32 codec in both
//! directions, so there is one definition of how 32 bytes become field elements.

use miden_protocol::{Felt, Word};

use super::bytes32::packed_felts_to_bytes32;
use super::deposit_intent::ForeignChainAddress;
use super::domain::CircleDomain;
use super::error::EncodingError;
use crate::note::xreserve_burn::XUsdcBurnAttachment;

/// The destination domain and recipient carried in the burn note's withdrawal attachment.
///
/// It is laid out as:
///
/// ```text
/// [
///   [destination_domain, 0, 0, 0]
///   DESTINATION_RECIPIENT_LO,
///   DESTINATION_RECIPIENT_HI,
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct XReserveBurnItems {
    pub dest_domain: CircleDomain,
    pub dest_recipient: ForeignChainAddress,
}

impl XReserveBurnItems {
    /// Encodes the domain and recipient into words.
    pub fn encode(&self) -> [Word; XUsdcBurnAttachment::NUM_WORDS] {
        let recipient = self.dest_recipient.to_packed_felts();
        let mut items = [Word::empty(); XUsdcBurnAttachment::NUM_WORDS];

        items[0][0] = Felt::from(self.dest_domain);
        items[1].as_mut_slice().copy_from_slice(&recipient[0..4]);
        items[2].as_mut_slice().copy_from_slice(&recipient[4..8]);

        items
    }

    /// Decodes the withdrawal payload, reversing [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::BurnItemsMalformed`] on a wrong length, a non-zero element after
    /// `destDomain`, or a field that is not a u32.
    pub fn decode(words: &[Word]) -> Result<Self, EncodingError> {
        let [domain_word, recipient_low, recipient_high] = words else {
            return Err(EncodingError::BurnItemsMalformed);
        };

        let [domain, padding @ ..] = domain_word.into_elements();
        if padding.iter().any(|element| *element != Felt::ZERO) {
            return Err(EncodingError::BurnItemsMalformed);
        }
        let dest_domain = u32::try_from(domain.as_canonical_u64())
            .map(CircleDomain::new)
            .map_err(|_| EncodingError::BurnItemsMalformed)?;

        // a limb that is not a valid u32 is reported as a malformed payload rather than being
        // truncated into a plausible-looking address
        let mut recipient = [Felt::ZERO; 2 * Word::NUM_ELEMENTS];
        recipient[0..4].copy_from_slice(recipient_low.as_elements());
        recipient[4..8].copy_from_slice(recipient_high.as_elements());

        let dest_recipient = packed_felts_to_bytes32(&recipient)
            .map(ForeignChainAddress::new)
            .map_err(|_| EncodingError::BurnItemsMalformed)?;
        Ok(Self { dest_domain, dest_recipient })
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

    /// TV-BN-1 (round-trip + golden layout): `encode` matches the golden words and
    /// `decode(encode(x)) == x` across the accept vectors (incl. boundary values).
    #[test]
    fn tv_bn_1_round_trip() {
        let v = load();
        let accept: Vec<_> = v.families.bn.iter().filter(|x| x.kind == "accept").collect();
        assert!(!accept.is_empty(), "bn accept vectors present");
        for vec in accept {
            let x = vec.expected_struct();
            let encoded = x.encode();
            assert_eq!(
                encoded.as_slice(),
                vec.items_words(),
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
                XReserveBurnItems::decode(&vec.items_words()).expect("golden decode"),
                x,
                "{}: decode golden words",
                vec.id
            );
        }
    }

    /// TV-BN-2 (destination-in-items): the destination fields land in the payload word layout
    /// (`destDomain` at word 0, `destRecipient` at words 1 and 2). `encode` has no metadata path —
    /// its only output is the payload words, so `metadata.sender` is structurally reserved for the
    /// depositor.
    #[test]
    fn tv_bn_2_destination_in_items() {
        let v = load();
        for vec in v.families.bn.iter().filter(|x| x.kind == "accept") {
            let items = vec.expected_struct().encode();
            let golden = vec.items_words();
            assert_eq!(items[0], golden[0], "{}: destDomain in word 0", vec.id);
            assert_eq!(&items[1..3], &golden[1..3], "{}: destRecipient in words 1 and 2", vec.id);
        }
    }

    /// TV-BN-4 (malformed → exact error): every malformed-items vector decodes to the exact
    /// `BurnItemsMalformed` (wrong length, non-zero domain padding, out-of-range domain, or a
    /// non-u32 limb).
    #[rstest]
    #[case("bn-rej-len-short")]
    #[case("bn-rej-len-long")]
    #[case("bn-rej-domain-padding-not-zero")]
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
            XReserveBurnItems::decode(&vec.items_words()),
            Err(EncodingError::BurnItemsMalformed),
            "{id}",
        );
    }
}

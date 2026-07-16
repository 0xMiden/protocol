use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::errors::NoteError;
use miden_protocol::{Felt, Hasher, Word};

// FEE PAYMENT INFO
// ================================================================================================

/// Conversion info instructing `miden::standards::fee::pay_fee` which asset to pay
/// the transaction fee in.
///
/// The fee amount computed by the transaction kernel is denominated in the native fee asset;
/// `pay_fee` pays `ceil(fee_amount * rate_num / rate_den)` of the asset issued by `faucet_id`.
/// To pay in an asset 1-to-1 (e.g. the native fee asset itself), use [`Self::trivial`].
///
/// For signature-based authentication components the conversion info is typically committed to
/// via the transaction's auth args (see [`commit_fee_conversion_info`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeConversionInfo {
    faucet_id: AccountId,
    rate_num: u32,
    rate_den: u32,
}

impl FeeConversionInfo {
    /// Creates new fee conversion info paying the fee in the asset issued by `faucet_id` at the
    /// rate `rate_num / rate_den`.
    ///
    /// # Errors
    ///
    /// Returns an error if `rate_num` or `rate_den` is zero.
    pub fn new(faucet_id: AccountId, rate_num: u32, rate_den: u32) -> Result<Self, NoteError> {
        if rate_num == 0 {
            return Err(NoteError::other("fee conversion rate numerator must be non-zero"));
        }
        if rate_den == 0 {
            return Err(NoteError::other("fee conversion rate denominator must be non-zero"));
        }

        Ok(Self { faucet_id, rate_num, rate_den })
    }

    /// Creates fee conversion info paying the fee in the asset issued by `faucet_id` at the
    /// trivial rate 1/1, e.g. to pay in the native fee asset itself.
    pub fn trivial(faucet_id: AccountId) -> Self {
        Self { faucet_id, rate_num: 1, rate_den: 1 }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the ID of the faucet issuing the fee payment asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the numerator of the conversion rate.
    pub fn rate_num(&self) -> u32 {
        self.rate_num
    }

    /// Returns the denominator of the conversion rate.
    pub fn rate_den(&self) -> u32 {
        self.rate_den
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Returns the conversion info encoded as a word.
    ///
    /// The layout must be kept in sync with `load_conversion_info` in the
    /// `miden::standards::fee` MASM module.
    pub fn to_word(&self) -> Word {
        Word::from([
            self.faucet_id.suffix(),
            self.faucet_id.prefix().as_felt(),
            Felt::from(self.rate_num),
            Felt::from(self.rate_den),
        ])
    }
}

// AUTH ARGS COMMITMENT
// ================================================================================================

/// Commits to the given conversion info under `salt` for passing to the authentication
/// procedure via the transaction's auth args.
///
/// Returns the auth args together with the advice map value holding their preimage: the auth
/// args are the commitment `hash(CONVERSION_INFO || SALT)` and the advice map must map them to
/// `[SALT, CONVERSION_INFO]`, which `miden::standards::fee::load_conversion_info` reads and
/// verifies in-VM.
///
/// Committing via the auth args means the signature over the transaction summary authorizes the
/// payment asset and rate, while the salt slot keeps the auth args usable as a unique salt for
/// replay protection.
pub fn commit_fee_conversion_info(
    conversion_info: FeeConversionInfo,
    salt: Word,
) -> (Word, Vec<Felt>) {
    let info_word = conversion_info.to_word();

    let mut value = Vec::with_capacity(8);
    value.extend(salt.iter());
    value.extend(info_word.iter());

    (Hasher::merge(&[info_word, salt]), value)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::AccountType;

    use super::*;

    fn faucet() -> AccountId {
        AccountId::builder()
            .account_type(AccountType::Public)
            .build_with_seed([3u8; 32])
    }

    /// A zero rate numerator or denominator is rejected by construction.
    #[test]
    fn zero_rates_are_rejected() {
        assert!(FeeConversionInfo::new(faucet(), 0, 1).is_err());
        assert!(FeeConversionInfo::new(faucet(), 1, 0).is_err());
        assert!(FeeConversionInfo::new(faucet(), 1, 1).is_ok());
    }

    /// The advice map value is the preimage of the auth args commitment.
    #[test]
    fn advice_map_value_is_commitment_preimage() {
        let payment_info = FeeConversionInfo::new(faucet(), 2, 3).unwrap();
        let salt = Word::from([1u32, 2, 3, 4]);

        let (key, value) = commit_fee_conversion_info(payment_info, salt);

        assert_eq!(key, Hasher::merge(&[payment_info.to_word(), salt]));
        assert_eq!(value.len(), 8);
        assert_eq!(&value[..4], salt.as_elements());
        assert_eq!(&value[4..], payment_info.to_word().as_elements());
    }
}

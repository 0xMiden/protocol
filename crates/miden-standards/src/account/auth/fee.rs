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
/// To pay in the native fee asset, use [`Self::native`], which commits to the native fee faucet
/// at rate 1/1.
///
/// The conversion info is committed to via the transaction's auth args: the auth args must be set
/// to [`Self::auth_args`], which is the hash of the conversion info together with a caller-chosen
/// salt, and the advice map must contain the preimage under that commitment (see
/// [`Self::advice_map_entry`]). The salt slot keeps the auth args usable as a unique salt for
/// replay protection while committing to the conversion info.
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

    /// Creates fee conversion info paying the fee in the native fee asset issued by
    /// `fee_faucet_id` (from the reference block's fee parameters), i.e. at rate 1/1.
    pub fn native(fee_faucet_id: AccountId) -> Self {
        Self {
            faucet_id: fee_faucet_id,
            rate_num: 1,
            rate_den: 1,
        }
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
            self.faucet_id.prefix().as_felt(),
            self.faucet_id.suffix(),
            Felt::from(self.rate_num),
            Felt::from(self.rate_den),
        ])
    }

    /// Returns the auth args committing to this conversion info under the given salt.
    pub fn auth_args(&self, salt: Word) -> Word {
        Hasher::merge(&[self.to_word(), salt])
    }

    /// Returns the advice map entry that must accompany the auth args commitment: the key is
    /// [`Self::auth_args`] and the value is the preimage `[SALT, CONVERSION_INFO]`.
    pub fn advice_map_entry(&self, salt: Word) -> (Word, Vec<Felt>) {
        let mut value = Vec::with_capacity(8);
        value.extend(salt.iter());
        value.extend(self.to_word().iter());

        (self.auth_args(salt), value)
    }
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

        let (key, value) = payment_info.advice_map_entry(salt);

        assert_eq!(key, payment_info.auth_args(salt));
        assert_eq!(value.len(), 8);
        assert_eq!(&value[..4], salt.as_elements());
        assert_eq!(&value[4..], payment_info.to_word().as_elements());
    }
}

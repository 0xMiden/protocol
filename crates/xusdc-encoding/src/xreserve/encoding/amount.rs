//! Reducing a deposit's uint256 amount to a Miden asset amount.
//!
//! Circle states deposit amounts as 256-bit values in the source token's smallest units; a Miden
//! fungible asset amount is a `u64` bounded by `AssetAmount::MAX`. Every mint therefore has to
//! cross that gap, and this is the only place it happens: on-chain the faucet does NOT divide,
//! because under `DC-14` the uint256 never reaches the chain at all.
//!
//! The arithmetic is the standards' [`EthAmount::scale_to_asset_amount`]. What lives here is its
//! adaptation to this crate's error type and the golden vectors that pin the behaviour Circle's
//! numbers depend on. Nothing saturates and nothing truncates silently: every path out is either
//! an exact value or an error.
//!
//! The exact cap is still Circle's to decide (`DEV-5`, OPEN). The mechanism is implemented; the
//! numbers it is parameterized with remain open, and nothing here should be read as settling them.

use miden_protocol::asset::AssetAmount;
use miden_standards::interop::eth::EthAmount;

use super::error::EncodingError;

/// The decimal scale every deposit amount is reduced at, and the only scale this transport can
/// express.
///
/// Circle's on-wire deposit `amount` is in 6-decimal smallest units and xUSDC is 6-decimal, so the
/// reduction is the identity. It cannot become anything else without a new transport: `DC-14`
/// zero-extends the carried `AssetAmount` back into its uint256 field when the faucet rebuilds the
/// signed message, which is lossless only at scale zero — at any other scale the remainder the
/// reduction dropped is unrecoverable and the rebuilt digest stops matching what Circle signed.
/// `constant_parity.rs` pins the value so a change fails a test rather than shipping a preimage
/// that can never verify. `DEV-5` stays OPEN.
pub(super) const DEPOSIT_SCALE_EXP: u32 = 0;

/// uint256 → AssetAmount at [`DEPOSIT_SCALE_EXP`]: `y = floor(x / 10^DEPOSIT_SCALE_EXP)`, rejecting
/// a quotient wider than a `u64` (`AmountTooLarge`) and a quotient past `AssetAmount::MAX`
/// (`AmountOverCap`). No saturation or clamping.
pub(super) fn uint256_to_asset_amount(amount: EthAmount) -> Result<AssetAmount, EncodingError> {
    let y = amount.scale_to_asset_amount(DEPOSIT_SCALE_EXP)?;
    // the standards routine bounds the quotient by the maximum fungible amount, which is
    // AssetAmount::MAX, so this conversion only re-states that bound in the type
    AssetAmount::try_from(y).map_err(|_| EncodingError::AmountOverCap)
}

// TESTS — TV-AMT-1..4
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-AMT-1 (happy path, written first): in-bound amounts reduce to themselves.
    #[test]
    fn tv_amt_1_in_bound() {
        let v = load();
        for vec in v
            .families
            .amt
            .iter()
            .filter(|v| v.kind == "accept" && v.id != "amt-cap-accept")
        {
            let y = uint256_to_asset_amount(vec.amount())
                .unwrap_or_else(|e| panic!("vector {}: must accept, got {e}", vec.id));
            assert_eq!(
                y,
                vec.expected_amount(),
                "vector {}: reduced amount",
                vec.id
            );
        }
    }

    /// TV-AMT-2 (boundary): exactly `AssetAmount::MAX = 2^63 − 2^31` is accepted at the cap
    /// (required cap-boundary edge).
    #[test]
    fn tv_amt_2_cap_boundary_accept() {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == "amt-cap-accept")
            .expect("vector");
        let y = uint256_to_asset_amount(vec.amount())
            .unwrap_or_else(|e| panic!("vector {}: must accept at cap, got {e}", vec.id));
        assert_eq!(y, vec.expected_amount(), "vector {}: cap boundary", vec.id);
        assert_eq!(
            y,
            AssetAmount::MAX,
            "cap boundary must equal AssetAmount::MAX"
        );
    }

    /// TV-AMT-3/4 (negative, parametrized): rejects pin their SPECIFIC variants — cap exceeded /
    /// limb overflow (required edge).
    #[rstest]
    #[case::tv_amt_3_cap_reject("amt-rej-cap")]
    #[case::tv_amt_4_limb_overflow("amt-rej-limb-overflow")]
    fn tv_amt_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .amt
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = uint256_to_asset_amount(vec.amount());
        match vec.expected_variant.as_deref() {
            Some("AmountOverCap") => {
                assert_matches!(result, Err(EncodingError::AmountOverCap), "vector {id}")
            }
            Some("AmountTooLarge") => {
                assert_matches!(result, Err(EncodingError::AmountTooLarge), "vector {id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }
}

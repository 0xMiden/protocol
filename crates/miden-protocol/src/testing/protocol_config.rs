use crate::account::AccountId;
use crate::asset::AssetId;
use crate::protocol_config::ProtocolConfig;
use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

impl ProtocolConfig {
    /// Returns the [`ProtocolConfig`] that test fixtures commit to.
    ///
    /// It describes the currently linked kernels and uses
    /// [`ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET`] as the fee faucet.
    pub fn mock() -> Self {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("mock fee faucet ID should be valid");

        ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
            .expect("mock protocol config should be valid")
    }
}

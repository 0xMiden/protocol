use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use miden_protocol::account::AccountProcedureRoot;
use miden_protocol::errors::AccountError;

use super::HotColdPolicy;
use crate::account::auth::{Approver, GuardianConfig};

// CONSTANTS
// ================================================================================================

/// The user key categories: hot and cold. Thresholds count signed categories, so this is the
/// highest threshold a policy can require.
pub const NUM_USER_KEY_CATEGORIES: u32 = 2;

/// The maximum number of hot keys. Together with the cold and the guardian key this stays within
/// the signer set size the multisig fee estimate is calibrated for.
pub const MAX_NUM_HOT_KEYS: usize = 62;

/// The default threshold in signed categories: any one user key category plus the guardian.
pub const DEFAULT_THRESHOLD: u32 = 1;

/// The number of blocks in an hour, assuming a 3 second block time.
pub const BLOCKS_PER_HOUR: u32 = 1200;

/// The shortest delay an account may configure: 24 hours, so that a cold key kept elsewhere can
/// be reached before a delayed action executes.
pub const MIN_DELAY_FLOOR_BLOCKS: u32 = 24 * BLOCKS_PER_HOUR;

/// The default delay: 2 days.
pub const DEFAULT_MIN_DELAY_BLOCKS: u32 = 48 * BLOCKS_PER_HOUR;

/// The default number of blocks a proposal transaction stays includable after its reference block.
pub const DEFAULT_PROPOSE_EXPIRATION_DELTA: u16 = 20;

// DELAY CONFIG
// ================================================================================================

/// The delay configuration of [`AuthHotColdGuardian`](super::AuthHotColdGuardian).
///
/// A single delay applies to every delayed action of the account. `min_delay` is the number of
/// blocks a proposal waits before it can execute, at least [`MIN_DELAY_FLOOR_BLOCKS`] with no upper
/// bound, since the immediate path stays available to both categories plus the guardian.
/// `propose_expiration_delta` bounds how many blocks after its reference block a proposal
/// transaction stays includable. `cancel_threshold` is the minimum number of signed categories a
/// cancellation needs.
///
/// The configuration is stored on chain as `[min_delay, propose_expiration_delta,
/// cancel_threshold, 0]`. The delayed-execution flows themselves are not part of this component
/// yet; the configuration is stored so adding them needs no storage change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotColdDelayConfig {
    min_delay: u32,
    propose_expiration_delta: u16,
    cancel_threshold: u32,
}

impl HotColdDelayConfig {
    /// Creates a new delay configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `min_delay` is below [`MIN_DELAY_FLOOR_BLOCKS`], if
    /// `propose_expiration_delta` is zero or if `cancel_threshold` is zero or exceeds
    /// [`NUM_USER_KEY_CATEGORIES`].
    pub fn new(
        min_delay: u32,
        propose_expiration_delta: u16,
        cancel_threshold: u32,
    ) -> Result<Self, AccountError> {
        if min_delay < MIN_DELAY_FLOOR_BLOCKS {
            return Err(AccountError::other("min_delay is below the minimum delay"));
        }
        if propose_expiration_delta == 0 {
            return Err(AccountError::other("propose_expiration_delta must be non-zero"));
        }
        if cancel_threshold == 0 {
            return Err(AccountError::other("cancel_threshold must be non-zero"));
        }
        if cancel_threshold > NUM_USER_KEY_CATEGORIES {
            return Err(AccountError::other(
                "cancel_threshold cannot exceed the number of user key categories",
            ));
        }
        Ok(Self {
            min_delay,
            propose_expiration_delta,
            cancel_threshold,
        })
    }

    pub fn min_delay(&self) -> u32 {
        self.min_delay
    }

    pub fn propose_expiration_delta(&self) -> u16 {
        self.propose_expiration_delta
    }

    pub fn cancel_threshold(&self) -> u32 {
        self.cancel_threshold
    }
}

impl Default for HotColdDelayConfig {
    /// Returns the default configuration: a 2 day delay, a 20 block proposal window and a
    /// cancellation threshold of one category.
    fn default() -> Self {
        Self {
            min_delay: DEFAULT_MIN_DELAY_BLOCKS,
            propose_expiration_delta: DEFAULT_PROPOSE_EXPIRATION_DELTA,
            cancel_threshold: 1,
        }
    }
}

// COMPONENT CONFIG
// ================================================================================================

/// Configuration for the [`AuthHotColdGuardian`](super::AuthHotColdGuardian) component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHotColdGuardianConfig {
    hot_keys: Vec<Approver>,
    cold_key: Approver,
    guardian_config: GuardianConfig,
    delay_config: HotColdDelayConfig,
    procedure_policies: BTreeMap<AccountProcedureRoot, HotColdPolicy>,
}

impl AuthHotColdGuardianConfig {
    /// Creates a new configuration from the hot keys, the cold key, the guardian and the delay
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no hot keys or more than [`MAX_NUM_HOT_KEYS`], or if a public
    /// key appears in more than one category. On chain only the guardian key is kept distinct from
    /// the user keys (by the key-changing procedures); a repeated hot key, or a key used as both
    /// hot and cold, is rejected here only.
    pub fn new(
        hot_keys: Vec<Approver>,
        cold_key: Approver,
        guardian_config: GuardianConfig,
        delay_config: HotColdDelayConfig,
    ) -> Result<Self, AccountError> {
        if hot_keys.is_empty() {
            return Err(AccountError::other("at least one hot key is required"));
        }
        if hot_keys.len() > MAX_NUM_HOT_KEYS {
            return Err(AccountError::other(
                "number of hot keys exceeds the maximum hot key set size",
            ));
        }

        let mut public_keys = BTreeSet::new();
        for approver in hot_keys
            .iter()
            .chain(core::iter::once(&cold_key))
            .chain(core::iter::once(&guardian_config.approver()))
        {
            if !public_keys.insert(approver.pub_key()) {
                return Err(AccountError::other(
                    "a public key may belong to only one key category",
                ));
            }
        }

        Ok(Self {
            hot_keys,
            cold_key,
            guardian_config,
            delay_config,
            procedure_policies: BTreeMap::new(),
        })
    }

    /// Attaches procedure policies, e.g. for the procedures of a wallet installed next to the
    /// component. A policy for one of the component's own procedures replaces its preset, see
    /// [`AuthHotColdGuardian::preset_policies`](super::AuthHotColdGuardian::preset_policies).
    ///
    /// # Errors
    ///
    /// Returns an error if a policy is set on the component's auth procedure, which never
    /// contributes to the policies.
    pub fn with_proc_policies(
        mut self,
        proc_policies: BTreeMap<AccountProcedureRoot, HotColdPolicy>,
    ) -> Result<Self, AccountError> {
        if proc_policies.contains_key(&super::AuthHotColdGuardian::auth_tx_root()) {
            return Err(AccountError::other(
                "procedure policy cannot be set on the auth procedure",
            ));
        }

        self.procedure_policies = proc_policies;
        Ok(self)
    }

    pub fn hot_keys(&self) -> &[Approver] {
        &self.hot_keys
    }

    pub fn cold_key(&self) -> Approver {
        self.cold_key
    }

    pub fn guardian_config(&self) -> GuardianConfig {
        self.guardian_config
    }

    pub fn delay_config(&self) -> HotColdDelayConfig {
        self.delay_config
    }

    pub fn procedure_policies(&self) -> &BTreeMap<AccountProcedureRoot, HotColdPolicy> {
        &self.procedure_policies
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;

    fn approver() -> Approver {
        let key = AuthSecretKey::new_ecdsa_k256_keccak();
        Approver::new(key.public_key().to_commitment(), key.auth_scheme())
    }

    #[test]
    fn delay_config_rejects_out_of_range_values() {
        let below = HotColdDelayConfig::new(MIN_DELAY_FLOOR_BLOCKS - 1, 20, 1).unwrap_err();
        assert!(below.to_string().contains("below the minimum delay"));

        let zero_delta = HotColdDelayConfig::new(MIN_DELAY_FLOOR_BLOCKS, 0, 1).unwrap_err();
        assert!(zero_delta.to_string().contains("propose_expiration_delta must be non-zero"));

        let zero_cancel = HotColdDelayConfig::new(MIN_DELAY_FLOOR_BLOCKS, 20, 0).unwrap_err();
        assert!(zero_cancel.to_string().contains("cancel_threshold must be non-zero"));

        let cancel_above = HotColdDelayConfig::new(MIN_DELAY_FLOOR_BLOCKS, 20, 3).unwrap_err();
        assert!(
            cancel_above
                .to_string()
                .contains("cannot exceed the number of user key categories")
        );

        assert!(HotColdDelayConfig::new(u32::MAX, 20, 2).is_ok());
    }

    #[test]
    fn config_rejects_empty_hot_keys() {
        let err = AuthHotColdGuardianConfig::new(
            vec![],
            approver(),
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("at least one hot key is required"));
    }

    #[test]
    fn config_rejects_too_many_hot_keys() {
        let hot_keys = (0..=MAX_NUM_HOT_KEYS).map(|_| approver()).collect();
        let err = AuthHotColdGuardianConfig::new(
            hot_keys,
            approver(),
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds the maximum hot key set size"));
    }

    #[test]
    fn config_rejects_a_key_in_two_categories() {
        let shared = approver();

        let hot_is_cold = AuthHotColdGuardianConfig::new(
            vec![shared],
            shared,
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap_err();
        assert!(hot_is_cold.to_string().contains("only one key category"));

        let cold_is_guardian = AuthHotColdGuardianConfig::new(
            vec![approver()],
            shared,
            GuardianConfig::new(shared),
            HotColdDelayConfig::default(),
        )
        .unwrap_err();
        assert!(cold_is_guardian.to_string().contains("only one key category"));

        let duplicate_hot = AuthHotColdGuardianConfig::new(
            vec![shared, shared],
            approver(),
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap_err();
        assert!(duplicate_hot.to_string().contains("only one key category"));
    }

    #[test]
    fn config_rejects_a_policy_on_the_auth_procedure() {
        let err = AuthHotColdGuardianConfig::new(
            vec![approver()],
            approver(),
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap()
        .with_proc_policies(BTreeMap::from([(
            super::super::AuthHotColdGuardian::auth_tx_root(),
            HotColdPolicy::ColdOnly,
        )]))
        .unwrap_err();
        assert!(err.to_string().contains("cannot be set on the auth procedure"));
    }
}

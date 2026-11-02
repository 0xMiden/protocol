use super::ProtocolConfigError;
use crate::block::BlockNumber;
use crate::{Hasher, Word, ZERO};

// NEXT PROTOCOL CONFIG
// ================================================================================================

/// A protocol upgrade that is scheduled but not yet in effect.
///
/// Committing to an upgrade ahead of time lets clients that come online before `effective_from`
/// learn about it and update before the switch happens, instead of being blocked once it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextProtocolConfig {
    /// The number of the first block for which the new configuration is in effect.
    effective_from: BlockNumber,

    /// The commitment to the [`ProtocolConfig`](super::ProtocolConfig) that becomes effective.
    protocol_config: Word,
}

impl NextProtocolConfig {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NextProtocolConfig`] from the provided inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if `effective_from` is [`BlockNumber::GENESIS`]. The genesis block defines
    /// the initial configuration, so no upgrade can become effective at it, and on-chain the
    /// genesis block number is the encoding of "no upgrade scheduled".
    pub fn new(
        effective_from: BlockNumber,
        protocol_config: Word,
    ) -> Result<Self, ProtocolConfigError> {
        if effective_from == BlockNumber::GENESIS {
            return Err(ProtocolConfigError::NextConfigEffectiveAtGenesis);
        }

        Ok(Self { effective_from, protocol_config })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of the first block for which the new configuration is in effect.
    pub fn effective_from(&self) -> BlockNumber {
        self.effective_from
    }

    /// Returns the commitment to the [`ProtocolConfig`](super::ProtocolConfig) that becomes
    /// effective.
    pub fn protocol_config(&self) -> Word {
        self.protocol_config
    }

    /// Returns a commitment to this scheduled upgrade.
    ///
    /// A block header without a scheduled upgrade commits to [`Word::empty`], which this commitment
    /// can never collide with because `effective_from` is never zero.
    pub fn to_commitment(&self) -> Word {
        let effective_from = Word::new([self.effective_from.into(), ZERO, ZERO, ZERO]);
        Hasher::merge(&[effective_from, self.protocol_config])
    }
}

// SERIALIZATION
// ================================================================================================

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rand::random;

    use super::*;

    #[test]
    fn commitment_binds_both_fields() {
        let config = random::<Word>();
        let next = NextProtocolConfig::new(BlockNumber::from(10u32), config).unwrap();
        let other_block = NextProtocolConfig::new(BlockNumber::from(11u32), config).unwrap();
        let other_config =
            NextProtocolConfig::new(BlockNumber::from(10u32), random::<Word>()).unwrap();

        assert_ne!(next.to_commitment(), other_block.to_commitment());
        assert_ne!(next.to_commitment(), other_config.to_commitment());
    }

    #[test]
    fn new_rejects_genesis() {
        let error = NextProtocolConfig::new(BlockNumber::GENESIS, Word::empty()).unwrap_err();
        assert_matches!(error, ProtocolConfigError::NextConfigEffectiveAtGenesis);
    }
}

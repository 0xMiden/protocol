//! Circle's domain identifier: the `u32` Circle assigns each chain it attests for.

use core::fmt;
use core::num::ParseIntError;
use core::str::FromStr;

use miden_protocol::Felt;
use serde::{Deserialize, Serialize};

/// A Circle domain identifier — the number Circle assigns a chain.
///
/// It names Miden as the `remoteDomain` a deposit is addressed to and the faucet is configured
/// with, and the source chains a withdrawal can be sent to as its destination domain. Every `u32`
/// is a well-formed identifier; which one Circle assigns Miden is still open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CircleDomain(u32);

impl CircleDomain {
    /// Miden's domain identifier.
    ///
    /// TODO: Circle has not assigned Miden a domain yet, so this is a placeholder. Replace it with
    /// the real value once Circle confirms it.
    pub const MIDEN: Self = Self(0);

    /// Wraps a Circle domain identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The identifier as the `u32` Circle's wire forms carry.
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Default for CircleDomain {
    /// Defaults to [`Self::MIDEN`], the domain this deployment runs on.
    fn default() -> Self {
        Self::MIDEN
    }
}

impl From<u32> for CircleDomain {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<CircleDomain> for u32 {
    fn from(domain: CircleDomain) -> Self {
        domain.0
    }
}

impl From<CircleDomain> for Felt {
    fn from(domain: CircleDomain) -> Self {
        Felt::from(domain.0)
    }
}

impl FromStr for CircleDomain {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self::new)
    }
}

impl fmt::Display for CircleDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::CircleDomain;

    #[test]
    fn a_domain_parses_from_a_32_bit_number() {
        assert_eq!("7".parse::<CircleDomain>().unwrap(), CircleDomain::new(7));
        assert!("".parse::<CircleDomain>().is_err());
        assert!("abc".parse::<CircleDomain>().is_err());
        assert!("-1".parse::<CircleDomain>().is_err());
        assert!("4294967296".parse::<CircleDomain>().is_err());
    }

    #[test]
    fn a_domain_deserializes_from_a_bare_number() {
        let domain: CircleDomain = serde_json::from_str("10007").unwrap();
        assert_eq!(domain, CircleDomain::new(10007));
        assert_eq!(serde_json::to_string(&domain).unwrap(), "10007");
    }
}

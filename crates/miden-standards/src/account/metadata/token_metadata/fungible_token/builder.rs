use miden_protocol::asset::TokenSymbol;

use super::super::{TokenMetadata, TokenName};
use super::{Description, ExternalLink, FungibleTokenMetadata, LogoURI};
use crate::account::faucets::FungibleFaucetError;

/// Builder for [`FungibleTokenMetadata`] to avoid unwieldy optional arguments.
///
/// Required fields are set in [`Self::new`]; optional fields and token supply
/// can be set via chainable methods. Token supply defaults to zero.
///
/// # Example
///
/// ```
/// # use miden_protocol::asset::TokenSymbol;
/// # use miden_standards::account::metadata::{
/// #     Description, FungibleTokenMetadataBuilder, LogoURI, TokenName,
/// # };
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let name = TokenName::new("My Token")?;
/// let symbol = TokenSymbol::new("MTK")?;
/// let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 8, 1_000_000)
///     .token_supply(100)
///     .description(Description::new("A test token")?)
///     .logo_uri(LogoURI::new("https://example.com/logo.png")?)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FungibleTokenMetadataBuilder {
    name: TokenName,
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: u64,
    token_supply: u64,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
    is_description_mutable: bool,
    is_logo_uri_mutable: bool,
    is_external_link_mutable: bool,
    is_max_supply_mutable: bool,
}

impl FungibleTokenMetadataBuilder {
    /// Creates a new builder with required fields. Token supply defaults to zero.
    ///
    /// # Parameters
    ///
    /// - `name`: display name (at most 32 UTF-8 bytes).
    /// - `symbol`: token symbol.
    /// - `decimals`: decimal precision; must be in the range `0..=12`.
    /// - `max_supply`: maximum number of tokens that can ever be minted; must be in the range
    ///   `0..=FungibleAsset::MAX_AMOUNT` (≤ 2^63 − 1). Expressed as a `u64` rather than a `Felt` to
    ///   avoid accidental out-of-range values.
    pub fn new(name: TokenName, symbol: TokenSymbol, decimals: u8, max_supply: u64) -> Self {
        Self {
            name,
            symbol,
            decimals,
            max_supply,
            token_supply: 0,
            description: None,
            logo_uri: None,
            external_link: None,
            is_description_mutable: false,
            is_logo_uri_mutable: false,
            is_external_link_mutable: false,
            is_max_supply_mutable: false,
        }
    }

    /// Sets the initial token supply (default is zero).
    pub fn token_supply(mut self, token_supply: u64) -> Self {
        self.token_supply = token_supply;
        self
    }

    /// Sets the optional description.
    pub fn description(mut self, description: Description) -> Self {
        self.description = Some(description);
        self
    }

    /// Sets the optional logo URI.
    pub fn logo_uri(mut self, logo_uri: LogoURI) -> Self {
        self.logo_uri = Some(logo_uri);
        self
    }

    /// Sets the optional external link.
    pub fn external_link(mut self, external_link: ExternalLink) -> Self {
        self.external_link = Some(external_link);
        self
    }

    /// Sets whether the description can be updated by the owner.
    pub fn is_description_mutable(mut self, mutable: bool) -> Self {
        self.is_description_mutable = mutable;
        self
    }

    /// Sets whether the logo URI can be updated by the owner.
    pub fn is_logo_uri_mutable(mut self, mutable: bool) -> Self {
        self.is_logo_uri_mutable = mutable;
        self
    }

    /// Sets whether the external link can be updated by the owner.
    pub fn is_external_link_mutable(mut self, mutable: bool) -> Self {
        self.is_external_link_mutable = mutable;
        self
    }

    /// Sets whether the max supply can be updated by the owner.
    pub fn is_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.is_max_supply_mutable = mutable;
        self
    }

    /// Builds [`FungibleTokenMetadata`].
    pub fn build(self) -> Result<FungibleTokenMetadata, FungibleFaucetError> {
        let mut token_metadata = TokenMetadata::new(self.name);
        if let Some(desc) = self.description {
            token_metadata = token_metadata.with_description(desc, self.is_description_mutable);
        } else {
            token_metadata = token_metadata.with_description_mutable(self.is_description_mutable);
        }
        if let Some(uri) = self.logo_uri {
            token_metadata = token_metadata.with_logo_uri(uri, self.is_logo_uri_mutable);
        } else {
            token_metadata = token_metadata.with_logo_uri_mutable(self.is_logo_uri_mutable);
        }
        if let Some(link) = self.external_link {
            token_metadata = token_metadata.with_external_link(link, self.is_external_link_mutable);
        } else {
            token_metadata =
                token_metadata.with_external_link_mutable(self.is_external_link_mutable);
        }
        token_metadata = token_metadata.with_max_supply_mutable(self.is_max_supply_mutable);

        FungibleTokenMetadata::new_validated(
            self.symbol,
            self.decimals,
            self.max_supply,
            self.token_supply,
            token_metadata,
        )
    }
}

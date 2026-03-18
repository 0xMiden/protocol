use miden_protocol::Felt;
use miden_protocol::asset::TokenSymbol;

use super::super::TokenName;
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
/// # use miden_protocol::Felt;
/// # use miden_standards::account::faucets::{
/// #     Description, FungibleTokenMetadataBuilder, LogoURI, TokenName,
/// # };
/// let name = TokenName::new("My Token").unwrap();
/// let symbol = TokenSymbol::new("MTK").unwrap();
/// let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 8, Felt::new(1_000_000))
///     .token_supply(Felt::new(100))
///     .description(Description::new("A test token").unwrap())
///     .logo_uri(LogoURI::new("https://example.com/logo.png").unwrap())
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct FungibleTokenMetadataBuilder {
    name: TokenName,
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
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
    pub fn new(name: TokenName, symbol: TokenSymbol, decimals: u8, max_supply: Felt) -> Self {
        Self {
            name,
            symbol,
            decimals,
            max_supply,
            token_supply: Felt::ZERO,
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
    pub fn token_supply(mut self, token_supply: Felt) -> Self {
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
        let mut meta = FungibleTokenMetadata::with_supply(
            self.symbol,
            self.decimals,
            self.max_supply,
            self.token_supply,
            self.name,
            self.description,
            self.logo_uri,
            self.external_link,
        )?;
        meta = meta
            .with_description_mutable(self.is_description_mutable)
            .with_logo_uri_mutable(self.is_logo_uri_mutable)
            .with_external_link_mutable(self.is_external_link_mutable)
            .with_max_supply_mutable(self.is_max_supply_mutable);
        Ok(meta)
    }
}

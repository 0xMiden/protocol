use miden_protocol::asset::TokenSymbol;
use miden_protocol::{Felt, Word};

use super::{mutability_config_slot, *};
use crate::account::metadata::{Description, ExternalLink, LogoURI};

#[test]
fn token_metadata_new() {
    let symbol = TokenSymbol::new("TEST").unwrap();
    let decimals = 8u8;
    let max_supply = 1_000_000u64;
    let name = TokenName::new("TEST").unwrap();

    let metadata =
        FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), decimals, max_supply)
            .build()
            .unwrap();

    assert_eq!(metadata.symbol(), &symbol);
    assert_eq!(metadata.decimals(), decimals);
    assert_eq!(metadata.max_supply(), Felt::new(max_supply));
    assert_eq!(metadata.token_supply(), Felt::ZERO);
    assert_eq!(metadata.name(), &name);
    assert!(metadata.description().is_none());
    assert!(metadata.logo_uri().is_none());
    assert!(metadata.external_link().is_none());
}

#[test]
fn token_metadata_with_supply() {
    let symbol = TokenSymbol::new("TEST").unwrap();
    let decimals = 8u8;
    let max_supply = 1_000_000u64;
    let token_supply = 500_000u64;
    let name = TokenName::new("TEST").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
        .token_supply(token_supply)
        .build()
        .unwrap();

    assert_eq!(metadata.symbol(), &symbol);
    assert_eq!(metadata.decimals(), decimals);
    assert_eq!(metadata.max_supply(), Felt::new(max_supply));
    assert_eq!(metadata.token_supply(), Felt::new(token_supply));
}

#[test]
fn token_metadata_builder_with_optionals() {
    let symbol = TokenSymbol::new("MTK").unwrap();
    let name = TokenName::new("My Token").unwrap();
    let description = Description::new("A test token").unwrap();
    let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
    let external_link = ExternalLink::new("https://example.com").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), 8, 1_000_000u64)
        .token_supply(100)
        .description(description.clone())
        .logo_uri(logo_uri.clone())
        .external_link(external_link.clone())
        .is_description_mutable(true)
        .is_max_supply_mutable(true)
        .build()
        .unwrap();

    assert_eq!(metadata.token_supply(), Felt::new(100u64));
    assert_eq!(metadata.description(), Some(&description));
    assert_eq!(metadata.logo_uri(), Some(&logo_uri));
    assert_eq!(metadata.external_link(), Some(&external_link));
    let slots = metadata.into_storage_slots();
    let config_word = slots[3].value();
    assert_eq!(config_word[0], Felt::from(1u32), "is_desc_mutable");
    assert_eq!(config_word[3], Felt::from(1u32), "is_max_supply_mutable");
}

#[test]
fn token_metadata_with_name_and_description() {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use crate::account::auth::NoAuth;
    use crate::account::faucets::BasicFungibleFaucet;

    let symbol = TokenSymbol::new("POL").unwrap();
    let decimals = 2u8;
    let max_supply = 123u64;
    let name = TokenName::new("polygon").unwrap();
    let description = Description::new("A polygon token").unwrap();

    let metadata =
        FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), decimals, max_supply)
            .description(description.clone())
            .build()
            .unwrap();

    assert_eq!(metadata.symbol(), &symbol);
    assert_eq!(metadata.name(), &name);
    assert_eq!(metadata.description(), Some(&description));

    let account = AccountBuilder::new([2u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata.clone())
        .with_component(BasicFungibleFaucet)
        .build()
        .expect("account build should succeed");

    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();
    assert_eq!(restored.symbol(), &symbol);
    assert_eq!(restored.name(), &name);
    assert_eq!(restored.description(), Some(&description));
}

#[test]
fn token_name_roundtrip() {
    let name = TokenName::new("polygon").unwrap();
    let words = name.to_words();
    let decoded = TokenName::try_from_words(&words).unwrap();
    assert_eq!(decoded.as_str(), "polygon");
}

#[test]
fn token_name_as_str() {
    let name = TokenName::new("my_token").unwrap();
    assert_eq!(name.as_str(), "my_token");
}

#[test]
fn token_name_too_long() {
    let s = "a".repeat(33);
    assert!(TokenName::new(&s).is_err());
}

#[test]
fn description_roundtrip() {
    let text = "A short description";
    let desc = Description::new(text).unwrap();
    let words = desc.to_words();
    let decoded = Description::try_from_words(&words).unwrap();
    assert_eq!(decoded.as_str(), text);
}

#[test]
fn description_too_long() {
    let s = "a".repeat(Description::MAX_BYTES + 1);
    assert!(Description::new(&s).is_err());
}

#[test]
fn logo_uri_roundtrip() {
    let url = "https://example.com/logo.png";
    let uri = LogoURI::new(url).unwrap();
    let words = uri.to_words();
    let decoded = LogoURI::try_from_words(&words).unwrap();
    assert_eq!(decoded.as_str(), url);
}

#[test]
fn external_link_roundtrip() {
    let url = "https://example.com";
    let link = ExternalLink::new(url).unwrap();
    let words = link.to_words();
    let decoded = ExternalLink::try_from_words(&words).unwrap();
    assert_eq!(decoded.as_str(), url);
}

#[test]
fn token_metadata_too_many_decimals() {
    let symbol = TokenSymbol::new("TEST").unwrap();
    let decimals = 13u8;
    let max_supply = 1_000_000u64;
    let name = TokenName::new("TEST").unwrap();

    let result = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply).build();
    assert!(matches!(result, Err(FungibleFaucetError::TooManyDecimals { .. })));
}

#[test]
fn token_metadata_max_supply_too_large() {
    use miden_protocol::asset::FungibleAsset;

    let symbol = TokenSymbol::new("TEST").unwrap();
    let decimals = 8u8;
    let max_supply = FungibleAsset::MAX_AMOUNT + 1;
    let name = TokenName::new("TEST").unwrap();

    let result = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply).build();
    assert!(matches!(result, Err(FungibleFaucetError::MaxSupplyTooLarge { .. })));
}

#[test]
fn token_metadata_to_word() {
    let symbol = TokenSymbol::new("POL").unwrap();
    let symbol_felt = symbol.as_element();
    let decimals = 2u8;
    let max_supply = 123u64;
    let name = TokenName::new("POL").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, decimals, max_supply)
        .build()
        .unwrap();
    let word = metadata.metadata_word_slot().value();

    assert_eq!(word[0], Felt::ZERO);
    assert_eq!(word[1], Felt::new(max_supply));
    assert_eq!(word[2], Felt::from(decimals));
    assert_eq!(word[3], symbol_felt);
}

#[test]
fn token_metadata_from_account_storage() {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use crate::account::auth::NoAuth;
    use crate::account::faucets::BasicFungibleFaucet;

    let symbol = TokenSymbol::new("POL").unwrap();
    let decimals = 2u8;
    let max_supply = 123u64;
    let name = TokenName::new("POL").unwrap();

    let original = FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
        .build()
        .unwrap();

    let account = AccountBuilder::new([3u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(original)
        .with_component(BasicFungibleFaucet)
        .build()
        .expect("account build should succeed");

    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

    assert_eq!(restored.symbol(), &symbol);
    assert_eq!(restored.decimals(), decimals);
    assert_eq!(restored.max_supply(), Felt::new(max_supply));
    assert_eq!(restored.token_supply(), Felt::ZERO);
}

#[test]
fn token_metadata_roundtrip_with_supply() {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use crate::account::auth::NoAuth;
    use crate::account::faucets::BasicFungibleFaucet;

    let symbol = TokenSymbol::new("POL").unwrap();
    let decimals = 2u8;
    let max_supply = 1000u64;
    let token_supply = 500u64;
    let name = TokenName::new("POL").unwrap();

    let original = FungibleTokenMetadataBuilder::new(name, symbol.clone(), decimals, max_supply)
        .token_supply(token_supply)
        .build()
        .unwrap();

    let account = AccountBuilder::new([4u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(original)
        .with_component(BasicFungibleFaucet)
        .build()
        .expect("account build should succeed");

    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

    assert_eq!(restored.symbol(), &symbol);
    assert_eq!(restored.decimals(), decimals);
    assert_eq!(restored.max_supply(), Felt::new(max_supply));
    assert_eq!(restored.token_supply(), Felt::new(token_supply));
}

#[test]
fn mutability_builders() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 1_000u64)
        .is_description_mutable(true)
        .is_logo_uri_mutable(true)
        .is_external_link_mutable(false)
        .is_max_supply_mutable(true)
        .build()
        .unwrap();

    let slots = metadata.into_storage_slots();

    // Slot layout (no owner slot): [0]=metadata, [1]=name_0, [2]=name_1, [3]=mutability_config
    let config_slot = &slots[3];
    let config_word = config_slot.value();
    assert_eq!(config_word[0], Felt::from(1u32), "is_desc_mutable");
    assert_eq!(config_word[1], Felt::from(1u32), "is_logo_mutable");
    assert_eq!(config_word[2], Felt::from(0u32), "is_extlink_mutable");
    assert_eq!(config_word[3], Felt::from(1u32), "is_max_supply_mutable");
}

#[test]
fn mutability_defaults_to_false() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 1_000u64).build().unwrap();

    let slots = metadata.into_storage_slots();
    let config_word = slots[3].value();
    assert_eq!(config_word[0], Felt::ZERO, "is_desc_mutable default");
    assert_eq!(config_word[1], Felt::ZERO, "is_logo_mutable default");
    assert_eq!(config_word[2], Felt::ZERO, "is_extlink_mutable default");
    assert_eq!(config_word[3], Felt::ZERO, "is_max_supply_mutable default");
}

#[test]
fn storage_slots_includes_metadata_word() {
    let symbol = TokenSymbol::new("POL").unwrap();
    let name = TokenName::new("polygon").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol.clone(), 2, 123u64)
        .build()
        .unwrap();
    let slots = metadata.into_storage_slots();

    // First slot is the metadata word [token_supply, max_supply, decimals, symbol]
    let metadata_word = slots[0].value();
    assert_eq!(metadata_word[0], Felt::ZERO); // token_supply
    assert_eq!(metadata_word[1], Felt::new(123)); // max_supply
    assert_eq!(metadata_word[2], Felt::from(2u32)); // decimals
    assert_eq!(metadata_word[3], Felt::from(symbol)); // symbol
}

#[test]
fn storage_slots_includes_name() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("my token").unwrap();
    let expected_words = name.to_words();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 100u64).build().unwrap();
    let slots = metadata.into_storage_slots();

    // Slot layout: [0]=metadata, [1]=name_0, [2]=name_1
    assert_eq!(slots[1].value(), expected_words[0]);
    assert_eq!(slots[2].value(), expected_words[1]);
}

#[test]
fn storage_slots_includes_description() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();
    let description = Description::new("A cool token").unwrap();
    let expected_words = description.to_words();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 100u64)
        .description(description)
        .build()
        .unwrap();
    let slots = metadata.into_storage_slots();

    // Slots 4..11 are description (7 words): after metadata(1) + name(2) + config(1)
    for (i, expected) in expected_words.iter().enumerate() {
        assert_eq!(slots[4 + i].value(), *expected, "description word {i}");
    }
}

#[test]
fn storage_slots_total_count() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 100u64).build().unwrap();
    let slots = metadata.into_storage_slots();

    // 1 metadata + 2 name + 1 config + 7 description + 7 logo + 7 external_link = 25
    assert_eq!(slots.len(), 25);
}

#[test]
fn into_account_component() {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use crate::account::auth::NoAuth;
    use crate::account::faucets::BasicFungibleFaucet;

    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("test token").unwrap();
    let description = Description::new("A test").unwrap();

    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 4, 10_000u64)
        .description(description)
        .is_max_supply_mutable(true)
        .build()
        .unwrap();

    // Should build an account successfully with FungibleTokenMetadata as a component
    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .build()
        .expect("account build should succeed");

    // Verify metadata slot is accessible
    let md_word = account.storage().get_item(FungibleTokenMetadata::metadata_slot()).unwrap();
    assert_eq!(md_word[1], Felt::new(10_000)); // max_supply
    assert_eq!(md_word[2], Felt::from(4u32)); // decimals

    // Verify mutability config
    let config = account.storage().get_item(mutability_config_slot()).unwrap();
    assert_eq!(config[3], Felt::from(1u32), "is_max_supply_mutable");
}

#[test]
fn roundtrip_via_storage_matches_original() {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use crate::account::auth::NoAuth;
    use crate::account::faucets::BasicFungibleFaucet;

    let symbol = TokenSymbol::new("RND").unwrap();
    let name = TokenName::new("Roundtrip Token").unwrap();
    let description = Description::new("Description").unwrap();
    let logo_uri = LogoURI::new("https://example.com/logo.png").unwrap();
    let external_link = ExternalLink::new("https://example.com").unwrap();

    let original = FungibleTokenMetadataBuilder::new(name.clone(), symbol.clone(), 6, 2_000_000u64)
        .token_supply(100_000)
        .description(description.clone())
        .logo_uri(logo_uri.clone())
        .external_link(external_link.clone())
        .is_description_mutable(true)
        .is_logo_uri_mutable(false)
        .is_external_link_mutable(true)
        .is_max_supply_mutable(false)
        .build()
        .unwrap();

    let account = AccountBuilder::new([5u8; 32])
        .account_type(AccountType::FungibleFaucet)
        .with_auth_component(NoAuth)
        .with_component(original)
        .with_component(BasicFungibleFaucet)
        .build()
        .expect("account build should succeed");

    let restored = FungibleTokenMetadata::try_from(account.storage()).unwrap();

    assert_eq!(restored.symbol(), &symbol);
    assert_eq!(restored.name(), &name);
    assert_eq!(restored.decimals(), 6);
    assert_eq!(restored.max_supply(), Felt::new(2_000_000));
    assert_eq!(restored.token_supply(), Felt::new(100_000));
    assert_eq!(restored.description(), Some(&description));
    assert_eq!(restored.logo_uri(), Some(&logo_uri));
    assert_eq!(restored.external_link(), Some(&external_link));
    let slots = restored.into_storage_slots();
    let config = slots[3].value();
    assert_eq!(config[0], Felt::from(1u32), "is_desc_mutable");
    assert_eq!(config[1], Felt::ZERO, "is_logo_mutable");
    assert_eq!(config[2], Felt::from(1u32), "is_extlink_mutable");
    assert_eq!(config[3], Felt::ZERO, "is_max_supply_mutable");
}

#[test]
fn logo_uri_too_long() {
    let s = "a".repeat(LogoURI::MAX_BYTES + 1);
    assert!(LogoURI::new(&s).is_err());
}

#[test]
fn external_link_too_long() {
    let s = "a".repeat(ExternalLink::MAX_BYTES + 1);
    assert!(ExternalLink::new(&s).is_err());
}

#[test]
fn name_max_32_bytes_accepted() {
    let s = "a".repeat(TokenName::MAX_BYTES);
    assert_eq!(s.len(), 32);
    let name = TokenName::new(&s).unwrap();
    let words = name.to_words();
    let decoded = TokenName::try_from_words(&words).unwrap();
    assert_eq!(decoded.as_str(), s);
}

#[test]
fn description_max_bytes_accepted() {
    let s = "a".repeat(Description::MAX_BYTES);
    let desc = Description::new(&s).unwrap();
    assert_eq!(desc.to_words().len(), 7);
}

#[test]
fn description_7_words_full_capacity() {
    let desc_text = "a".repeat(Description::MAX_BYTES);
    let description = Description::new(&desc_text).unwrap();
    let expected_words = description.to_words();

    let metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("T").unwrap(),
        TokenSymbol::new("TST").unwrap(),
        2,
        1_000u64,
    )
    .description(description)
    .build()
    .unwrap();

    let slots = metadata.into_storage_slots();
    // Description slots start at index 4: [0]=metadata, [1]=name_0, [2]=name_1, [3]=config
    for (i, expected) in expected_words.iter().enumerate() {
        assert_eq!(slots[4 + i].value(), *expected, "description word {i}");
    }
}

#[test]
fn token_supply_exceeds_max_supply() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();
    let max_supply = 100u64;
    let token_supply = 101u64;

    let result = FungibleTokenMetadataBuilder::new(name, symbol, 2, max_supply)
        .token_supply(token_supply)
        .build();
    assert!(matches!(result, Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply { .. })));
}

#[test]
fn with_token_supply_exceeds_max_supply() {
    let symbol = TokenSymbol::new("TST").unwrap();
    let name = TokenName::new("T").unwrap();
    let metadata = FungibleTokenMetadataBuilder::new(name, symbol, 2, 100u64).build().unwrap();

    let result = metadata.with_token_supply(Felt::new(101));
    assert!(matches!(result, Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply { .. })));
}

#[test]
fn invalid_token_symbol_in_metadata_word() {
    use super::super::TokenMetadata;

    // TokenSymbol::try_from(Felt) fails when the value exceeds MAX_ENCODED_VALUE.
    let bad_symbol = Felt::new(TokenSymbol::MAX_ENCODED_VALUE + 1);
    let bad_word = Word::from([Felt::ZERO, Felt::new(100), Felt::new(2), bad_symbol]);
    let token_metadata = TokenMetadata::new(TokenName::new("test").unwrap());
    let result =
        FungibleTokenMetadata::from_metadata_word_and_token_metadata(bad_word, token_metadata);
    assert!(matches!(result, Err(FungibleFaucetError::InvalidTokenSymbol(_))));
}

//! `build_components` refuses a DOM_PAUSER holder that holds any other role.
//! It also isolates BLK_MANAGER from every other holder; ADMIN, ATTEST_ADMIN and DOM_UNPAUSER may overlap.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};

fn builder_with_holders(
    attest_admin: AccountId,
    pauser: AccountId,
    unpauser: AccountId,
    blk_manager: AccountId,
) -> Result<XReserveStablecoinBuilder> {
    XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::new(0).context("valid token supply")?)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![attest_admin])
        .pauser_holders(vec![pauser])
        .unpauser_holders(vec![unpauser])
        .blocklist_manager_holders(vec![blk_manager])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()
        .context("the fixed-identity USDCx faucet builds")
}

/// Every blocklist-holder collision is rejected with the offending role named.
#[rstest]
#[case::administrator(test_account_id(1), "ADMIN")]
#[case::attest_admin(test_account_id(5), "ATTEST_ADMIN")]
#[case::dom_pauser(test_account_id(2), "DOM_PAUSER")]
#[case::dom_unpauser(test_account_id(3), "DOM_UNPAUSER")]
fn build_rejects_blk_manager_colliding_with_a_privileged_role(
    #[case] blk_manager: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let err = builder_with_holders(
        test_account_id(5),
        test_account_id(2),
        test_account_id(3),
        blk_manager,
    )?
    .build_components()
    .expect_err("a BLK_MANAGER holder colliding with a privileged role must be rejected");
    match err {
        XReserveStablecoinBuilderError::BlocklistManagerNotIsolated { collides_with } => {
            assert_eq!(
                collides_with, expected_role,
                "the rejection must name the collided privileged role"
            );
        }
        other => panic!("expected BlocklistManagerNotIsolated{{{expected_role}}}, got {other:?}"),
    }
    Ok(())
}

/// A pause holder cannot also carry a higher-consequence role.
#[rstest]
#[case::administrator(test_account_id(1), "ADMIN")]
#[case::attest_admin(test_account_id(5), "ATTEST_ADMIN")]
#[case::dom_unpauser(test_account_id(3), "DOM_UNPAUSER")]
fn build_rejects_dom_pauser_colliding_with_any_other_holder(
    #[case] pauser: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let err = builder_with_holders(
        test_account_id(5),
        pauser,
        test_account_id(3),
        test_account_id(4),
    )?
    .build_components()
    .expect_err("a DOM_PAUSER holder colliding with another role must be rejected");
    match err {
        XReserveStablecoinBuilderError::PauserNotIsolated { collides_with } => {
            assert_eq!(
                collides_with, expected_role,
                "the rejection must name the collided role"
            );
        }
        other => panic!("expected PauserNotIsolated{{{expected_role}}}, got {other:?}"),
    }
    Ok(())
}

/// Isolated pause/blocklist holders build while ADMIN and ATTEST_ADMIN share the owner account.
#[test]
fn build_accepts_isolated_blk_manager() -> Result<()> {
    builder_with_holders(
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )?
    .build_components()
    .context("a properly isolated BLK_MANAGER holder must build")?;
    Ok(())
}

/// Every member of a multi-holder role is seeded: two DOM_PAUSER holders both carry the
/// enabled membership row in the built account's RBAC map.
#[test]
fn build_seeds_every_member_of_a_multi_holder_role() -> Result<()> {
    use miden_protocol::account::RoleSymbol;
    use xusdc_encoding::account::xreserve::{build_faucet_account, DOM_PAUSER_ROLE};

    let pausers = [test_account_id(2), test_account_id(6)];
    let account = build_faucet_account(
        [7u8; 32],
        AssetAmount::ZERO,
        test_account_id(1),
        vec![test_account_id(5)],
        pausers.to_vec(),
        vec![test_account_id(3)],
        vec![test_account_id(4)],
        test_fee_parameters(),
        test_fee_asset_id(),
        TEST_DOMAIN,
    )
    .context("a two-pauser composition must build")?;
    let role = RoleSymbol::new(DOM_PAUSER_ROLE).context("DOM_PAUSER is a valid role symbol")?;
    for pauser in pausers {
        assert_eq!(
            read_role_membership(&account, &role, pauser)?,
            miden_protocol::Word::from([1u32, 0, 0, 0]),
            "every configured DOM_PAUSER holder must be seeded as a member",
        );
    }
    Ok(())
}

/// The operational roles may be empty at build time: a faucet with no seeded pauser composes
/// (the role is populated later through the standard role-action note). Only `ADMIN` requires a
/// holder, which its singular `owner` input guarantees by type.
#[test]
fn build_accepts_an_empty_operational_role() -> Result<()> {
    XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::ZERO)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(5)])
        .pauser_holders(Vec::new())
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()
        .context("an empty DOM_PAUSER role must construct")?
        .build_components()
        .map_err(|e| anyhow::anyhow!("an empty DOM_PAUSER role must compose: {e}"))?;
    Ok(())
}

/// A role listing the same member twice is rejected at construction.
#[test]
fn build_rejects_a_duplicate_role_member() -> Result<()> {
    let err = XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::ZERO)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(5)])
        .pauser_holders(vec![test_account_id(2), test_account_id(2)])
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()
        .expect_err("a duplicated role member must be rejected");
    match err {
        XReserveStablecoinBuilderError::DuplicateRoleMember { role } => {
            assert_eq!(role, "DOM_PAUSER", "the rejection must name the role");
        }
        other => panic!("expected DuplicateRoleMember{{DOM_PAUSER}}, got {other:?}"),
    }
    Ok(())
}

/// The isolation rules cover every member of a multi-holder role: the SECOND pauser colliding
/// with the unpauser is rejected exactly like a sole pauser would be.
#[test]
fn build_rejects_a_secondary_pauser_colliding_with_another_role() -> Result<()> {
    let err = XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::ZERO)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(5)])
        .pauser_holders(vec![test_account_id(2), test_account_id(3)])
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()
        .context("the two-pauser builder constructs")?
        .build_components()
        .expect_err("a secondary DOM_PAUSER holder colliding with DOM_UNPAUSER must be rejected");
    match err {
        XReserveStablecoinBuilderError::PauserNotIsolated { collides_with } => {
            assert_eq!(collides_with, "DOM_UNPAUSER");
        }
        other => panic!("expected PauserNotIsolated{{DOM_UNPAUSER}}, got {other:?}"),
    }
    Ok(())
}

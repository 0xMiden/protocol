//! `set_attester` requires the dedicated `ATTEST_ADMIN` role through the account-wide authority.
//! The default fixture places `ADMIN` and `ATTEST_ADMIN` on id(1); the separate-holder case proves
//! that attester administration follows only `ATTEST_ADMIN`. The setter remains usable while paused.
//! Enabling, removing and rotating an attester changes which attestations real mints accept;
//! those effects live in the mint end-to-end suites. Role seeding is pinned against production by
//! `role_admin.rs::shipped_role_graph_reads_back` and against the burn replica by
//! `set_min_burn.rs::support_replica_matches_the_production_role_seed`.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotPatch};
use miden_protocol::asset::AssetAmount;
use miden_protocol::Word;
use miden_standards::account::policies::TokenPolicyManager;
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveFaucetExtension, XReserveStablecoinBuilder, ATTESTATION_MINT_POLICY_PROC_PATH,
};

// The fixture gives ADMIN and ATTEST_ADMIN to id(1); DOM_PAUSER = id(2) and DOM_UNPAUSER = id(3)
// are privileged accounts without attester-administration capability.
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_unpauser() -> AccountId {
    test_account_id(3)
}

/// The config word the builder does not read (these tests invoke `set_attester` via a note, never
/// the mint driver).
fn dummy_config() -> Word {
    Word::from([7u32, 0, 0, 0])
}

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// These tests reach the account through admin notes and never invoke it, so it only has to
/// compile.
fn placeholder_driver_src() -> String {
    "#! Test driver stand-in: never invoked by this suite (the custom mint entry was deleted by\n\
     #! the Wave-1 S1 recomposition); the guarded fixture only requires a compilable component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// A guarded production faucet with ADMIN and ATTEST_ADMIN on the same account.
/// The attestation policy is active and `attesters_seed = None` (empty allowlist).
fn guarded_faucet() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    let domain = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        1_000_000,
        0,
        domain,
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// Reads the `xReserveAttesters` allowlist entry for `commitment` from a committed account (EMPTY_WORD
/// when unset) — the no-state-change read-back the non-administrator reject uses.
fn read_attester(account: &miden_protocol::account::Account, commitment: Word) -> Result<Word> {
    Ok(account.storage().get_map_item(
        XReserveFaucetExtension::xreserve_attesters_slot(),
        StorageMapKey::new(commitment),
    )?)
}

// EXPORT PROBE (green scaffold — flat-path check for the setter)
// ================================================================================================

#[test]
fn probe_attester_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attester_admin::set_attester";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// PRODUCTION REGRESSION GATE — the role map must not perturb the mint-gate posture
// ================================================================================================

/// The attester role does not disturb what actually guards minting.
///
/// The composed account's active mint-policy slot must still hold exactly the root of the
/// attestation policy resolved from the installed component. That is the structural form of the
/// property everything else depends on: every increase in supply goes through the attestation
/// gate. The executing halves — real mints accepted and rejected — live in the mint end-to-end
/// suites.
#[test]
fn production_build_gates_mint_on_the_attestation_policy() -> Result<()> {
    let components = production_component_set(0)?;
    let attestation_root = components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH))
        .map(Word::from)
        .context("the composed set must carry the attestation mint policy proc")?;
    let active = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == TokenPolicyManager::active_mint_policy_slot())
        .context("the composed set must carry the active-mint-policy slot")?
        .value();
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (the role map \
         leaves the mint gate on the attestation policy)"
    );
    Ok(())
}

// ATTESTER ADMINISTRATION — the setter resolves to ATTEST_ADMIN
// ================================================================================================

/// The fixture administrator also holds ATTEST_ADMIN, so its setter note enables the entry.
#[tokio::test]
async fn set_attester_administrator_succeeds() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([10u32, 11, 12, 13]);

    let executed = run_set_attester_tx(&gm.harness, &account, administrator(), commitment, 1, 7)
        .await
        .expect("the administrator's set_attester(K, true) must succeed");

    // the allowlist entry landed: xReserveAttesters[K] == [1,0,0,0].
    let attesters = XReserveFaucetExtension::xreserve_attesters_slot();
    let StorageSlotPatch::Map(delta) = executed
        .account_patch()
        .storage()
        .get(attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .expect("the commitment KEY must appear in the xReserveAttesters delta");
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "enabled marker written"
    );
    Ok(())
}

/// Separating the holders hands attester administration to ATTEST_ADMIN alone.
#[tokio::test]
async fn set_attester_requires_attest_admin_not_admin() -> Result<()> {
    let components = XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::ZERO)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(5)])
        .pauser_holders(vec![test_account_id(2)])
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(TEST_DOMAIN)
        .build()?
        .build_components()?;
    let mut builder = MockChain::builder();
    let mut account = add_faucet_account(&mut builder, Auth::IncrNonce, components)?;
    let chain = builder.build()?;
    let commitment = Word::from([41u32, 42, 43, 44]);

    let result = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(set_attester_note(test_account_id(1), commitment, 1, 41)?)
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(read_attester(&account, commitment)?, Word::empty());

    let executed = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(set_attester_note(test_account_id(5), commitment, 1, 42)?)
        .build()?
        .execute()
        .await?;
    account.apply_patch(executed.account_patch())?;
    assert_eq!(
        read_attester(&account, commitment)?,
        Word::from([1u32, 0, 0, 0])
    );
    Ok(())
}

/// A `sender` without ATTEST_ADMIN traps the exact
/// ERR_SENDER_LACKS_ROLE AND leaves the allowlist entry for the attempted key EMPTY (no partial write).
async fn assert_set_attester_non_administrator_rejected(
    sender: AccountId,
    key_seed: u32,
) -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([key_seed, key_seed + 1, key_seed + 2, key_seed + 3]);

    let result = run_set_attester_tx(&gm.harness, &account, sender, commitment, 1, 7).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());

    // no state change: the allowlist entry for the attempted key never landed (reads EMPTY_WORD).
    assert_eq!(
        read_attester(&account, commitment)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected non-administrator set_attester leaves xReserveAttesters[K] empty"
    );
    Ok(())
}

/// The seeded DOM_PAUSER holder id(2) has no ATTEST_ADMIN membership and is rejected.
#[tokio::test]
async fn set_attester_former_admin_dom_pauser_non_administrator_rejects() -> Result<()> {
    assert_set_attester_non_administrator_rejected(dom_pauser(), 20).await
}

/// The seeded DOM_UNPAUSER holder id(3) has no ATTEST_ADMIN membership and is rejected.
#[tokio::test]
async fn set_attester_dom_unpauser_non_administrator_rejects() -> Result<()> {
    assert_set_attester_non_administrator_rejected(dom_unpauser(), 30).await
}

// THE SETTER IS NOT PAUSE-GATED — ATTEST_ADMIN may set_attester while the faucet is paused
// ================================================================================================

/// After the Domain Pauser pauses the faucet (the stock `PausableManager`, role-gated), an
/// `ATTEST_ADMIN`-sent `set_attester` note SUCCEEDS while paused: the admin setters are deliberately NOT
/// pause-gated, so a compromised attester can be disabled during a pause — which is exactly when it
/// is needed. The enabled marker lands despite is_paused == true. The attester-admin gate still
/// governs it — the rejection tests above prove that half.
#[tokio::test]
async fn set_attester_administrator_succeeds_while_paused() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([1u32, 2, 3, 4]);

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // tx2: the ATTEST_ADMIN holder's set_attester(K, true) SUCCEEDS while paused — setters are not pause-gated.
    let executed = run_set_attester_tx(&gm.harness, &evolved, administrator(), commitment, 1, 7)
        .await
        .expect(
            "the administrator's set_attester(K, true) must succeed while the faucet is paused",
        );

    // the allowlist entry landed despite the pause: xReserveAttesters[K] == [1,0,0,0].
    let attesters = XReserveFaucetExtension::xreserve_attesters_slot();
    let StorageSlotPatch::Map(delta) = executed
        .account_patch()
        .storage()
        .get(attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .expect("the commitment KEY must appear in the xReserveAttesters delta");
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "enabled marker written while paused"
    );
    Ok(())
}

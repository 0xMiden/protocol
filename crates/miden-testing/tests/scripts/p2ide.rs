use anyhow::Context;
use miden_protocol::Felt;
use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, AssetVault, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteType};
use miden_standards::errors::standards::{
    ERR_P2IDE_RECLAIM_ACCT_IS_NOT_RECLAIMER, ERR_P2IDE_RECLAIM_DISABLED,
    ERR_P2IDE_RECLAIM_HEIGHT_NOT_REACHED, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Test that the P2IDE note works like a regular P2ID note
#[tokio::test]
async fn p2ide_script_success_without_reclaim_or_timelock() -> anyhow::Result<()> {
    let reclaim_height = None; // if 0, means it is not reclaimable
    let timelock_height = None; // if 0 means it is not timelocked

    let P2ideTestSetup {
        mock_chain,
        fungible_asset,
        target_account,
        malicious_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(reclaim_height, timelock_height)?;

    // CONSTRUCT AND EXECUTE TX (Failure - Malicious Account)
    let executed_transaction_1 = mock_chain
        .build_transaction(malicious_account.id())
        .unauthenticated_input_note(p2ide_note.clone())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(executed_transaction_1, ERR_P2IDE_RECLAIM_DISABLED);

    // CONSTRUCT AND EXECUTE TX (Success - Target Account)
    let executed_transaction_2 = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let target_account_after: Account = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset])?,
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::new_unchecked(2),
    );
    assert_eq!(
        executed_transaction_2.final_account().to_commitment(),
        target_account_after.to_commitment()
    );

    Ok(())
}

/// Test that the P2IDE note can have a timelock that unlocks before the reclaim block height
#[tokio::test]
async fn p2ide_script_success_timelock_unlock_before_reclaim_height() -> anyhow::Result<()> {
    let reclaim_height = Some(BlockNumber::from(5u32));
    let timelock_height = None;

    let P2ideTestSetup {
        mut mock_chain,
        fungible_asset,
        target_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(reclaim_height, timelock_height)?;

    mock_chain.prove_until_block(4).context("failed to prove multiple blocks")?;

    // CONSTRUCT AND EXECUTE TX (Success - Target Account)
    let executed_transaction_1 = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let target_account_after: Account = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset])?,
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::new_unchecked(2),
    );
    assert_eq!(
        executed_transaction_1.final_account().to_commitment(),
        target_account_after.to_commitment()
    );

    Ok(())
}

/// Test that the P2IDE note can have a timelock set and reclaim functionality
/// disabled.
#[tokio::test]
async fn p2ide_script_timelocked_reclaim_disabled() -> anyhow::Result<()> {
    let reclaim_height = None;
    let timelock_height = BlockNumber::from(5u32);
    let P2ideTestSetup {
        mut mock_chain,
        fungible_asset,
        sender_account,
        target_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(reclaim_height, Some(timelock_height))?;

    mock_chain.prove_until_block(10u32).context("failed to prove multiple blocks")?;

    // ───────────────────── reclaim attempt (sender) → FAIL ────────────
    let early_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .reference_block(timelock_height.as_u32() - 1)
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_reclaim, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED);

    // ───────────────────── early spend attempt (target)  → FAIL ─────────────
    let early_spend = mock_chain
        .build_transaction(target_account.id())
        .reference_block(timelock_height.as_u32() - 1)
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_spend, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED);

    // ───────────────────── reclaim attempt (sender) → FAIL ────────────
    let early_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_reclaim, ERR_P2IDE_RECLAIM_DISABLED);

    // ───────────────────── target spends successfully ───────────────────────
    let final_tx = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let target_after = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset])?,
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(final_tx.final_account().to_commitment(), target_after.to_commitment());

    Ok(())
}

/// Test that an attempted reclaim of the P2IDE note fails if consumed by the reclaimer
/// before the timelock expires. Creating a P2IDE note with a reclaim block height that is
/// less than the timelock block height would be the same as creating a P2IDE note
/// where the reclaim block height is equal to the timelock block height
#[tokio::test]
async fn p2ide_script_reclaim_fails_before_timelock_expiry() -> anyhow::Result<()> {
    let reclaim_height = BlockNumber::from(1u32);
    let timelock_height = BlockNumber::from(5u32);

    let P2ideTestSetup {
        mut mock_chain,
        fungible_asset,
        sender_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(Some(reclaim_height), Some(timelock_height))?;

    mock_chain.prove_until_block(reclaim_height + 4)?;

    // CONSTRUCT AND EXECUTE TX (Failure - sender_account tries to reclaim)
    let executed_transaction_1 = mock_chain
        .build_transaction(sender_account.id())
        .reference_block(1u32)
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        executed_transaction_1,
        ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED
    );

    // CONSTRUCT AND EXECUTE TX (Success - sender_account)
    let executed_transaction_2 = mock_chain
        .build_transaction(sender_account.id())
        .reference_block(timelock_height)
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let sender_account_after: Account = Account::new_existing(
        sender_account.id(),
        AssetVault::new(&[fungible_asset])?,
        sender_account.storage().clone(),
        sender_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(
        executed_transaction_2.final_account().to_commitment(),
        sender_account_after.to_commitment()
    );

    Ok(())
}

/// Test that the P2IDE note can have timelock and reclaim functionality
#[tokio::test]
async fn p2ide_script_reclaimable_timelockable() -> anyhow::Result<()> {
    let reclaim_height = BlockNumber::from(10u32);
    let timelock_height = BlockNumber::from(7u32);

    let P2ideTestSetup {
        mut mock_chain,
        fungible_asset,
        sender_account,
        target_account,
        malicious_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(Some(reclaim_height), Some(timelock_height))?;

    // ───────────────────── early reclaim attempt (sender) → FAIL ────────────
    let early_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_reclaim, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED);

    // ───────────────────── early spend attempt (target)  → FAIL ─────────────
    let early_spend = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_spend, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED);

    // ───────────────────── advance chain past timelock height ──────────────────────
    mock_chain.prove_until_block(timelock_height + 1)?;

    // ───────────────────── early reclaim attempt (sender) → FAIL ────────────
    let early_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_reclaim, ERR_P2IDE_RECLAIM_HEIGHT_NOT_REACHED);

    // ───────────────────── advance chain past reclaim height ──────────────────────
    mock_chain.prove_until_block(reclaim_height + 1)?;

    // CONSTRUCT AND EXECUTE TX (Failure - Malicious Account)
    let executed_transaction_1 = mock_chain
        .build_transaction(malicious_account.id())
        .unauthenticated_input_note(p2ide_note.clone())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        executed_transaction_1,
        ERR_P2IDE_RECLAIM_ACCT_IS_NOT_RECLAIMER
    );

    // ───────────────────── target spends successfully ───────────────────────
    let final_tx = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let target_after = Account::new_existing(
        target_account.id(),
        AssetVault::new(&[fungible_asset])?,
        target_account.storage().clone(),
        target_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(final_tx.final_account().to_commitment(), target_after.to_commitment());

    Ok(())
}

/// Test that the P2IDE note can be reclaimed after timelock
#[tokio::test]
async fn p2ide_script_reclaim_success_after_timelock() -> anyhow::Result<()> {
    let reclaim_height = BlockNumber::from(5);
    let timelock_height = BlockNumber::from(3);

    let P2ideTestSetup {
        mut mock_chain,
        fungible_asset,
        sender_account,
        p2ide_note,
        ..
    } = setup_p2ide_test(Some(reclaim_height), Some(timelock_height))?;

    // ───────────────────── early reclaim attempt (sender) → FAIL ────────────
    let early_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(early_reclaim, ERR_P2IDE_TIMELOCK_HEIGHT_NOT_REACHED);

    // ───────────────────── advance chain past reclaim height ──────────────────────
    mock_chain.prove_until_block(reclaim_height + 1)?;

    // ───────────────────── sender reclaims successfully ───────────────────────
    let final_tx = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let sender_after = Account::new_existing(
        sender_account.id(),
        AssetVault::new(&[fungible_asset])?,
        sender_account.storage().clone(),
        sender_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(final_tx.final_account().to_commitment(), sender_after.to_commitment());

    Ok(())
}

/// Test that when the reclaimer is distinct from the note's metadata sender, only the
/// reclaimer (stored in note storage) can reclaim the note - the metadata sender cannot.
#[tokio::test]
async fn p2ide_script_reclaim_by_distinct_reclaimer() -> anyhow::Result<()> {
    let reclaim_height = BlockNumber::from(5u32);

    let fungible_asset: Asset = FungibleAsset::mock(100);
    let mut builder = MockChain::builder();

    let sender_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let reclaimer_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let target_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // the reclaimer (allowed to reclaim) is distinct from the metadata sender
    let p2ide_note = builder.add_p2ide_note(
        sender_account.id(),
        target_account.id(),
        Some(reclaimer_account.id()),
        &[fungible_asset],
        NoteType::Public,
        Some(reclaim_height),
        None,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_until_block(reclaim_height + 1)?;

    // ───────────────────── sender (not the reclaimer) cannot reclaim → FAIL ────────────
    let sender_reclaim = mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(sender_reclaim, ERR_P2IDE_RECLAIM_ACCT_IS_NOT_RECLAIMER);

    // ───────────────────── reclaimer reclaims successfully ───────────────────────
    let final_tx = mock_chain
        .build_transaction(reclaimer_account.id())
        .authenticated_input_note(p2ide_note.id())
        .build()?
        .execute()
        .await?;

    let reclaimer_after = Account::new_existing(
        reclaimer_account.id(),
        AssetVault::new(&[fungible_asset])?,
        reclaimer_account.storage().clone(),
        reclaimer_account.code().clone(),
        Felt::new_unchecked(2),
    );

    assert_eq!(final_tx.final_account().to_commitment(), reclaimer_after.to_commitment());

    Ok(())
}

struct P2ideTestSetup {
    mock_chain: MockChain,
    fungible_asset: Asset,
    sender_account: Account,
    target_account: Account,
    malicious_account: Account,
    p2ide_note: Note,
}

fn setup_p2ide_test(
    reclaim_height: Option<BlockNumber>,
    timelock_height: Option<BlockNumber>,
) -> anyhow::Result<P2ideTestSetup> {
    let fungible_asset: Asset = FungibleAsset::mock(100);

    let mut builder = MockChain::builder();

    // Create sender and target accounts
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let target_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let malicious_account = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let p2ide_note = builder.add_p2ide_note(
        sender_account.id(),
        target_account.id(),
        None,
        &[fungible_asset],
        NoteType::Public,
        reclaim_height,
        timelock_height,
    )?;

    let mock_chain = builder.build()?;

    Ok(P2ideTestSetup {
        mock_chain,
        fungible_asset,
        sender_account,
        target_account,
        malicious_account,
        p2ide_note,
    })
}

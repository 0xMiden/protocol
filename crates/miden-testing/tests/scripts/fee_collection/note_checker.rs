use core::error::Error;
use std::collections::BTreeSet;

use assert_matches::assert_matches;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::note::{Note, NoteId};
use miden_standards::account::fees::FeePolicy;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::MockChain;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    FeeRejection,
    NoteConsumptionChecker,
    NoteConsumptionInfo,
    NoteFailure,
    SponsorshipRejection,
    TransactionExecutor,
};
use rstest::rstest;

use super::{FEE_AMOUNT, Sponsorship, Test, fee_asset, fee_faucet_id, other_asset};

/// A custom fee policy charging `fee_amount` of the fee faucet's asset for every note.
///
/// Since it is not a [`BasicConstantFeePolicy`], the note checker cannot tell the fees it charges
/// without executing it.
fn flat_fee_policy(fee_amount: u64) -> anyhow::Result<FeePolicy> {
    const POLICY_NAME: &str = "test::fees::flat_fee";
    let masm_source = format!(
        r#"
        use miden::standards::assets::fungible_asset

        #! Fee policy pricing every note at the same fee.
        #!
        #! Inputs:  [RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]
        #! Outputs: [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc compute_note_fee
            push.{fee_asset_id}
            # => [FEE_ASSET_ID, RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]

            push.{fee_amount} exec.fungible_asset::create_value swapw
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]

            # drop the note parameters
            repeat.4 movupw.2 dropw end
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        end
        "#,
        fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word(),
    );

    let code = CodeBuilder::default().compile_component_code(POLICY_NAME, &masm_source)?;
    let root = code
        .get_procedure_root_by_path(format!("{POLICY_NAME}::compute_note_fee").as_str())
        .expect("flat fee policy should export compute_note_fee");
    let component =
        AccountComponent::new(code, vec![], AccountComponentMetadata::mock(POLICY_NAME))?;

    Ok(FeePolicy::custom(root, [component])?)
}

/// Runs [`NoteConsumptionChecker::check_notes_consumability`] over `notes` against the network
/// account.
async fn check_notes(
    mock_chain: &MockChain,
    network_account_id: AccountId,
    notes: Vec<Note>,
) -> anyhow::Result<NoteConsumptionInfo> {
    let mut builder = mock_chain.build_transaction(network_account_id);
    for note in &notes {
        builder = builder.authenticated_input_note(note.id());
    }
    let mock_tx = builder.build()?;

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx)
        .with_source_manager(mock_tx.source_manager());
    Ok(NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            network_account_id,
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await?)
}

/// Runs the checker and returns the note ids it reports as `(successful, failed)`.
async fn check_consumability(
    mock_chain: &MockChain,
    network_account_id: AccountId,
    notes: Vec<Note>,
) -> anyhow::Result<(BTreeSet<NoteId>, BTreeSet<NoteId>)> {
    let info = check_notes(mock_chain, network_account_id, notes).await?;

    Ok((
        info.successful().iter().map(|note| note.note().id()).collect(),
        info.failed().iter().map(|note| note.note().id()).collect(),
    ))
}

/// Returns the reason the checker rejected the note with `note_id` without executing it.
///
/// Panics if the note did not fail, failed in execution, or was rejected for a reason other than
/// an `R`.
fn rejection_reason<R: Error + 'static>(info: &NoteConsumptionInfo, note_id: NoteId) -> &R {
    let failed = info
        .failed()
        .iter()
        .find(|failed| failed.note().id() == note_id)
        .unwrap_or_else(|| panic!("note {note_id} should have failed"));
    let NoteFailure::Rejected { reason } = failed.failure() else {
        panic!("note {note_id} should have been rejected without being executed, got {failed:?}");
    };
    reason.downcast_ref::<R>().unwrap_or_else(|| {
        panic!(
            "note {note_id} should have been rejected with a {}, got: {reason}",
            core::any::type_name::<R>()
        )
    })
}

/// An uncovered feature note does not drag the intact (feature note, FEE_SPONSORSHIP) pairs
/// sharing its batch down with it.
///
/// Writing `F` for a feature note, `S` for the sponsorship bound to it and `S'` for an underfunded
/// one, the cases below are:
///
/// ```text
/// [F0, S0]           ->  successful {F0, S0}   failed {}
/// [F0, S0, F1]       ->  successful {F0, S0}   failed {F1}
/// [F0, S0, F1, S1']  ->  successful {F0, S0}   failed {F1, S1'}
/// ```
#[rstest]
#[case::no_sponsorship(None)]
#[case::underfunded_sponsorship(Some(FEE_AMOUNT - 1))]
#[tokio::test]
async fn note_checker_keeps_intact_pairs_alongside_an_uncovered_note(
    #[case] uncovered_sponsored_amount: Option<u64>,
) -> anyhow::Result<()> {
    let mut test_builder = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?));
    if let Some(amount) = uncovered_sponsored_amount {
        test_builder = test_builder.sponsorship(Sponsorship::new(1, fee_asset(amount)?));
    }
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = test_builder.build()?;

    // control: the intact pair is consumable on its own
    let intact = vec![feature_notes[0].clone(), sponsorship_notes[0].clone()];
    let intact_ids: BTreeSet<NoteId> = intact.iter().map(Note::id).collect();
    let (successful, failed) =
        check_consumability(&mock_chain, network_account.id(), intact.clone()).await?;
    assert_eq!(successful, intact_ids, "the intact pair should be consumable on its own");
    assert!(failed.is_empty(), "no note of an intact pair should fail");

    // subject: the same pair, plus the uncovered feature note and its underfunded sponsorship
    let mut poisoned = intact;
    poisoned.push(feature_notes[1].clone());
    let mut uncovered_ids = BTreeSet::from([feature_notes[1].id()]);
    if uncovered_sponsored_amount.is_some() {
        poisoned.push(sponsorship_notes[1].clone());
        uncovered_ids.insert(sponsorship_notes[1].id());
    }

    let info = check_notes(&mock_chain, network_account.id(), poisoned).await?;
    let successful: BTreeSet<NoteId> = info.successful().iter().map(|n| n.note().id()).collect();
    let failed: BTreeSet<NoteId> = info.failed().iter().map(|n| n.note().id()).collect();
    assert_eq!(successful, intact_ids, "the intact pair should survive the uncovered note");
    assert_eq!(failed, uncovered_ids, "only the uncovered note and its sponsorship should fail");

    // the uncovered bundle is ruled out from the fee schedule, without being executed
    let provided = AssetAmount::new(uncovered_sponsored_amount.unwrap_or(0))?;
    for note_id in uncovered_ids {
        assert_matches!(
            rejection_reason::<FeeRejection>(&info, note_id),
            FeeRejection::FeeNotCovered { feature_note_id, required, provided: actual }
                if *feature_note_id == feature_notes[1].id()
                    && required.as_u64() == FEE_AMOUNT
                    && *actual == provided
        );
    }

    Ok(())
}

/// A FEE_SPONSORSHIP note whose feature note is absent is not bundled with anything: it fails on
/// its own and leaves an intact pair untouched. Its only remaining path is the reclaim.
///
/// If the network account is not the reclaimer, the note is rejected before anything is executed.
/// If it is, the static rules cannot rule the reclaim out, so the note is left for the executor to
/// decide. Fee collection then turns it down anyway, since it does not allow reclaiming a
/// sponsorship in a network transaction, which is why the note ends up blamed rather than rejected.
#[rstest]
#[case::not_reclaimer(false)]
#[case::reclaimer(true)]
#[tokio::test]
async fn note_checker_fails_an_orphan_sponsorship_alone(
    #[case] reclaimable_by_target: bool,
) -> anyhow::Result<()> {
    let builder = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?));
    let builder = if reclaimable_by_target {
        builder.sponsorship(Sponsorship::reclaimable(1, fee_asset(FEE_AMOUNT)?))
    } else {
        builder.sponsorship(Sponsorship::new(1, fee_asset(FEE_AMOUNT)?))
    };
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = builder.build()?;

    // the sponsorship for the second feature note is included, but that feature note is not
    let notes = vec![
        feature_notes[0].clone(),
        sponsorship_notes[0].clone(),
        sponsorship_notes[1].clone(),
    ];

    let info = check_notes(&mock_chain, network_account.id(), notes).await?;

    assert_eq!(
        info.successful().iter().map(|note| note.note().id()).collect::<BTreeSet<_>>(),
        BTreeSet::from([feature_notes[0].id(), sponsorship_notes[0].id()]),
        "the intact pair should survive the orphan sponsorship"
    );
    let [orphan] = info.failed() else {
        panic!("only the orphan sponsorship should fail, got {:?}", info.failed());
    };
    assert_eq!(orphan.note().id(), sponsorship_notes[1].id());
    if reclaimable_by_target {
        assert!(
            orphan.is_blamed(),
            "a reclaimable orphan should be executed rather than rejected, and fail there"
        );
    } else {
        // the account is not the orphan's reclaimer, so it is rejected without being executed
        assert_matches!(
            rejection_reason::<SponsorshipRejection>(&info, orphan.note().id()),
            SponsorshipRejection::NotReclaimer { native_account, .. }
                if *native_account == network_account.id()
        );
    }

    Ok(())
}

/// A FEE_SPONSORSHIP note that names another sponsorship note as its feature note is rejected
/// without being executed, and the sponsorship it names is judged on its own.
///
/// Writing `F` for the feature note, `S1` for its sponsorship and `S2` for a sponsorship naming
/// `S1`, the cases below are:
///
/// ```text
/// [S1, S2]      ->  successful {}        rejected {S1, S2}
/// [F, S1, S2]   ->  successful {F, S1}   rejected {S2}
/// ```
///
/// Without `F`, `S1` can only be reclaimed, and the network account is not its reclaimer.
#[rstest]
#[case::feature_note_absent(false)]
#[case::feature_note_present(true)]
#[tokio::test]
async fn note_checker_rejects_a_sponsorship_naming_another_sponsorship(
    #[case] include_feature_note: bool,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?))
        .sponsorship(Sponsorship::chained(0, fee_asset(FEE_AMOUNT)?))
        .build()?;
    let (feature_note, sponsorship, chained) =
        (&feature_notes[0], &sponsorship_notes[0], &sponsorship_notes[1]);

    let mut notes = vec![sponsorship.clone(), chained.clone()];
    if include_feature_note {
        notes.insert(0, feature_note.clone());
    }
    let info = check_notes(&mock_chain, network_account.id(), notes).await?;

    let successful: BTreeSet<_> = info.successful().iter().map(|note| note.note().id()).collect();
    let rejected: BTreeSet<_> = info
        .failed()
        .iter()
        .filter(|failed| failed.is_rejected())
        .map(|failed| failed.note().id())
        .collect();
    assert_eq!(
        info.failed().len(),
        rejected.len(),
        "every failed note should be rejected without being executed, got {:?}",
        info.failed()
    );

    assert_matches!(
        rejection_reason::<SponsorshipRejection>(&info, chained.id()),
        SponsorshipRejection::FeatureNoteIsSponsorship { feature_note_id }
            if *feature_note_id == sponsorship.id()
    );

    if include_feature_note {
        assert_eq!(successful, BTreeSet::from([feature_note.id(), sponsorship.id()]));
        assert_eq!(rejected, BTreeSet::from([chained.id()]));
    } else {
        assert!(successful.is_empty(), "no note should be consumable, got {successful:?}");
        assert_eq!(rejected, BTreeSet::from([sponsorship.id(), chained.id()]));
    }

    Ok(())
}

/// Bundling follows the note IDs the sponsorships name, not the order the notes are passed in, and
/// several sponsorships topping up one feature note join the same bundle.
#[rstest]
#[tokio::test]
async fn note_checker_bundles_by_note_id_regardless_of_order(
    #[values(false, true)] sponsorships_first: bool,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        // the first feature note's fee is split across two sponsorships, so its bundle holds three
        // notes; the second feature note stays uncovered
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT / 2)?))
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT - FEE_AMOUNT / 2)?))
        .build()?;

    let covered = [
        feature_notes[0].clone(),
        sponsorship_notes[0].clone(),
        sponsorship_notes[1].clone(),
    ];
    let mut notes = if sponsorships_first {
        vec![
            sponsorship_notes[0].clone(),
            sponsorship_notes[1].clone(),
            feature_notes[0].clone(),
        ]
    } else {
        covered.to_vec()
    };
    notes.push(feature_notes[1].clone());

    let (successful, failed) =
        check_consumability(&mock_chain, network_account.id(), notes).await?;

    assert_eq!(
        successful,
        covered.iter().map(Note::id).collect::<BTreeSet<_>>(),
        "the feature note and both of its sponsorships should be consumed together"
    );
    assert_eq!(
        failed,
        BTreeSet::from([feature_notes[1].id()]),
        "only the uncovered feature note should fail"
    );

    Ok(())
}

/// A rejected bundle blames exactly one note and reports the rest as its collateral, naming it.
///
/// The account prices notes through a custom fee policy, so the checker cannot tell the
/// underfunded bundle apart without executing it. The uncovered feature note is the one blamed -
/// fee collection fails in the epilogue, which points at no particular note - and the sponsorship
/// that shares its bundle is reported as collateral of it, with no error of its own.
#[tokio::test]
async fn note_checker_blames_one_note_per_rejected_bundle() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .fee_policy(flat_fee_policy(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?))
        // the second feature note's sponsorship does not cover its fee
        .sponsorship(Sponsorship::new(1, fee_asset(FEE_AMOUNT - 1)?))
        .build()?;

    let notes = vec![
        feature_notes[0].clone(),
        sponsorship_notes[0].clone(),
        feature_notes[1].clone(),
        sponsorship_notes[1].clone(),
    ];
    let info = check_notes(&mock_chain, network_account.id(), notes).await?;

    let blamed: Vec<_> = info.failed().iter().filter(|failed| failed.is_blamed()).collect();
    assert_eq!(blamed.len(), 1, "a rejected bundle should blame exactly one note");
    assert_eq!(
        blamed[0].note().id(),
        feature_notes[1].id(),
        "the uncovered feature note heads its bundle, so it takes the epilogue failure"
    );
    assert!(blamed[0].execution_error().is_some(), "the blamed note should carry the error");

    let collateral: Vec<_> = info
        .failed()
        .iter()
        .filter_map(|failed| match failed.failure() {
            NoteFailure::Collateral { blamed_by } => Some((failed, *blamed_by)),
            _ => None,
        })
        .collect();
    assert_eq!(collateral.len(), 1, "the sponsorship should be the only collateral note");
    let (collateral_note, blamed_by) = collateral[0];
    assert_eq!(collateral_note.note().id(), sponsorship_notes[1].id());
    assert_eq!(
        blamed_by,
        feature_notes[1].id(),
        "collateral should name the note that was blamed"
    );
    assert!(
        collateral_note.is_collateral(),
        "the sponsorship should be reported as collateral"
    );
    assert!(
        collateral_note.execution_error().is_none(),
        "a collateral note has no error of its own"
    );

    // The note a collateral failure names is always reported alongside it.
    assert!(
        info.failed().iter().any(|failed| failed.note().id() == blamed_by),
        "the blamed note should be in the same failed list"
    );

    Ok(())
}

/// A FEE_SPONSORSHIP note funded with an asset other than the one the account collects fees in is
/// rejected before anything is executed, and so is the feature note it is bound to, which is left
/// without anything covering its fee.
///
/// Without the check the pair would be tried and fail in the epilogue, which points at no note, so
/// the blame would fall on the feature note heading the bundle and the sponsorship that actually
/// carries the wrong asset would be reported as its collateral.
#[tokio::test]
async fn note_checker_rejects_a_sponsorship_carrying_the_wrong_fee_asset() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?))
        // the second feature note is sponsored in an asset the account does not collect fees in
        .sponsorship(Sponsorship::new(1, other_asset(FEE_AMOUNT)?))
        .build()?;

    let notes = vec![
        feature_notes[0].clone(),
        sponsorship_notes[0].clone(),
        feature_notes[1].clone(),
        sponsorship_notes[1].clone(),
    ];
    let info = check_notes(&mock_chain, network_account.id(), notes).await?;

    assert_eq!(
        info.successful().iter().map(|note| note.note().id()).collect::<BTreeSet<_>>(),
        BTreeSet::from([feature_notes[0].id(), sponsorship_notes[0].id()]),
        "the intact pair should survive the wrongly funded sponsorship"
    );

    assert_eq!(info.failed().len(), 2, "only the wrongly funded pair should fail");
    assert_matches!(
        rejection_reason::<SponsorshipRejection>(&info, sponsorship_notes[1].id()),
        SponsorshipRejection::WrongFeeAsset { expected, actual }
            if *expected == AssetId::new_fungible(fee_faucet_id()?)
                && *actual == other_asset(FEE_AMOUNT)?.id()
    );
    // the wrongly funded sponsorship does not count towards the fee
    assert_matches!(
        rejection_reason::<FeeRejection>(&info, feature_notes[1].id()),
        FeeRejection::FeeNotCovered { provided, .. } if *provided == AssetAmount::ZERO
    );

    Ok(())
}

/// Several FEE_SPONSORSHIP notes bound to one feature note are summed against its fee: the bundle
/// is kept when they cover it between them, and rejected as a whole, without being executed, when
/// they fall short of it.
#[rstest]
#[case::covered_between_them(FEE_AMOUNT / 2, FEE_AMOUNT - FEE_AMOUNT / 2, true)]
#[case::one_short(FEE_AMOUNT / 2, FEE_AMOUNT - FEE_AMOUNT / 2 - 1, false)]
#[tokio::test]
async fn note_checker_sums_the_sponsorships_of_a_feature_note(
    #[case] first_amount: u64,
    #[case] second_amount: u64,
    #[case] covered: bool,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .sponsorship(Sponsorship::new(0, fee_asset(first_amount)?))
        .sponsorship(Sponsorship::new(0, fee_asset(second_amount)?))
        .build()?;

    let bundle = vec![
        feature_notes[0].clone(),
        sponsorship_notes[0].clone(),
        sponsorship_notes[1].clone(),
    ];
    let bundle_ids: Vec<NoteId> = bundle.iter().map(Note::id).collect();
    let info = check_notes(&mock_chain, network_account.id(), bundle).await?;

    if covered {
        assert_eq!(info.successful().len(), 3, "the covered bundle should be consumable");
        assert!(info.failed().is_empty(), "no note of the covered bundle should fail");
    } else {
        assert!(info.successful().is_empty(), "no note of the uncovered bundle should succeed");
        for note_id in bundle_ids {
            assert_matches!(
                rejection_reason::<FeeRejection>(&info, note_id),
                FeeRejection::FeeNotCovered { required, provided, .. }
                    if required.as_u64() == FEE_AMOUNT
                        && provided.as_u64() == first_amount + second_amount
            );
        }
    }

    Ok(())
}

/// A feature note whose script root the account schedules no fee for is rejected together with
/// its sponsorship, without being executed, since fee estimation aborts for it.
#[tokio::test]
async fn note_checker_rejects_an_unscheduled_feature_note() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .sponsorship(Sponsorship::new(0, fee_asset(FEE_AMOUNT)?))
        .build()?;

    let info = check_notes(
        &mock_chain,
        network_account.id(),
        vec![feature_notes[0].clone(), sponsorship_notes[0].clone()],
    )
    .await?;

    assert!(info.successful().is_empty(), "no note of the bundle should succeed");
    for note_id in [feature_notes[0].id(), sponsorship_notes[0].id()] {
        assert_matches!(
            rejection_reason::<FeeRejection>(&info, note_id),
            FeeRejection::FeeNotScheduled { feature_note_id, script_root }
                if *feature_note_id == feature_notes[0].id()
                    && *script_root == feature_notes[0].script().root()
        );
    }

    Ok(())
}

/// A feature note the account schedules a zero fee for needs no sponsorship.
#[tokio::test]
async fn note_checker_keeps_a_zero_fee_feature_note_without_sponsorship() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        ..
    } = Test::builder().feature_note_fee(AssetAmount::ZERO).build()?;

    let info =
        check_notes(&mock_chain, network_account.id(), vec![feature_notes[0].clone()]).await?;

    assert_eq!(info.successful().len(), 1, "the zero-fee feature note should be consumable");
    assert!(info.failed().is_empty(), "the zero-fee feature note should not fail");

    Ok(())
}

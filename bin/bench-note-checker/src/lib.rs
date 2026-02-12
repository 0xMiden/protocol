use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::RpoRandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, TxContextInput};
use miden_tx::auth::UnreachableAuth;
use miden_tx::{NoteConsumptionChecker, TransactionExecutor};
use serde::{Deserialize, Serialize};

pub mod benchmark_names {
    pub const BENCH_GROUP: &str = "note_checker";
    pub const BENCH_MIXED_NOTES: &str = "mixed_successful_and_failing_notes";
}

/// Benchmark result measurements for note checker performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteCheckerMeasurements {
    pub failing_note_count: usize,
    pub successful_notes_found: usize,
    pub failed_notes_count: usize,
    pub total_iterations: usize,
    pub execution_time_ms: f64,
}

impl NoteCheckerMeasurements {
    pub fn new(
        failing_note_count: usize,
        successful_notes_found: usize,
        failed_notes_count: usize,
        total_iterations: usize,
        execution_time_ms: f64,
    ) -> Self {
        Self {
            failing_note_count,
            successful_notes_found,
            failed_notes_count,
            total_iterations,
            execution_time_ms,
        }
    }
}

/// Benchmark configuration for mixed note scenarios.
#[derive(Clone, Debug)]
pub struct MixedNotesConfig {
    /// Number of failing notes to insert between successful notes.
    pub failing_note_count: usize,
}

/// Setup data for the mixed notes benchmark.
pub struct MixedNotesSetup {
    pub mock_chain: MockChain,
    pub notes: Vec<Note>,
    pub target_account_id: AccountId,
    pub expected_successful_count: usize,
}

/// Creates a benchmark setup with one successful note, N failing notes, and one more successful
/// note. This tests the iterative elimination strategy of `check_notes_consumability`.
pub fn setup_mixed_notes_benchmark(config: MixedNotesConfig) -> anyhow::Result<MixedNotesSetup> {
    // Create a mock chain with an account.
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let target_account_id = account.id();

    // Create the first successful note (P2ID note that the account can consume).
    let successful_note_1 = builder.add_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?,
        account.id(),
        &[FungibleAsset::mock(100)],
        NoteType::Public,
    )?;

    // Create many failing notes (division by zero error).
    let sender = AccountId::try_from(ACCOUNT_ID_SENDER)?;
    let mut failing_notes = Vec::with_capacity(config.failing_note_count);

    for i in 0..config.failing_note_count {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        let mut rng = RpoRandomCoin::new([i as u32, 0, 0, 0].into());
        let failing_note = NoteBuilder::new(sender, &mut rng)
            .code("begin push.0 div end") // Division by zero - will fail.
            .build()?;
        failing_notes.push(failing_note);
    }

    // Create the second successful note.
    let successful_note_2 = builder.add_p2id_note(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into()?,
        account.id(),
        &[FungibleAsset::mock(200)],
        NoteType::Public,
    )?;

    // Build the mock chain.
    let mock_chain = builder.build()?;

    // Arrange notes: [successful_1, failing_notes..., successful_2].
    let mut all_notes = vec![successful_note_1.clone()];
    all_notes.extend(failing_notes);
    all_notes.push(successful_note_2.clone());

    // We expect exactly 2 successful notes.
    let expected_successful_count = 2;

    Ok(MixedNotesSetup {
        mock_chain,
        notes: all_notes,
        target_account_id,
        expected_successful_count,
    })
}

/// Runs the note consumability check and validates the results.
pub async fn run_mixed_notes_check(setup: &MixedNotesSetup) -> anyhow::Result<()> {
    // Create transaction context with the setup data.
    let tx_context = setup
        .mock_chain
        .build_tx_context(TxContextInput::AccountId(setup.target_account_id), &[], &setup.notes)?
        .build()?;

    let block_ref = tx_context.tx_inputs().block_header().block_num();
    let tx_args = tx_context.tx_args().clone();

    // Create executor and checker.
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&tx_context);
    let checker = NoteConsumptionChecker::new(&executor);

    let result = checker
        .check_notes_consumability(setup.target_account_id, block_ref, setup.notes.clone(), tx_args)
        .await?;

    // Validate that we got the expected number of successful notes.
    assert_eq!(
        setup.expected_successful_count,
        result.successful.len(),
        "Expected {} successful notes, got {}",
        setup.expected_successful_count,
        result.successful.len()
    );

    // Validate that we have some failed notes (all the failing ones).
    assert!(!result.failed.is_empty(), "Expected some failed notes");

    Ok(())
}

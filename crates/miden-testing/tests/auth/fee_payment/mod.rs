use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::ExecutedTransaction;
use miden_standards::note::TxFeeNote;

mod bound;
mod guarded_multisig;
mod multisig;
mod multisig_smart;
mod network;
mod no_auth;
mod singlesig;
mod sponsorship;

// CONSTANTS
// ================================================================================================

/// The verification base fee configured on the fee-charging mock chains used across the fee
/// payment tests.
const VERIFICATION_BASE_FEE: u32 = 500;

// The cycle-estimate constants used by the fee-paying auth flows. These are Rust mirrors used to
// regression-test that the estimates remain upper bounds of the measured cycle counts. There is
// no build-time link between the MASM `const`s and these copies, so each must be updated by hand
// when its MASM counterpart changes; the assertions in the per-component test files only catch a
// MASM value that becomes too LOW (measured cycles exceed the mirror), which is the direction
// that matters.
//
// Must be kept in sync with `miden::standards::auth::signature` (per-scheme estimates and
// `MULTISIG_AUTH_BASE_CYCLES`) and `miden::standards::fee` (`PAY_FEE_CYCLES` and the epilogue
// margins).
const ECDSA_K256_KECCAK_AUTH_CYCLES: usize = 8000;
const FALCON_512_POSEIDON2_AUTH_CYCLES: usize = 80000;
const MULTISIG_AUTH_BASE_CYCLES: usize = 8192;
const PAY_FEE_CYCLES: usize = 8192;
const POST_AUTH_EPILOGUE_BASE_CYCLES: usize = 4096;
const POST_AUTH_EPILOGUE_PER_NOTE_CYCLES: usize = 512;

// HELPER FUNCTIONS
// ================================================================================================

/// Asserts the executed transaction produced exactly one output note: a public TX_FEE note
/// carrying a single native fee asset whose amount covers the required fee. Returns the fee
/// asset for further assertions.
fn assert_single_fee_note(
    executed_transaction: &ExecutedTransaction,
) -> anyhow::Result<FungibleAsset> {
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    let assets = output_note.assets();
    assert_eq!(assets.num_assets(), 1);
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let Asset::Fungible(fee_asset) = asset else {
        panic!("fee note asset should be fungible");
    };
    assert_eq!(fee_asset.faucet_id(), ACCOUNT_ID_FEE_FAUCET.try_into()?);

    let required_fee = executed_transaction.compute_fee();
    assert!(
        fee_asset.amount() >= required_fee,
        "paid fee {} should cover the required fee {required_fee}",
        fee_asset.amount()
    );

    Ok(*fee_asset)
}

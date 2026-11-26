use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountType};
use miden_protocol::asset::{AssetCallbacks, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::ExecutedTransaction;
use miden_standards::account::auth::NoAuth;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::TxFeeNote;

mod conversion;
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
pub(super) const VERIFICATION_BASE_FEE: u32 = 500;

/// The fee cap the multisig fee payment tests bind into the transaction summary, generously above
/// the fees the fee-charging mock chains compute.
pub(super) const MAX_FEE: u64 = 100_000;

// The cycle-estimate constants used by the fee-paying auth flows. These are Rust mirrors used to
// regression-test that the estimates remain upper bounds of the measured cycle counts. There is
// no build-time link between the MASM `const`s and these copies, so each must be updated by hand
// when its MASM counterpart changes; the assertions in the per-component test files only catch a
// MASM value that becomes too LOW (measured cycles exceed the mirror), which is the direction
// that matters.
//
// Must be kept in sync with `miden::standards::auth::signature` (per-scheme estimates) and
// `miden::standards::fee` (`PAY_FEE_CYCLES` and the epilogue margins).
const ECDSA_K256_KECCAK_AUTH_CYCLES: usize = 8000;
const FALCON_512_EIDOS_AUTH_CYCLES: usize = 80000;
const PAY_FEE_CYCLES: usize = 8192;
const POST_AUTH_EPILOGUE_BASE_CYCLES: usize = 4096;
const POST_AUTH_EPILOGUE_PER_NOTE_CYCLES: usize = 512;

// HELPER FUNCTIONS
// ================================================================================================

/// Builds an existing faucet account whose `on_before_note_sealed` callback returns a single-word
/// attachment for every sealed note holding its assets.
pub(super) fn attaching_callback_faucet(seed: [u8; 32]) -> anyhow::Result<Account> {
    const COMPONENT_NAME: &str = "tests::attaching_callback";

    let code = CodeBuilder::default().compile_component_code(
        COMPONENT_NAME,
        "
        use miden::core::crypto::hashes::eidos
        use miden::protocol::output_note

        @locals(4)
        @account_procedure
        pub proc on_before_note_sealed
            drop
            # => [pad(16)]

            # put the attachment into the advice map under its commitment
            push.1.2.3.4 loc_storew_le.0
            exec.eidos::hash
            # => [ATTACHMENT_COMMITMENT, pad(16)]

            locaddr.0 dup add.4 movdn.5 movdn.4 adv.insert_mem
            # => [ATTACHMENT_COMMITMENT, start_ptr, end_ptr, pad(16)]

            movup.4 drop movup.4 drop push.7
            # => [attachment_scheme, ATTACHMENT_COMMITMENT, pad(16)]

            exec.output_note::single_attachment_list
            # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(16)]

            exec.::miden::core::sys::truncate_stack
            # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
        end",
    )?;
    let root = code
        .as_package()
        .get_procedure_root_by_path(format!("{COMPONENT_NAME}::on_before_note_sealed").as_str())
        .expect("callback procedure should exist");
    let callback = AccountComponent::new(
        code,
        AssetCallbacks::new().on_before_note_sealed(root).into_storage_slots(),
        AccountComponentMetadata::new(COMPONENT_NAME),
    )?;

    Ok(AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_component(NoAuth)
        .with_component(callback)
        .build_existing()?)
}

/// Asserts the executed transaction produced exactly one output note: a public TX_FEE note
/// carrying a single native fee asset whose amount covers the required fee. Returns the fee
/// asset for further assertions.
pub(super) fn assert_single_fee_note(
    executed_transaction: &ExecutedTransaction,
) -> anyhow::Result<FungibleAsset> {
    assert_eq!(executed_transaction.output_notes().num_notes(), 1);
    let output_note = executed_transaction.output_notes().get_note(0);

    assert_eq!(output_note.metadata().tag(), TxFeeNote::TAG);
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);

    let assets = output_note.assets();
    assert_eq!(assets.num_assets(), 1);
    let asset = assets.iter().next().expect("fee note should carry an asset");
    let fee_asset = asset.unwrap_fungible();
    assert_eq!(fee_asset.faucet_id(), ACCOUNT_ID_FEE_FAUCET.try_into()?);

    let required_fee = executed_transaction.compute_fee();
    assert!(
        fee_asset.amount() >= required_fee,
        "paid fee {} should cover the required fee {required_fee}",
        fee_asset.amount()
    );

    Ok(fee_asset)
}

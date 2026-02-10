use alloc::string::String;

use anyhow::Context;
use miden_processor::ContextId;
use miden_processor::fast::ExecutionOutput;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::testing::storage::prepare_assets;
use miden_protocol::transaction::memory::{
    self,
    MemoryOffset,
    NOTE_MEM_SIZE,
    NUM_OUTPUT_NOTES_PTR,
    OUTPUT_NOTE_ASSETS_OFFSET,
    OUTPUT_NOTE_DIRTY_FLAG_OFFSET,
    OUTPUT_NOTE_METADATA_OFFSET,
    OUTPUT_NOTE_NUM_ASSETS_OFFSET,
    OUTPUT_NOTE_RECIPIENT_OFFSET,
    OUTPUT_NOTE_SECTION_OFFSET,
};
use miden_protocol::vm::StackInputs;
use miden_protocol::{Felt, Word, ZERO};

use crate::MockChain;

mod test_account;
mod test_account_delta;
mod test_account_interface;
mod test_active_note;
mod test_asset;
mod test_asset_vault;
mod test_auth;
mod test_epilogue;
mod test_faucet;
mod test_fee;
mod test_fpi;
mod test_input_note;
mod test_lazy_loading;
mod test_link_map;
mod test_note;
mod test_output_note;
mod test_prologue;
mod test_tx;

// HELPER FUNCTIONS
// ================================================================================================

/// Extension trait for an [`ExecutionOutput`] to conveniently read the stack and kernel memory.
pub trait ExecutionOutputExt {
    /// Reads a word from transaction kernel memory or returns [`Word::empty`] if that location is
    /// not initialized.
    fn get_kernel_mem_word(&self, addr: u32) -> Word;

    /// Reads an element from transaction kernel memory or returns [`ZERO`] if that location is not
    /// initialized.
    // Unused for now, but may become useful in the future.
    #[allow(dead_code)]
    fn get_kernel_mem_element(&self, addr: u32) -> Felt;

    /// Reads an element from the stack.
    fn get_stack_element(&self, idx: usize) -> Felt;

    /// Reads a [`Word`] from the stack in little-endian (memory) order.
    fn get_stack_word_le(&self, index: usize) -> Word;

    /// Reads the [`Word`] of the input note's memory identified by the index at the provided
    /// `offset`.
    fn get_note_mem_word(&self, note_idx: u32, offset: MemoryOffset) -> Word {
        self.get_kernel_mem_word(input_note_data_ptr(note_idx) + offset)
    }
}

impl ExecutionOutputExt for ExecutionOutput {
    fn get_kernel_mem_word(&self, addr: u32) -> Word {
        let tx_kernel_context = ContextId::root();
        let clk = 0u32;

        self.memory
            .read_word(tx_kernel_context, Felt::new(u64::from(addr)), clk.into())
            .expect("expected address to be word-aligned")
    }

    fn get_stack_element(&self, index: usize) -> Felt {
        *self.stack.get(index).expect("index must be in bounds")
    }

    fn get_stack_word_le(&self, index: usize) -> Word {
        self.stack.get_word(index).expect("index must be in bounds")
    }

    fn get_kernel_mem_element(&self, addr: u32) -> Felt {
        let tx_kernel_context = ContextId::root();

        self.memory
            .read_element(tx_kernel_context, Felt::new(u64::from(addr)))
            .expect("address converted from u32 should be in bounds")
    }
}

pub fn input_note_data_ptr(note_idx: u32) -> memory::MemoryAddress {
    memory::INPUT_NOTE_DATA_SECTION_OFFSET + note_idx * memory::NOTE_MEM_SIZE
}

/// Returns MASM code that defines a procedure called `create_mock_notes` which creates the notes
/// specified in `notes`, which stores output note metadata in the transaction host's memory.
pub fn create_mock_notes_procedure(notes: &[Note]) -> String {
    if notes.is_empty() {
        return String::new();
    }

    let mut script = String::from(
        "proc create_mock_notes
            # remove padding from prologue
            dropw dropw dropw dropw
        ",
    );

    for (idx, note) in notes.iter().enumerate() {
        let metadata = Word::from(note.metadata());
        let recipient = note.recipient().digest();
        let assets = prepare_assets(note.assets());
        let num_assets = assets.len();
        let note_offset = (idx as u32) * NOTE_MEM_SIZE;

        assert!(num_assets == 1, "notes are expected to have one asset only");

        script.push_str(&format!(
            "
                # populate note {idx}
                push.{metadata}
                push.{OUTPUT_NOTE_SECTION_OFFSET} push.{note_offset} push.{OUTPUT_NOTE_METADATA_OFFSET} add add mem_storew_le dropw

                push.{recipient}
                push.{OUTPUT_NOTE_SECTION_OFFSET} push.{note_offset} push.{OUTPUT_NOTE_RECIPIENT_OFFSET} add add mem_storew_le dropw

                push.{num_assets}
                push.{OUTPUT_NOTE_SECTION_OFFSET} push.{note_offset} push.{OUTPUT_NOTE_NUM_ASSETS_OFFSET} add add mem_store

                push.1 # dirty flag should be `1` by default
                push.{OUTPUT_NOTE_SECTION_OFFSET} push.{note_offset} push.{OUTPUT_NOTE_DIRTY_FLAG_OFFSET} add add mem_store

                push.{first_asset}
                push.{OUTPUT_NOTE_SECTION_OFFSET} push.{note_offset} push.{OUTPUT_NOTE_ASSETS_OFFSET} add add mem_storew_le dropw
                ",
            idx = idx,
            metadata = metadata,
            recipient = recipient,
            num_assets = num_assets,
            first_asset = assets[0],
            note_offset = note_offset,
        ));
    }
    script.push_str(&format!(
        "# set num output notes
                push.{count} push.{NUM_OUTPUT_NOTES_PTR} mem_store
            end
            ",
        count = notes.len(),
    ));

    script
}

// HELPER STRUCTURE
// ================================================================================================

/// Helper struct which holds the data required for the `input_note` and `output_note` tests.
struct TestSetup {
    mock_chain: MockChain,
    account: Account,
    p2id_note_0_assets: Note,
    p2id_note_1_asset: Note,
    p2id_note_2_assets: Note,
}

/// Return a [`TestSetup`], whose notes contain 0, 1 and 2 assets respectively.
fn setup_test() -> anyhow::Result<TestSetup> {
    let mut builder = MockChain::builder();

    // asset for the account
    let fungible_asset_0_double_amount = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?,
            10,
        )
        .context("fungible_asset_0 is invalid")?,
    );

    // assets for the P2ID notes
    let fungible_asset_0 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).context("id should be valid")?,
            5,
        )
        .context("fungible_asset_0 is invalid")?,
    );
    let fungible_asset_1 = Asset::Fungible(
        FungibleAsset::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
                .context("id should be valid")?,
            10,
        )
        .context("fungible_asset_1 is invalid")?,
    );

    let account = builder.add_existing_wallet_with_assets(
        crate::Auth::BasicAuth,
        [fungible_asset_0_double_amount, fungible_asset_1],
    )?;

    // Notes
    let p2id_note_0_assets = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[],
        NoteType::Public,
    )?;
    let p2id_note_1_asset = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_0],
        NoteType::Public,
    )?;
    let p2id_note_2_assets = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &[fungible_asset_0, fungible_asset_1],
        NoteType::Public,
    )?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    if std::env::var("DEBUG_NOTE_INPUTS").is_ok() {
        std::eprintln!(
            "p2id_note_1_asset inputs len={}, values={:?}, commitment={:?}",
            p2id_note_1_asset.inputs().num_values(),
            p2id_note_1_asset.inputs().values(),
            p2id_note_1_asset.inputs().commitment()
        );
    }

    anyhow::Ok(TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    })
}

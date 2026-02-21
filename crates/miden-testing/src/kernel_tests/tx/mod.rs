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
use miden_protocol::transaction::memory::{self, MemoryOffset};
use miden_protocol::vm::StackInputs;
use miden_protocol::{Felt, Word, ZERO};

use crate::MockChain;

mod test_account;
mod test_account_delta;
mod test_account_interface;
mod test_active_note;
mod test_array;
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

    /// Reads a [`Word`] from the stack in big-endian (reversed) order.
    fn get_stack_word_be(&self, index: usize) -> Word;

    /// Reads a [`Word`] from the stack in little-endian (memory) order.
    #[allow(dead_code)]
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
        let err_ctx = ();

        self.memory
            .read_word(tx_kernel_context, Felt::from(addr), clk.into(), &err_ctx)
            .expect("expected address to be word-aligned")
    }

    fn get_stack_element(&self, index: usize) -> Felt {
        *self.stack.get(index).expect("index must be in bounds")
    }

    fn get_stack_word_be(&self, index: usize) -> Word {
        self.stack.get_stack_word_be(index).expect("index must be in bounds")
    }

    fn get_stack_word_le(&self, index: usize) -> Word {
        self.stack.get_stack_word_le(index).expect("index must be in bounds")
    }

    fn get_kernel_mem_element(&self, addr: u32) -> Felt {
        let tx_kernel_context = ContextId::root();
        let err_ctx = ();

        self.memory
            .read_element(tx_kernel_context, Felt::from(addr), &err_ctx)
            .expect("address converted from u32 should be in bounds")
    }
}

pub fn input_note_data_ptr(note_idx: u32) -> memory::MemoryAddress {
    memory::INPUT_NOTE_DATA_SECTION_OFFSET + note_idx * memory::NOTE_MEM_SIZE
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

    anyhow::Ok(TestSetup {
        mock_chain,
        account,
        p2id_note_0_assets,
        p2id_note_1_asset,
        p2id_note_2_assets,
    })
}

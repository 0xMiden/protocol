//! Cycle-cost benchmark estimating the cost of storage arrays (a.k.a. storage lists, see issue
//! #2176) against the storage-map-backed [`double_word_array`] standard.
//!
//! A storage array of `N` double-words (one double-word = two words = 8 felts, the size of one
//! input-note asset) is modeled by the core primitives a future `get_array` / `set_array` would
//! invoke:
//! - read  `get_array` ≈ `mem::pipe_double_words_preimage_to_memory` (validates the advice preimage
//!   against the known slot commitment), exactly what `input_note::get_assets` does.
//! - write `set_array` ≈ `poseidon2::hash_double_words` (compute the commitment) +
//!   `mem::pipe_double_words_preimage_to_memory` (re-validate the advice preimage). Two hashes,
//!   because account mutators cross a `syscall` memory-context boundary.
//!
//! The map baseline exercises the real `double_word_array` (internally `2 ×` `get_map_item` /
//! `set_map_item` per double-word), so the comparison is measured rather than extrapolated.
//!
//! Run with: `cargo test -p miden-testing test_storage_array_bench -- --nocapture`.

use alloc::string::String;
use alloc::vec::Vec;
use std::println;

use anyhow::Result;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountBuilder,
    AccountComponent,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, NonFungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::code_builder::CodeBuilder;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{Auth, MockChain, TestTransactionBuilder, TransactionContext, TxContextInput};

/// Number of double-words to benchmark. Capped at 64 so the `get_assets` read path stays within
/// `MAX_ASSETS_PER_NOTE` (a single note can carry at most 64 assets).
const SWEEP: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

/// Memory destination used by the scripts. Word-aligned and far from any kernel region.
const DEST_PTR: u32 = 0;

/// Storage slot name backing the `double_word_array` map baseline.
const DWA_SLOT: &str = "bench::double_word_array::data";

// BENCHMARK
// ================================================================================================

/// Measures and prints the per-`N` cycle cost of array-style reads/writes versus the map baseline.
#[tokio::test]
async fn test_storage_array_bench() -> Result<()> {
    let mut rows = Vec::new();
    for &num_double_words in SWEEP {
        let read_assets = bench_read_get_assets(num_double_words).await?;
        let read_pipe = bench_read_generic_pipe(num_double_words).await?;
        let write = bench_write(num_double_words).await?;
        let map_read = bench_map(num_double_words, MapOp::Get).await?;
        let map_write = bench_map(num_double_words, MapOp::Set).await?;
        rows.push(Row {
            num_double_words,
            read_assets,
            read_pipe,
            write,
            map_read,
            map_write,
        });
    }

    println!(
        "\ncycles to move N double-words (one double-word = one input-note asset = 8 felts)\n"
    );
    println!(
        "{:>3} | {:>9} {:>9} | {:>9} | {:>9} {:>9}",
        "N", "read_asset", "read_raw", "write_raw", "read_map", "write_map",
    );
    println!("{:-<62}", "");
    for row in &rows {
        println!(
            "{:>3} | {:>9} {:>9} | {:>9} | {:>9} {:>9}",
            row.num_double_words,
            row.read_assets,
            row.read_pipe,
            row.write,
            row.map_read,
            row.map_write,
        );
    }

    Ok(())
}

/// One row of benchmark results: cycle counts to move `num_double_words` double-words each way.
struct Row {
    num_double_words: usize,
    read_assets: usize,
    read_pipe: usize,
    write: usize,
    map_read: usize,
    map_write: usize,
}

// READ BENCHMARKS
// ================================================================================================

/// Reads `N` double-words via `input_note::get_assets` from a note carrying `N` assets.
async fn bench_read_get_assets(num_double_words: usize) -> Result<usize> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let assets: Vec<Asset> = (0..num_double_words)
        .map(|index| NonFungibleAsset::mock(&(index as u32).to_le_bytes()))
        .collect();
    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account.id(),
        &assets,
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let code = format!(
        "
        use miden::protocol::input_note
        use miden::core::sys
        begin
            push.0 push.{DEST_PTR}       # [dest_ptr, note_index]
            exec.input_note::get_assets  # [num_assets]
            drop
            exec.sys::truncate_stack
        end
        "
    );
    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let context = mock_chain
        .build_tx_context(TxContextInput::AccountId(account.id()), &[], &[note])?
        .tx_script(tx_script)
        .build()?;

    script_cycles(context).await
}

/// Reads `N` double-words via a bare `mem::pipe_double_words_preimage_to_memory`, isolating the
/// dominant cost without the surrounding note machinery.
async fn bench_read_generic_pipe(num_double_words: usize) -> Result<usize> {
    let (commitment, values) = double_word_preimage(num_double_words);
    let num_words = num_double_words * 2;

    let code = format!(
        "
        use miden::core::mem
        use miden::core::sys
        begin
            push.{commitment}
            adv.push_mapval              # advice stack <- 2N words ; OS [COMMITMENT]
            push.{DEST_PTR}              # [dest_ptr, COMMITMENT]
            push.{num_words}             # [num_words, dest_ptr, COMMITMENT]
            exec.mem::pipe_double_words_preimage_to_memory
            drop
            exec.sys::truncate_stack
        end
        "
    );
    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let context = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .extend_advice_map([(commitment, values)])
        .build()?;

    script_cycles(context).await
}

// WRITE BENCHMARK
// ================================================================================================

/// Writes `N` double-words the way `set_array` would: pipe the advice preimage into memory
/// (validates against the commitment, hash 1), then re-hash that memory (hash 2). The data enters
/// memory through the pipe so no auxiliary fill loop pollutes the cycle count.
async fn bench_write(num_double_words: usize) -> Result<usize> {
    let (commitment, values) = double_word_preimage(num_double_words);
    let num_words = num_double_words * 2;
    let end_ptr = DEST_PTR + (num_words as u32) * 4;

    let code = format!(
        "
        use miden::core::mem
        use miden::core::crypto::hashes::poseidon2
        use miden::core::sys
        begin
            push.{commitment}
            adv.push_mapval
            push.{DEST_PTR}
            push.{num_words}
            exec.mem::pipe_double_words_preimage_to_memory  # [write_ptr'] (hash 1, validates)
            drop
            push.{end_ptr} push.{DEST_PTR}                  # [start_addr, end_addr]
            exec.poseidon2::hash_double_words               # [COMMITMENT] (hash 2)
            dropw
            exec.sys::truncate_stack
        end
        "
    );
    let tx_script = CodeBuilder::default().compile_tx_script(code)?;

    let context = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .extend_advice_map([(commitment, values)])
        .build()?;

    script_cycles(context).await
}

// MAP BASELINE
// ================================================================================================

/// Which `double_word_array` operation to benchmark.
#[derive(Clone, Copy)]
enum MapOp {
    Get,
    Set,
}

/// Reads or writes `N` double-words through the map-backed `double_word_array` standard, one call
/// per index.
async fn bench_map(num_double_words: usize, op: MapOp) -> Result<usize> {
    let slot_name = StorageSlotName::new(DWA_SLOT).expect("slot name should be valid");

    let wrapper_component_code = format!(
        r#"
        use miden::core::word
        use miden::standards::data_structures::double_word_array

        const ARRAY_SLOT_NAME = word("{slot_name}")

        #! Inputs:  [index, pad(15)]
        #! Outputs: [VALUE_0, VALUE_1, pad(8)]
        pub proc test_get
            push.ARRAY_SLOT_NAME[0..2]
            exec.double_word_array::get
            swapdw dropw dropw
        end

        #! Inputs:  [index, VALUE_0, VALUE_1, pad(7)]
        #! Outputs: [OLD_VALUE_0, OLD_VALUE_1, pad(8)]
        pub proc test_set
            push.ARRAY_SLOT_NAME[0..2]
            exec.double_word_array::set
        end
        "#
    );

    let wrapper_library = CodeBuilder::default()
        .compile_component_code("wrapper::component", wrapper_component_code)?;

    // Pre-populate indices `0..N` (two map entries per index) so reads hit populated leaves and
    // writes overwrite existing values.
    let mut entries = Vec::new();
    for index in 0..num_double_words as u32 {
        entries.push((
            StorageMapKey::from_array([0u32, 0, 0, index]),
            Word::from([index + 1, index + 1, index + 1, index + 1]),
        ));
        entries.push((
            StorageMapKey::from_array([0u32, 0, 1, index]),
            Word::from([index + 2, index + 2, index + 2, index + 2]),
        ));
    }

    let wrapper_component = AccountComponent::new(
        wrapper_library.clone(),
        vec![StorageSlot::with_map(slot_name, StorageMap::with_entries(entries)?)],
        AccountComponentMetadata::mock("wrapper::component"),
    )?;

    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(wrapper_component)
        .build_existing()?;

    let mut body = String::new();
    for index in 0..num_double_words as u32 {
        match op {
            MapOp::Get => body.push_str(&format!(
                "
            push.{index}
            call.wrapper::test_get
            dropw dropw
                "
            )),
            MapOp::Set => body.push_str(&format!(
                "
            push.{value_1} push.{value_0} push.{index}
            call.wrapper::test_set
            dropw dropw
                ",
                value_0 = Word::from([index + 100, index + 100, index + 100, index + 100]),
                value_1 = Word::from([index + 200, index + 200, index + 200, index + 200]),
            )),
        }
    }

    let tx_script_code = format!(
        "
        use wrapper::component->wrapper
        use miden::core::sys
        begin
            {body}
            exec.sys::truncate_stack
        end
        "
    );
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&wrapper_library)?
        .compile_tx_script(tx_script_code)?;

    let context = TestTransactionBuilder::new(account).tx_script(tx_script).build()?;

    script_cycles(context).await
}

// HELPERS
// ================================================================================================

/// Executes the transaction and returns the number of cycles spent in the transaction script.
async fn script_cycles(context: TransactionContext) -> Result<usize> {
    Ok(context.execute().await?.measurements().tx_script_processing)
}

/// Builds a deterministic preimage of `2N` words and its Poseidon2 commitment. The commitment
/// matches what `hash_double_words` / `pipe_double_words_preimage_to_memory` compute over the same
/// elements (the same convention as note assets).
fn double_word_preimage(num_double_words: usize) -> (Word, Vec<Felt>) {
    let num_words = num_double_words * 2;
    let mut values = Vec::with_capacity(num_words * 4);
    for word_index in 0..num_words as u32 {
        let base = word_index * 4;
        for offset in 1..=4u32 {
            values.push(Felt::from(base + offset));
        }
    }
    let commitment = Hasher::hash_elements(&values);
    (commitment, values)
}

//! Tests for the sorted pipe procedures in `miden::protocol_utils::mem`.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::errors::tx_kernel::ERR_MEM_WORDS_NOT_STRICTLY_SORTED;
use miden_protocol::{Hasher, Word};

use crate::{MockTransaction, TestTransactionBuilder, assert_execution_error};

/// Returns the advice map key under which the tests provide the piped words.
fn advice_key() -> Word {
    Word::from([1, 2, 3, 4u32])
}

/// The memory address at which the tests write the piped words.
const WRITE_PTR: u32 = 4000;

/// Returns words in ascending order, including words that differ only in the least or most
/// significant element, so that the Rust order and `word::lt` are compared on both.
fn sorted_words() -> Vec<Word> {
    BTreeSet::from([
        Word::from([9, 0, 0, 0u32]),
        Word::from([0, 0, 0, 1u32]),
        Word::from([1, 0, 0, 1u32]),
        Word::from([0, 7, 0, 1u32]),
        Word::from([3, 3, 3, 3u32]),
    ])
    .into_iter()
    .collect()
}

/// Returns the code that pipes `num_entries` entries with the provided procedure and asserts the
/// commitment and the end pointer.
fn pipe_code(proc_name: &str, num_entries: usize, words: &[Word]) -> String {
    let commitment = Hasher::hash_elements(Word::words_as_elements(words));
    let end_ptr = WRITE_PTR as usize + words.len() * 4;

    // the last word is the one that the odd tail of the words procedure writes
    let last_word_check = words
        .last()
        .map(|last_word| {
            format!(
                "padw push.{last_word_ptr} mem_loadw_le push.{last_word} assert_eqw.err=\"last word\"",
                last_word_ptr = end_ptr - 4,
            )
        })
        .unwrap_or_default();

    let advice_key = advice_key();

    format!(
        r#"
        use miden::protocol_utils::mem

        begin
            push.{advice_key} adv.push_mapvaln.8 dropw
            # drop the number of elements that precedes the padded elements
            adv_push drop

            push.{WRITE_PTR} push.{num_entries}
            exec.mem::{proc_name}
            # => [COMMITMENT, end_ptr]

            push.{commitment} assert_eqw.err="commitment"
            push.{end_ptr} assert_eq.err="end pointer"

            {last_word_check}
        end
        "#
    )
}

/// Returns a mock transaction with the words in the advice map.
fn mock_tx_with_words(words: &[Word]) -> anyhow::Result<MockTransaction> {
    TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(advice_key(), Word::words_as_elements(words).to_vec())
        .build()
}

#[rstest::rstest]
#[case::empty(0)]
#[case::one(1)]
#[case::two(2)]
#[case::three(3)]
#[case::five(5)]
#[tokio::test]
async fn pipe_strictly_sorted_words_writes_and_commits(
    #[case] num_words: usize,
) -> anyhow::Result<()> {
    let words = sorted_words()[..num_words].to_vec();
    let code = pipe_code("pipe_strictly_sorted_words_to_memory", num_words, &words);

    mock_tx_with_words(&words)?.execute_code(&code).await?;

    Ok(())
}

#[rstest::rstest]
#[case::duplicate_in_pair(vec![0, 0])]
#[case::unsorted_in_pair(vec![1, 0])]
#[case::unsorted_across_pairs(vec![0, 2, 1, 3])]
#[case::duplicate_across_pairs(vec![0, 1, 1, 2])]
#[case::unsorted_tail(vec![0, 1, 3, 4, 2])]
#[case::duplicate_tail(vec![0, 1, 1])]
#[tokio::test]
async fn pipe_strictly_sorted_words_rejects_unsorted_words(
    #[case] word_indices: Vec<usize>,
) -> anyhow::Result<()> {
    let sorted_words = sorted_words();
    let words: Vec<Word> = word_indices.iter().map(|&idx| sorted_words[idx]).collect();
    let code = pipe_code("pipe_strictly_sorted_words_to_memory", words.len(), &words);

    let result = mock_tx_with_words(&words)?.execute_code(&code).await;

    assert_execution_error!(result, ERR_MEM_WORDS_NOT_STRICTLY_SORTED);

    Ok(())
}

#[rstest::rstest]
#[case::empty(0)]
#[case::one(1)]
#[case::three(3)]
#[tokio::test]
async fn pipe_strictly_sorted_key_value_pairs_writes_and_commits(
    #[case] num_entries: usize,
) -> anyhow::Result<()> {
    // the values are in descending order to show that only the keys must be sorted
    let keys = sorted_words();
    let words: Vec<Word> = keys[..num_entries]
        .iter()
        .zip(keys.iter().rev())
        .flat_map(|(key, value)| [*key, *value])
        .collect();
    let code = pipe_code("pipe_strictly_sorted_key_value_pairs_to_memory", num_entries, &words);

    mock_tx_with_words(&words)?.execute_code(&code).await?;

    Ok(())
}

#[rstest::rstest]
#[case::duplicate_key(vec![0, 0])]
#[case::unsorted_keys(vec![0, 2, 1])]
#[tokio::test]
async fn pipe_strictly_sorted_key_value_pairs_rejects_unsorted_keys(
    #[case] key_indices: Vec<usize>,
) -> anyhow::Result<()> {
    let sorted_words = sorted_words();
    let words: Vec<Word> =
        key_indices.iter().flat_map(|&idx| [sorted_words[idx], Word::empty()]).collect();
    let code =
        pipe_code("pipe_strictly_sorted_key_value_pairs_to_memory", key_indices.len(), &words);

    let result = mock_tx_with_words(&words)?.execute_code(&code).await;

    assert_execution_error!(result, ERR_MEM_WORDS_NOT_STRICTLY_SORTED);

    Ok(())
}

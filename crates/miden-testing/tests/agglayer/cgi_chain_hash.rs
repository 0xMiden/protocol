extern crate alloc;

use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::{GlobalIndex, agglayer_library};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;
use miden_tx::utils::hex_to_bytes;

use super::test_utils::{CGIChainHashTestData, CLAIMED_GLOBAL_INDEX_HASH_CHAIN};

/// Checks the correctness of the claimed global index chain hash computation, used during the CLAIM
/// note execution.
#[tokio::test]
async fn compute_cgi_hash_chain_matches_solidity_vector() -> anyhow::Result<()> {
    let cgi_chain_hash_data: &CGIChainHashTestData = &CLAIMED_GLOBAL_INDEX_HASH_CHAIN;

    let [global_index_lo, global_index_hi] =
        GlobalIndex::from_hex(&cgi_chain_hash_data.global_index)
            .expect("valid global index hex")
            .to_words();

    let leaf_bytes: [u8; 32] =
        hex_to_bytes(&cgi_chain_hash_data.leaf).expect("leaf value must be 32 bytes");
    let [leaf_lo, leaf_hi] = Keccak256Output::from(leaf_bytes).to_words();

    let expected_cgi_hash_bytes: [u8; 32] =
        hex_to_bytes(&cgi_chain_hash_data.cgi_chain_hash).expect("claimed hash must be 32 bytes");
    let [expected_cgi_hash_lo, expected_cgi_hash_hi] =
        Keccak256Output::from(expected_cgi_hash_bytes).to_words();

    let old_cgi_hash_bytes: [u8; 32] = hex_to_bytes(&cgi_chain_hash_data.old_cgi_chain_hash)
        .expect("claimed hash must be 32 bytes");
    let [old_cgi_hash_lo, old_cgi_hash_hi] = Keccak256Output::from(old_cgi_hash_bytes).to_words();

    let source = format!(
        r#"
        use miden::core::crypto::hashes::keccak256
        use miden::core::word
        use miden::core::sys

        use miden::agglayer::bridge::bridge_in
        use miden::agglayer::common::utils
        
        const LEAF_VALUE_PTR = 0
        const GLOBAL_INDEX_PTR = 512

        begin
            # push the expected hash onto the stack
            push.{expected_cgi_hash_hi} exec.word::reverse
            push.{expected_cgi_hash_lo} exec.word::reverse
            # => [EXPECTED_CGI_HASH[8]]

            # push the old CGI chain hash onto the stack
            push.{old_cgi_hash_hi} exec.word::reverse
            push.{old_cgi_hash_lo} exec.word::reverse
            # => [OLD_CGI_CHAIN_HASH[8], EXPECTED_CGI_HASH[8]]

            # push the leaf value onto the stack and save it into the memory
            push.LEAF_VALUE_PTR 
            push.{leaf_hi} exec.word::reverse
            push.{leaf_lo} exec.word::reverse
            exec.utils::mem_store_double_word dropw dropw
            # => [leaf_value_ptr, OLD_CGI_CHAIN_HASH[8], EXPECTED_CGI_HASH[8]]

            # push the global index onto the stack and save it into the memory
            push.GLOBAL_INDEX_PTR 
            push.{global_index_hi} exec.word::reverse
            push.{global_index_lo} exec.word::reverse
            exec.utils::mem_store_double_word dropw dropw drop
            # => [leaf_value_ptr, OLD_CGI_CHAIN_HASH[8], EXPECTED_CGI_HASH[8]]

            # compute the CGI chain hash
            exec.bridge_in::compute_cgi_hash_chain
            # => [NEW_CGI_CHAIN_HASH[8], EXPECTED_CGI_HASH[8]]

            # assert that the hashes are identical
            # => [NEW_CGI_CHAIN_HASH_LO, NEW_CGI_CHAIN_HASH_HI, EXPECTED_CGI_HASH_LO, EXPECTED_CGI_HASH_HI]

            swapw.3
            # => [EXPECTED_CGI_HASH_HI, NEW_CGI_CHAIN_HASH_HI, EXPECTED_CGI_HASH_LO, NEW_CGI_CHAIN_HASH_LO]

            assert_eqw.err="CGI chain hash (HI) is incorrect"
            # => [EXPECTED_CGI_HASH_LO, NEW_CGI_CHAIN_HASH_LO]

            assert_eqw.err="CGI chain hash (LO) is incorrect"
            # => []

            exec.sys::truncate_stack
            # => []
        end
    "#
    );

    let tx_script = CodeBuilder::new()
        .with_statically_linked_library(&agglayer_library())?
        .compile_tx_script(source)?;

    TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script.clone())
        .build()?
        .execute()
        .await?;

    Ok(())
}

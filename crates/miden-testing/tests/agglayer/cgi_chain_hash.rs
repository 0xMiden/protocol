extern crate alloc;

use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::{GlobalIndex, agglayer_library};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;
use miden_tx::utils::hex_to_bytes;

use super::test_utils::{CGIChainHashTestData, CLAIMED_GLOBAL_INDEX_HASH_CHAIN};

#[tokio::test]
#[ignore = "CGI chain hash is not stored anywhere yet"]
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
        use miden::core::sys

        use miden::agglayer::common::utils
        
        const GLOBAL_INDEX_PTR = 0
        const OLD_CGI_CHAIN_HASH_PTR = 8

        # This is a copy of the `compute_cgi_hash_chain` procedure, designed only for testing
        # purposes. Keep in sync with the original procedure.
        #
        # This procedure expects the global index and the old CGI chain hash to be stored in memory
        # at addresses 0 and 8 respectively.
        #
        # Inputs: [LEAF_VALUE[8]]
        # Outputs: [NEW_CGI_CHAIN_HASH[8]]
        proc compute_cgi_hash_chain_copy
            # load the global index onto the stack
            push.GLOBAL_INDEX_PTR exec.utils::mem_load_double_word
            # => [GLOBAL_INDEX[8], LEAF_VALUE[8]]

            exec.keccak256::merge
            # => [Keccak256(GLOBAL_INDEX, LEAF_VALUE), pad(8)]

            # load the old CGI chain hash
            push.OLD_CGI_CHAIN_HASH_PTR exec.utils::mem_load_double_word
            # => [OLD_CGI_CHAIN_HASH[8], Keccak256(GLOBAL_INDEX, LEAF_VALUE), pad(8)]

            # compute the new CGI chain hash
            exec.keccak256::merge
            # => [NEW_CGI_CHAIN_HASH[8], pad(8)]
        end

        begin
            # push the expected hash onto the stack
            push.{expected_cgi_hash_hi} push.{expected_cgi_hash_lo}
            # => [EXPECTED_CGI_HASH[8]]

            # push the leaf value onto the stack
            push.{leaf_hi} push.{leaf_lo}
            # => [LEAF_VALUE[8], EXPECTED_CGI_HASH[8]]

            # push the global index onto the stack and save it into the memory
            push.GLOBAL_INDEX_PTR push.{global_index_hi} push.{global_index_lo}
            exec.utils::mem_store_double_word dropw dropw drop
            # => [LEAF_VALUE[8], EXPECTED_CGI_HASH[8]]

            # push the old CGI chain hash onto the stack and save it into the memory
            push.OLD_CGI_CHAIN_HASH_PTR push.{old_cgi_hash_hi} push.{old_cgi_hash_lo}
            exec.utils::mem_store_double_word dropw dropw drop
            # => [LEAF_VALUE[8], EXPECTED_CGI_HASH[8]]

            # compute the CGI chain hash
            exec.compute_cgi_hash_chain_copy
            # => [NEW_CGI_CHAIN_HASH[8], EXPECTED_CGI_HASH[8]]

            # assert that the hashes are identical
            # => [NEW_CGI_CHAIN_HASH_LO, NEW_CGI_CHAIN_HASH_HI, EXPECTED_CGI_HASH_LO, EXPECTED_CGI_HASH_HI]

            debug.stack

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

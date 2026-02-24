extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::{GlobalIndex, agglayer_library};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_protocol::Felt;
use miden_tx::utils::hex_to_bytes;

use super::test_utils::{
    CGIChainHashTestData,
    CLAIMED_GLOBAL_INDEX_HASH_CHAIN,
    execute_program_with_default_host,
};

#[tokio::test]
#[ignore = "CGI chain hash is not stored anywhere yet"]
async fn compute_cgi_hash_chain_matches_solidity_vector() -> anyhow::Result<()> {
    let vector: &CGIChainHashTestData = &*CLAIMED_GLOBAL_INDEX_HASH_CHAIN;

    let global_index = GlobalIndex::from_hex(&vector.global_index).expect("valid global index hex");

    let leaf_bytes: [u8; 32] = hex_to_bytes(&vector.leaf)
        .expect("valid leaf value hex")
        .try_into()
        .expect("leaf value must be 32 bytes");
    let [leaf_lo, leaf_hi] = Keccak256Output::from(leaf_bytes).to_words();

    let expected_hash_bytes: [u8; 32] = hex_to_bytes(&vector.cgi_chain_hash)
        .expect("valid claimed hash hex")
        .try_into()
        .expect("claimed hash must be 32 bytes");
    let [expected_hash_lo, expected_hash_hi] = Keccak256Output::from(expected_hash_bytes).to_words();

    let source = format!(
        r#"
        use miden::core::sys
        use miden::agglayer::bridge::bridge_in

        begin
            
        end
    "#
    );



    Ok(())
}

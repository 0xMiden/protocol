use alloc::format;
use alloc::string::ToString;

use miden_agglayer::{ExitRoot, SmtNode, agglayer_library};
use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
use miden_protocol::utils::sync::LazyLock;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;

// MERKLE TREE FRONTIER
// ================================================================================================

static CANONICAL_ZEROS_32: LazyLock<Vec<Keccak256Digest>> = LazyLock::new(|| {
    let mut zeros_by_height = Vec::with_capacity(32);

    // Push the zero of height 0 to the zeros vec. This is done separately because the zero of
    // height 0 is just a plain zero array ([0u8; 32]), it doesn't require to perform any hashing.
    zeros_by_height.push(Keccak256Digest::default());

    // Compute the canonical zeros for each height from 1 to 32
    // Zero of height `n` is computed as: `ZERO_N = Keccak256::merge(ZERO_{N-1}, ZERO_{N-1})`
    for _ in 1..32 {
        let last_zero = zeros_by_height.last().expect("zeros vec should have at least one value");
        let current_height_zero = Keccak256::merge(&[*last_zero, *last_zero]);
        zeros_by_height.push(current_height_zero);
    }

    zeros_by_height
});

struct MerkleTreeFrontier32<const TREE_HEIGHT: usize = 32> {
    num_leaves: u32,
    frontier: [Keccak256Digest; TREE_HEIGHT],
}

impl<const TREE_HEIGHT: usize> MerkleTreeFrontier32<TREE_HEIGHT> {
    pub fn new() -> Self {
        Self {
            num_leaves: 0,
            frontier: [Keccak256Digest::default(); TREE_HEIGHT],
        }
    }

    pub fn append_and_update_frontier(&mut self, new_leaf: Keccak256Digest) -> Keccak256Digest {
        let mut curr_hash = new_leaf;
        let mut idx = self.num_leaves;
        self.num_leaves += 1;

        for height in 0..TREE_HEIGHT {
            if (idx & 1) == 0 {
                // This height wasn't "occupied" yet: store cur as the subtree root at height h.
                self.frontier[height] = curr_hash;

                // Pair it with the canonical zero subtree on the right at this height.
                curr_hash = Keccak256::merge(&[curr_hash, CANONICAL_ZEROS_32[height]]);
            } else {
                // This height already had a subtree root stored in frontier[h], merge into parent.
                curr_hash = Keccak256::merge(&[self.frontier[height], curr_hash])
            }

            idx >>= 1;
        }

        // curr_hash at this point is equal to the root of the full tree
        curr_hash
    }
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn test_append_and_update_frontier() -> anyhow::Result<()> {
    let mut mtf = MerkleTreeFrontier32::<32>::new();

    let mut source = "use agglayer::bridge::merkle_tree_frontier begin".to_string();

    for round in 0..32 {
        // construct the leaf from the hex representation of the round number
        let leaf = Keccak256Digest::try_from(format!("{:#066x}", round).as_str()).unwrap();
        let root = mtf.append_and_update_frontier(leaf);
        let num_leaves = mtf.num_leaves;

        source.push_str(&leaf_assertion_code(
            SmtNode::new(leaf.into()),
            ExitRoot::new(root.into()),
            num_leaves,
        ));
    }

    source.push_str("end");

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

#[tokio::test]
async fn test_check_empty_mtf_root() -> anyhow::Result<()> {
    let zero_leaf = Keccak256Digest::default();
    let zero_31 = *CANONICAL_ZEROS_32.get(31).expect("zeros should have 32 values total");
    let empty_mtf_root = Keccak256::merge(&[zero_31, zero_31]);

    let mut source = "use agglayer::bridge::merkle_tree_frontier begin".to_string();

    for round in 1..=32 {
        // check that pushing the zero leaves into the MTF doesn't change its root
        source.push_str(&leaf_assertion_code(
            SmtNode::new(zero_leaf.into()),
            ExitRoot::new(empty_mtf_root.into()),
            round,
        ));
    }

    source.push_str("end");

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

// SOLIDITY COMPATIBILITY TESTS
// ================================================================================================
// These tests verify that the Rust MerkleTreeFrontier32 implementation produces identical
// results to the Solidity DepositContractBase.sol implementation.
// Test vectors generated from: https://github.com/agglayer/agglayer-contracts
// Run `make generate-solidity-test-vectors` to regenerate the test vectors.

use super::test_utils::{SOLIDITY_CANONICAL_ZEROS, SOLIDITY_MTF_VECTORS};

/// Verifies that the Rust MerkleTreeFrontier32 produces the same canonical zeros as Solidity.
#[test]
fn test_solidity_canonical_zeros_compatibility() {
    for (height, expected_hex) in SOLIDITY_CANONICAL_ZEROS.canonical_zeros.iter().enumerate() {
        let expected = Keccak256Digest::try_from(expected_hex.as_str()).unwrap();
        let actual = CANONICAL_ZEROS_32[height];

        assert_eq!(
            actual, expected,
            "canonical zero mismatch at height {}: expected {}, got {:?}",
            height, expected_hex, actual
        );
    }
}

/// Verifies that the Rust MerkleTreeFrontier32 produces the same roots as Solidity's
/// DepositContractBase after adding each leaf.
#[test]
fn test_solidity_mtf_compatibility() {
    let mtf_vectors = &*SOLIDITY_MTF_VECTORS;

    // Validate parallel arrays have same length
    assert_eq!(mtf_vectors.leaves.len(), mtf_vectors.roots.len());
    assert_eq!(mtf_vectors.leaves.len(), mtf_vectors.counts.len());

    let mut mtf = MerkleTreeFrontier32::<32>::new();

    for i in 0..mtf_vectors.leaves.len() {
        let leaf = Keccak256Digest::try_from(mtf_vectors.leaves[i].as_str()).unwrap();
        let expected_root = Keccak256Digest::try_from(mtf_vectors.roots[i].as_str()).unwrap();

        let actual_root = mtf.append_and_update_frontier(leaf);
        let actual_count = mtf.num_leaves;

        assert_eq!(
            actual_count, mtf_vectors.counts[i],
            "leaf count mismatch after adding leaf {}: expected {}, got {}",
            mtf_vectors.leaves[i], mtf_vectors.counts[i], actual_count
        );

        assert_eq!(
            actual_root, expected_root,
            "root mismatch after adding leaf {} (count={}): expected {}, got {:?}",
            mtf_vectors.leaves[i], mtf_vectors.counts[i], mtf_vectors.roots[i], actual_root
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn leaf_assertion_code(leaf: SmtNode, expected_root: ExitRoot, num_leaves: u32) -> String {
    let [leaf_lo, leaf_hi] = leaf.to_words();
    let [root_lo, root_hi] = expected_root.to_words();

    format!(
        r#"
            # load the provided leaf onto the stack
            push.{leaf_hi}
            push.{leaf_lo}

            # add this leaf to the MTF
            exec.merkle_tree_frontier::append_and_update_frontier
            # => [NEW_ROOT_LO, NEW_ROOT_HI, new_leaf_count]

            # assert the root correctness after the first leaf was added
            push.{root_lo}
            push.{root_hi}
            movdnw.3
            # => [EXPECTED_ROOT_LO, NEW_ROOT_LO, NEW_ROOT_HI, EXPECTED_ROOT_HI, new_leaf_count]

            assert_eqw.err="MTF root (LO) is incorrect"
            # => [NEW_ROOT_HI, EXPECTED_ROOT_HI, new_leaf_count]

            assert_eqw.err="MTF root (HI) is incorrect"
            # => [new_leaf_count]

            # assert the new number of leaves
            push.{num_leaves}
            assert_eq.err="new leaf count is incorrect"
        "#
    )
}

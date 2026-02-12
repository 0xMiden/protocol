use miden_crypto::merkle::smt::Smt;
#[cfg(not(target_family = "wasm"))]
use winter_rand_utils::rand_value;

use crate::Word;
use crate::account::Account;
use crate::block::account_tree::{AccountTree, account_id_to_smt_key};
use crate::block::{BlockHeader, BlockNumber, FeeParameters};
use crate::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;
use crate::testing::random_signer::RandomBlockSigner;

impl BlockHeader {
    /// Creates a mock block. The account tree is formed from the provided `accounts`,
    /// and the chain commitment and note root are set to the provided `chain_commitment` and
    /// `note_root` values respectively.
    ///
    /// For non-WASM targets, the remaining header values are initialized randomly. For WASM
    /// targets, values are initialized to [Default::default()]
    pub fn mock(
        block_num: impl Into<BlockNumber>,
        chain_commitment: Option<Word>,
        note_root: Option<Word>,
        accounts: &[Account],
        tx_kernel_commitment: Word,
    ) -> Self {
        let smt = Smt::with_entries(
            accounts
                .iter()
                .map(|acct| (account_id_to_smt_key(acct.id()), acct.commitment())),
        )
        .expect("failed to create account db");
        let acct_db = AccountTree::new(smt).expect("failed to create account tree");
        let account_root = acct_db.root();
        let fee_parameters =
            FeeParameters::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 500)
                .expect("native asset ID should be a fungible faucet ID");
        let validator_key = SecretKey::random().public_key();

        #[cfg(not(target_family = "wasm"))]
        let (
            prev_block_commitment,
            chain_commitment,
            nullifier_root,
            note_root,
            tx_commitment,
            timestamp,
        ) = {
            let prev_block_commitment = rand_value::<Word>();
            let chain_commitment = chain_commitment.unwrap_or(rand_value::<Word>());
            let nullifier_root = rand_value::<Word>();
            let note_root = note_root.unwrap_or(rand_value::<Word>());
            let tx_commitment = rand_value::<Word>();
            let timestamp = rand_value();

            (
                prev_block_commitment,
                chain_commitment,
                nullifier_root,
                note_root,
                tx_commitment,
                timestamp,
            )
        };

        #[cfg(target_family = "wasm")]
        let (
            prev_block_commitment,
            chain_commitment,
            nullifier_root,
            note_root,
            tx_commitment,
            timestamp,
        ) = {
            (
                Default::default(),
                chain_commitment.unwrap_or_default(),
                Default::default(),
                note_root.unwrap_or_default(),
                Default::default(),
                Default::default(),
            )
        };

        BlockHeader::new(
            0,
            prev_block_commitment,
            block_num.into(),
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            tx_kernel_commitment,
            validator_key,
            fee_parameters,
            timestamp,
        )
    }
}

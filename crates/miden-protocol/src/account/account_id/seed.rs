use alloc::vec::Vec;

use crate::account::account_id::AccountIdVersion;
use crate::account::account_id::v0::{compute_digest, validate_prefix};
use crate::account::{AccountStorageMode, AccountType};
use crate::errors::AccountError;
use crate::{Felt, Word};

/// Finds and returns a seed suitable for creating an account ID for the specified account type
/// using the provided initial seed as a starting point.
///
/// This currently always uses a single thread. This method used to either use a single- or
/// multi-threaded implementation based on a compile-time feature flag. The multi-threaded
/// implementation was removed in commit dab6159318832fc537bb35abf251870a9129ac8c in PR 1061.
pub(super) fn compute_account_seed(
    init_seed: [u8; 32],
    account_type: AccountType,
    storage_mode: AccountStorageMode,
    version: AccountIdVersion,
    code_commitment: Word,
    storage_commitment: Word,
) -> Result<Word, AccountError> {
    compute_account_seed_single(
        init_seed,
        account_type,
        storage_mode,
        version,
        code_commitment,
        storage_commitment,
    )
}

fn compute_account_seed_single(
    init_seed: [u8; 32],
    account_type: AccountType,
    storage_mode: AccountStorageMode,
    version: AccountIdVersion,
    code_commitment: Word,
    storage_commitment: Word,
) -> Result<Word, AccountError> {
    let init_seed: Vec<[u8; 8]> =
        init_seed.chunks(8).map(|chunk| chunk.try_into().unwrap()).collect();
    let mut current_seed: Word = Word::from([
        Felt::new(u64::from_le_bytes(init_seed[0])),
        Felt::new(u64::from_le_bytes(init_seed[1])),
        Felt::new(u64::from_le_bytes(init_seed[2])),
        Felt::new(u64::from_le_bytes(init_seed[3])),
    ]);
    let mut current_digest = compute_digest(current_seed, code_commitment, storage_commitment);

    // loop until we have a seed that satisfies the specified account type.
    loop {
        // Check if the seed satisfies the specified type, storage mode and version. Additionally,
        // the most significant bit of the suffix must be zero to ensure felt validity.
        let prefix = current_digest.as_elements()[0];
        let suffix = current_digest.as_elements()[1];
        let is_suffix_msb_zero = suffix.as_int() >> 63 == 0;

        if let Ok((computed_account_type, computed_storage_mode, computed_version)) =
            validate_prefix(prefix)
            && computed_account_type == account_type
            && computed_storage_mode == storage_mode
            && computed_version == version
            && is_suffix_msb_zero
        {
            return Ok(current_seed);
        };

        current_seed = current_digest;
        current_digest = compute_digest(current_seed, code_commitment, storage_commitment);
    }
}

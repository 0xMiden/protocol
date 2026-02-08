use miden_core::field::PrimeField64;
use miden_processor::{ExecutionError, Felt, ProcessorState};
use miden_protocol::account::{AccountId, StorageSlotId, StorageSlotType};
use miden_protocol::note::{NoteId, NoteInputs};
use miden_protocol::transaction::memory::{
    ACCOUNT_STACK_TOP_PTR,
    ACCT_CODE_COMMITMENT_OFFSET,
    ACCT_STORAGE_SLOT_ID_PREFIX_OFFSET,
    ACCT_STORAGE_SLOT_ID_SUFFIX_OFFSET,
    ACCT_STORAGE_SLOT_TYPE_OFFSET,
    ACCT_STORAGE_SLOT_VALUE_OFFSET,
    ACTIVE_INPUT_NOTE_PTR,
    NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR,
};
use miden_protocol::{Hasher, Word};

use crate::errors::TransactionKernelError;

// TRANSACTION KERNEL PROCESS
// ================================================================================================

pub(super) trait TransactionKernelProcess {
    /// Returns the pointer to the active account.
    fn get_active_account_ptr(&self) -> Result<u32, TransactionKernelError>;

    /// Returns the [`AccountId`] of the active account.
    fn get_active_account_id(&self) -> Result<AccountId, TransactionKernelError>;

    /// Returns the account code commitment of the active account.
    fn get_active_account_code_commitment(&self) -> Result<Word, TransactionKernelError>;

    #[allow(dead_code)]
    fn get_num_storage_slots(&self) -> Result<u64, TransactionKernelError>;

    fn get_vault_root(&self, vault_root_ptr: Felt) -> Result<Word, TransactionKernelError>;

    fn get_active_note_id(&self) -> Result<Option<NoteId>, TransactionKernelError>;

    fn get_storage_slot(
        &self,
        slot_ptr: Felt,
    ) -> Result<(StorageSlotId, StorageSlotType, Word), TransactionKernelError>;

    fn read_note_recipient_info_from_adv_map(
        &self,
        recipient_digest: Word,
    ) -> Result<(NoteInputs, Word, Word), TransactionKernelError>;

    fn read_note_inputs_from_adv_map(
        &self,
        inputs_commitment: &Word,
    ) -> Result<NoteInputs, TransactionKernelError>;

    fn has_advice_map_entry(&self, key: Word) -> bool;

    /// Returns `true` if the advice provider has a merkle path for the provided root and leaf
    /// index, `false` otherwise.
    fn has_merkle_path<const TREE_DEPTH: u8>(
        &self,
        root: Word,
        leaf_index: Felt,
    ) -> Result<bool, TransactionKernelError>;
}

impl<'a> TransactionKernelProcess for ProcessorState<'a> {
    fn get_active_account_ptr(&self) -> Result<u32, TransactionKernelError> {
        let account_stack_top_ptr =
            self.get_mem_value(self.ctx(), ACCOUNT_STACK_TOP_PTR).ok_or_else(|| {
                TransactionKernelError::other("account stack top ptr should be initialized")
            })?;
        let account_stack_top_ptr: u32 =
            account_stack_top_ptr.as_canonical_u64().try_into().map_err(|_| {
                TransactionKernelError::other("account stack top ptr should fit into a u32")
            })?;

        let active_account_ptr = self
            .get_mem_value(self.ctx(), account_stack_top_ptr)
            .ok_or_else(|| TransactionKernelError::other("account id should be initialized"))?;
        active_account_ptr
            .as_canonical_u64()
            .try_into()
            .map_err(|_| TransactionKernelError::other("active account ptr should fit into a u32"))
    }

    fn get_active_account_id(&self) -> Result<AccountId, TransactionKernelError> {
        let active_account_ptr = self.get_active_account_ptr()?;
        let active_account_id_and_nonce = self
            .get_mem_word(self.ctx(), active_account_ptr)
            .map_err(|_| {
                TransactionKernelError::other("active account ptr should be word-aligned")
            })?
            .ok_or_else(|| {
                TransactionKernelError::other("active account id should be initialized")
            })?;

        AccountId::try_from([active_account_id_and_nonce[3], active_account_id_and_nonce[2]])
            .map_err(|_| {
                TransactionKernelError::other(
                    "active account id ptr should point to a valid account ID",
                )
            })
    }

    fn get_active_account_code_commitment(&self) -> Result<Word, TransactionKernelError> {
        let active_account_ptr = self.get_active_account_ptr()?;
        let code_commitment = self
            .get_mem_word(self.ctx(), active_account_ptr + ACCT_CODE_COMMITMENT_OFFSET)
            .map_err(|err| {
                TransactionKernelError::other_with_source(
                    "failed to read code commitment from memory",
                    err,
                )
            })?
            .ok_or_else(|| {
                TransactionKernelError::other("active account code commitment was not initialized")
            })?;

        Ok(code_commitment)
    }

    /// Returns the number of storage slots initialized for the active account.
    ///
    /// # Errors
    /// Returns an error if the memory location supposed to contain the account storage slot number
    /// has not been initialized.
    fn get_num_storage_slots(&self) -> Result<u64, TransactionKernelError> {
        let num_storage_slots_felt = self
            .get_mem_value(self.ctx(), NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR)
            .ok_or(TransactionKernelError::AccountStorageSlotsNumMissing(
                NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR,
            ))?;

        Ok(num_storage_slots_felt.as_canonical_u64())
    }

    /// Returns the ID of the active note, or None if the note execution hasn't started yet or has
    /// already ended.
    ///
    /// # Errors
    /// Returns an error if the address of the active note is invalid (e.g., greater than
    /// `u32::MAX`).
    fn get_active_note_id(&self) -> Result<Option<NoteId>, TransactionKernelError> {
        // get the note address in `Felt` or return `None` if the address hasn't been accessed
        // previously.
        let note_address_felt = match self.get_mem_value(self.ctx(), ACTIVE_INPUT_NOTE_PTR) {
            Some(addr) => addr,
            None => return Ok(None),
        };
        // convert note address into u32
        let note_address: u32 = note_address_felt.as_canonical_u64().try_into().map_err(|_| {
            TransactionKernelError::other(format!(
                "failed to convert {note_address_felt} into a memory address (u32)"
            ))
        })?;
        // if `note_address` == 0 note execution has ended and there is no valid note address
        if note_address == 0 {
            Ok(None)
        } else {
            Ok(self
                .get_mem_word(self.ctx(), note_address)
                .map_err(|err| {
                    TransactionKernelError::other_with_source(
                        "failed to read note address",
                        ExecutionError::MemoryErrorNoCtx(err),
                    )
                })?
                .map(NoteId::from_raw))
        }
    }

    /// Returns the vault root at the provided pointer.
    fn get_vault_root(&self, vault_root_ptr: Felt) -> Result<Word, TransactionKernelError> {
        let vault_root_ptr: u32 = vault_root_ptr.as_canonical_u64().try_into().map_err(|_err| {
            TransactionKernelError::other(format!(
                "vault root ptr should fit into a u32, but was {vault_root_ptr}"
            ))
        })?;
        self.get_mem_word(self.ctx(), vault_root_ptr)
            .map_err(|_err| {
                TransactionKernelError::other(format!(
                    "vault root ptr {vault_root_ptr} is not word-aligned"
                ))
            })?
            .ok_or_else(|| {
                TransactionKernelError::other(format!(
                    "vault root ptr {vault_root_ptr} was not initialized"
                ))
            })
    }

    fn get_storage_slot(
        &self,
        slot_ptr: Felt,
    ) -> Result<(StorageSlotId, StorageSlotType, Word), TransactionKernelError> {
        let slot_ptr: u32 = slot_ptr.as_canonical_u64().try_into().map_err(|_err| {
            TransactionKernelError::other(format!(
                "slot ptr should fit into a u32, but was {slot_ptr}"
            ))
        })?;

        let slot_metadata = self
            .get_mem_word(self.ctx(), slot_ptr)
            .map_err(|err| {
                TransactionKernelError::other_with_source(
                    format!("misaligned slot ptr {slot_ptr}"),
                    err,
                )
            })?
            .ok_or_else(|| {
                TransactionKernelError::other(format!("slot ptr {slot_ptr} is uninitialized"))
            })?;

        let slot_value_ptr = slot_ptr + ACCT_STORAGE_SLOT_VALUE_OFFSET as u32;
        let slot_value = self
            .get_mem_word(self.ctx(), slot_value_ptr)
            .map_err(|err| {
                TransactionKernelError::other_with_source(
                    format!("misaligned slot value ptr {slot_value_ptr}"),
                    err,
                )
            })?
            .ok_or_else(|| {
                TransactionKernelError::other(format!(
                    "slot value ptr {slot_value_ptr} is uninitialized"
                ))
            })?;

        let slot_type = slot_metadata[ACCT_STORAGE_SLOT_TYPE_OFFSET as usize];
        let slot_type: u8 = slot_type.as_canonical_u64().try_into().map_err(|err| {
            TransactionKernelError::other(format!("failed to convert {slot_type} into u8: {err}"))
        })?;
        let slot_type = StorageSlotType::try_from(slot_type).map_err(|err| {
            TransactionKernelError::other_with_source(
                format!("failed to convert {slot_type} into storage slot type",),
                err,
            )
        })?;

        let suffix = slot_metadata[ACCT_STORAGE_SLOT_ID_SUFFIX_OFFSET as usize];
        let prefix = slot_metadata[ACCT_STORAGE_SLOT_ID_PREFIX_OFFSET as usize];
        let slot_id = StorageSlotId::new(suffix, prefix);

        Ok((slot_id, slot_type, slot_value))
    }

    fn read_note_recipient_info_from_adv_map(
        &self,
        recipient_digest: Word,
    ) -> Result<(NoteInputs, Word, Word), TransactionKernelError> {
        let (sn_script_hash, inputs_commitment) =
            read_double_word_from_adv_map(self, recipient_digest)?;
        let (sn_hash, script_root) = read_double_word_from_adv_map(self, sn_script_hash)?;
        let (serial_num, _) = read_double_word_from_adv_map(self, sn_hash)?;

        let inputs = self.read_note_inputs_from_adv_map(&inputs_commitment)?;

        Ok((inputs, script_root, serial_num))
    }

    /// Extracts and validates note inputs from the advice provider.
    fn read_note_inputs_from_adv_map(
        &self,
        inputs_commitment: &Word,
    ) -> Result<NoteInputs, TransactionKernelError> {
        let inputs_data = self.advice_provider().get_mapped_values(inputs_commitment);

        match inputs_data {
            None => Ok(NoteInputs::default()),
            Some(inputs) => {
                let inputs_commitment_hash = Hasher::hash_elements(inputs_commitment.as_elements());
                let num_inputs = self
                    .advice_provider()
                    .get_mapped_values(&inputs_commitment_hash)
                    .ok_or_else(|| {
                        TransactionKernelError::other(
                            "expected num_inputs to be present in advice provider",
                        )
                    })?;
                if num_inputs.len() != 1 {
                    return Err(TransactionKernelError::other(
                        "expected num_inputs advice entry to contain exactly one element",
                    ));
                }
                let num_inputs = num_inputs[0].as_canonical_u64() as usize;

                let note_inputs = NoteInputs::new(inputs[0..num_inputs].to_vec())
                    .map_err(TransactionKernelError::MalformedNoteInputs)?;

                if &note_inputs.commitment() == inputs_commitment {
                    Ok(note_inputs)
                } else {
                    Err(TransactionKernelError::InvalidNoteInputs {
                        expected: *inputs_commitment,
                        actual: note_inputs.commitment(),
                    })
                }
            },
        }
    }

    fn has_advice_map_entry(&self, key: Word) -> bool {
        self.advice_provider().get_mapped_values(&key).is_some()
    }

    fn has_merkle_path<const TREE_DEPTH: u8>(
        &self,
        root: Word,
        leaf_index: Felt,
    ) -> Result<bool, TransactionKernelError> {
        self.advice_provider()
            .has_merkle_path(root, Felt::new(u64::from(TREE_DEPTH)), leaf_index)
            .map_err(|err| {
                TransactionKernelError::other_with_source(
                    "failed to check for merkle path presence in advice provider",
                    err,
                )
            })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Reads a double word (two [`Word`]s, 8 [`Felt`]s total) from the advice map.
///
/// # Errors
/// Returns an error if the key is not present in the advice map or if the data is malformed
/// (not exactly 8 elements).
fn read_double_word_from_adv_map(
    process: &ProcessorState,
    key: Word,
) -> Result<(Word, Word), TransactionKernelError> {
    let data = process
        .advice_provider()
        .get_mapped_values(&key)
        .ok_or_else(|| TransactionKernelError::MalformedRecipientData(vec![]))?;

    if data.len() != 8 {
        return Err(TransactionKernelError::MalformedRecipientData(data.to_vec()));
    }

    let first_word = Word::new([data[0], data[1], data[2], data[3]]);
    let second_word = Word::new([data[4], data[5], data[6], data[7]]);

    Ok((first_word, second_word))
}

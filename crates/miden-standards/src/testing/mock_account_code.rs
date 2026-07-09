use miden_protocol::account::AccountCode;
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use crate::code_builder::CodeBuilder;

const MOCK_FAUCET_CODE: &str = "
    use miden::protocol::faucet

    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc mint
        exec.faucet::mint
        # => [pad(16)]
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc burn
        exec.faucet::burn
        # => [pad(16)]
    end
";

const MOCK_ACCOUNT_CODE: &str = "
    use miden::core::sys
    use miden::protocol::active_account
    use miden::protocol::native_account
    use miden::protocol::output_note
    use {NOTE_TYPE_PRIVATE} from miden::protocol::note
    use miden::standards::wallets::basic as wallet

    pub use {receive_asset} from miden::standards::wallets::basic
    pub use {move_asset_to_note} from miden::standards::wallets::basic
    pub use {create_note} from miden::standards::wallets::basic

    # Note: all account's export procedures below should be only called or dyncall'ed, so it
    # is assumed that the operand stack at the beginning of their execution is pad'ed and
    # does not have any other valuable information.

    #! Inputs:  [slot_id_prefix, slot_id_suffix, VALUE, pad(10)]
    #! Outputs: [OLD_VALUE, pad(12)]
    @account_procedure
    pub proc set_item
        exec.native_account::set_item
        # => [OLD_VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, pad(14)]
    #! Outputs: [VALUE, pad(12)]
    @account_procedure
    pub proc get_item
        exec.active_account::get_item
        # => [VALUE, pad(14)]

        # truncate the stack
        movup.4 drop movup.4 drop
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, pad(14)]
    #! Outputs: [has_slot, pad(15)]
    @account_procedure
    pub proc has_storage_slot
        exec.active_account::has_storage_slot
        # => [has_slot, pad(15)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, pad(14)]
    #! Outputs: [VALUE, pad(12)]
    @account_procedure
    pub proc get_initial_item
        exec.native_account::get_initial_item
        # => [VALUE, pad(14)]

        # truncate the stack
        movup.4 drop movup.4 drop
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, NEW_VALUE, pad(6)]
    #! Outputs: [OLD_VALUE, pad(12)]
    @account_procedure
    pub proc set_map_item
        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, pad(10)]
    #! Outputs: [VALUE, pad(12)]
    @account_procedure
    pub proc get_map_item
        exec.active_account::get_map_item
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, pad(10)]
    #! Outputs: [INIT_VALUE, pad(12)]
    @account_procedure
    pub proc get_initial_map_item
        exec.native_account::get_initial_map_item
        # => [INIT_VALUE, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [CODE_COMMITMENT, pad(12)]
    @account_procedure
    pub proc get_code_commitment
        exec.active_account::get_code_commitment
        # => [CODE_COMMITMENT, pad(16)]

        # truncate the stack
        swapw dropw
        # => [CODE_COMMITMENT, pad(12)]
    end

    # READ-ONLY GETTERS
    # ---------------------------------------------------------------------------------------------
    # These wrap the account-context-only read procedures so tests can invoke them through the
    # account via `call`.

    #! Inputs:  [pad(16)]
    #! Outputs: [INIT_COMMITMENT, pad(12)]
    @account_procedure
    pub proc get_initial_commitment
        exec.native_account::get_initial_commitment
        # => [INIT_COMMITMENT, pad(16)]

        exec.sys::truncate_stack
        # => [INIT_COMMITMENT, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [ACCOUNT_COMMITMENT, pad(12)]
    @account_procedure
    pub proc compute_commitment
        exec.active_account::compute_commitment
        # => [ACCOUNT_COMMITMENT, pad(16)]

        exec.sys::truncate_stack
        # => [ACCOUNT_COMMITMENT, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [nonce, pad(15)]
    @account_procedure
    pub proc get_nonce
        exec.active_account::get_nonce
        # => [nonce, pad(16)]

        exec.sys::truncate_stack
        # => [nonce, pad(15)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [INIT_STORAGE_COMMITMENT, pad(12)]
    @account_procedure
    pub proc get_initial_storage_commitment
        exec.native_account::get_initial_storage_commitment
        # => [INIT_STORAGE_COMMITMENT, pad(16)]

        exec.sys::truncate_stack
        # => [INIT_STORAGE_COMMITMENT, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [INIT_VAULT_ROOT, pad(12)]
    @account_procedure
    pub proc get_initial_vault_root
        exec.native_account::get_initial_vault_root
        # => [INIT_VAULT_ROOT, pad(16)]

        exec.sys::truncate_stack
        # => [INIT_VAULT_ROOT, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [VAULT_ROOT, pad(12)]
    @account_procedure
    pub proc get_vault_root
        exec.active_account::get_vault_root
        # => [VAULT_ROOT, pad(16)]

        exec.sys::truncate_stack
        # => [VAULT_ROOT, pad(12)]
    end

    #! Inputs:  [ASSET_ID, pad(12)]
    #! Outputs: [ASSET_VALUE, pad(12)]
    @account_procedure
    pub proc get_asset
        exec.active_account::get_asset
        # => [ASSET_VALUE, pad(12)]

        exec.sys::truncate_stack
        # => [ASSET_VALUE, pad(12)]
    end

    #! Inputs:  [ASSET_ID, pad(12)]
    #! Outputs: [ASSET_VALUE, pad(12)]
    @account_procedure
    pub proc get_initial_asset
        exec.native_account::get_initial_asset
        # => [ASSET_VALUE, pad(12)]

        exec.sys::truncate_stack
        # => [ASSET_VALUE, pad(12)]
    end

    #! Inputs:  [ASSET_ID, pad(12)]
    #! Outputs: [balance, pad(15)]
    @account_procedure
    pub proc get_balance
        exec.active_account::get_balance
        # => [balance, pad(15)]

        exec.sys::truncate_stack
        # => [balance, pad(15)]
    end

    #! Inputs:  [ASSET_ID, pad(12)]
    #! Outputs: [init_balance, pad(15)]
    @account_procedure
    pub proc get_initial_balance
        exec.native_account::get_initial_balance
        # => [init_balance, pad(15)]

        exec.sys::truncate_stack
        # => [init_balance, pad(15)]
    end

    #! Inputs:  [ASSET_ID, pad(12)]
    #! Outputs: [has_asset, pad(15)]
    @account_procedure
    pub proc has_non_fungible_asset
        exec.active_account::has_non_fungible_asset
        # => [has_asset, pad(15)]

        exec.sys::truncate_stack
        # => [has_asset, pad(15)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [num_procedures, pad(15)]
    @account_procedure
    pub proc get_num_procedures
        exec.active_account::get_num_procedures
        # => [num_procedures, pad(16)]

        exec.sys::truncate_stack
        # => [num_procedures, pad(15)]
    end

    #! Inputs:  [index, pad(15)]
    #! Outputs: [PROC_ROOT, pad(12)]
    @account_procedure
    pub proc get_procedure_root
        exec.active_account::get_procedure_root
        # => [PROC_ROOT, pad(15)]

        exec.sys::truncate_stack
        # => [PROC_ROOT, pad(12)]
    end

    #! Inputs:  [PROC_ROOT, pad(12)]
    #! Outputs: [is_available, pad(15)]
    @account_procedure
    pub proc has_procedure
        exec.active_account::has_procedure
        # => [is_available, pad(15)]

        exec.sys::truncate_stack
        # => [is_available, pad(15)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [DELTA_COMMITMENT, pad(12)]
    @account_procedure
    pub proc compute_delta_commitment
        exec.native_account::compute_delta_commitment
        # => [DELTA_COMMITMENT, pad(16)]

        exec.sys::truncate_stack
        # => [DELTA_COMMITMENT, pad(12)]
    end

    #! Inputs:  [PROC_ROOT, pad(12)]
    #! Outputs: [was_called, pad(15)]
    @account_procedure
    pub proc was_procedure_called
        exec.native_account::was_procedure_called
        # => [was_called, pad(15)]

        exec.sys::truncate_stack
        # => [was_called, pad(15)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [CODE_COMMITMENT, pad(12)]
    @account_procedure
    pub proc compute_storage_commitment
        exec.active_account::compute_storage_commitment
        # => [STORAGE_COMMITMENT, pad(16)]

        swapw dropw
        # => [STORAGE_COMMITMENT, pad(12)]
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [FINAL_ASSET_VALUE, pad(12)]
    @account_procedure
    pub proc add_asset
        exec.native_account::add_asset
        # => [FINAL_ASSET_VALUE, pad(12)]
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [FINAL_ASSET_VALUE, pad(12)]
    @account_procedure
    pub proc remove_asset
        exec.native_account::remove_asset
        # => [FINAL_ASSET_VALUE, pad(12)]
    end

    #! Creates a note with hardcoded default recipient/type/tag from the account context.
    #!
    #! Inputs:  [pad(16)]
    #! Outputs: [note_idx, pad(15)]
    @account_procedure
    pub proc create_default_note
        push.1.2.3.4           # = RECIPIENT
        push.NOTE_TYPE_PRIVATE # = NoteType::Private
        push.0                 # = NoteTag
        # => [tag, note_type, RECIPIENT, pad(16)]

        exec.output_note::create
        # => [note_idx, pad(16)]

        # the pushes above overflow the 16-element window; truncate so the account procedure
        # returns at most 16 elements as required by the `call` convention
        exec.sys::truncate_stack
        # => [note_idx, pad(15)]
    end

    #! Creates a default note and adds the provided asset to it from the account context.
    #!
    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc create_default_note_with_asset
        exec.create_default_note
        # => [note_idx, ASSET_ID, ASSET_VALUE, pad(7)]

        movdn.8
        # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

        exec.output_note::add_asset
        # => [pad(16)]
    end

    #! Creates a default note and moves the provided asset to it from the account context.
    #!
    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc create_default_note_with_moved_asset
        exec.create_default_note
        # => [note_idx, ASSET_ID, ASSET_VALUE, pad(7)]

        movdn.8
        # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

        call.wallet::move_asset_to_note
        # => [pad(16)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [3, pad(12)]
    @account_procedure
    pub proc account_procedure_1
        push.1.2 add

        # truncate the stack
        swap drop
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [1, pad(12)]
    @account_procedure
    pub proc account_procedure_2
        push.2.1 sub

        # truncate the stack
        swap drop
    end
";

static MOCK_FAUCET_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("mock::faucet", MOCK_FAUCET_CODE)
        .expect("mock faucet code should be valid")
        .into()
});

static MOCK_ACCOUNT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("mock::account", MOCK_ACCOUNT_CODE)
        .expect("mock account code should be valid")
        .into()
});

// MOCK ACCOUNT CODE EXT
// ================================================================================================

/// Extension trait for [`AccountCode`] to access the mock libraries.
pub trait MockAccountCodeExt {
    /// Returns the [`Library`] of the mock account under the `mock::account` namespace.
    ///
    /// This account interface wraps most account kernel APIs for testing purposes.
    fn mock_account_library() -> Library {
        MOCK_ACCOUNT_LIBRARY.clone()
    }

    /// Returns the [`Library`] of the mock faucet under the `mock::faucet` namespace.
    ///
    /// This account interface wraps most faucet kernel APIs for testing purposes.
    fn mock_faucet_library() -> Library {
        MOCK_FAUCET_LIBRARY.clone()
    }
}

impl MockAccountCodeExt for AccountCode {}

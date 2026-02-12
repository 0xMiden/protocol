use miden_protocol::account::AccountCode;
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use crate::code_builder::CodeBuilder;

const MOCK_FAUCET_CODE: &str = "
    use miden::protocol::faucet

    #! Inputs:  [ASSET, pad(12)]
    #! Outputs: [ASSET, pad(12)]
    pub proc mint
        exec.faucet::mint
        # => [ASSET, pad(12)]
    end

    #! Inputs:  [ASSET, pad(12)]
    #! Outputs: [ASSET, pad(12)]
    pub proc burn
        exec.faucet::burn
        # => [ASSET, pad(12)]
    end
";

const MOCK_ACCOUNT_CODE: &str = "
    use miden::protocol::active_account
    use miden::protocol::native_account
    use miden::protocol::tx

    pub use ::miden::standards::wallets::basic::receive_asset
    pub use ::miden::standards::wallets::basic::move_asset_to_note

    # Note: all account's export procedures below should be only called or dyncall'ed, so it
    # is assumed that the operand stack at the beginning of their execution is pad'ed and
    # does not have any other valuable information.

    #! Inputs:  [slot_id_prefix, slot_id_suffix, VALUE, pad(10)]
    #! Outputs: [OLD_VALUE, pad(12)]
    pub proc set_item
        exec.native_account::set_item
        # => [OLD_VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, pad(14)]
    #! Outputs: [VALUE, pad(12)]
    pub proc get_item
        exec.active_account::get_item
        # => [VALUE, pad(14)]

        # truncate the stack
        movup.4 drop movup.4 drop
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, pad(14)]
    #! Outputs: [VALUE, pad(12)]
    pub proc get_initial_item
        exec.active_account::get_initial_item
        # => [VALUE, pad(14)]

        # truncate the stack
        movup.4 drop movup.4 drop
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, NEW_VALUE, pad(6)]
    #! Outputs: [OLD_VALUE, pad(12)]
    pub proc set_map_item
        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, pad(10)]
    #! Outputs: [VALUE, pad(12)]
    pub proc get_map_item
        exec.active_account::get_map_item
        # => [VALUE, pad(12)]
    end

    #! Inputs:  [slot_id_prefix, slot_id_suffix, KEY, pad(10)]
    #! Outputs: [INIT_VALUE, pad(12)]
    pub proc get_initial_map_item
        exec.active_account::get_initial_map_item
        # => [INIT_VALUE, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [CODE_COMMITMENT, pad(12)]
    pub proc get_code_commitment
        exec.active_account::get_code_commitment
        # => [CODE_COMMITMENT, pad(16)]

        # truncate the stack
        swapw dropw
        # => [CODE_COMMITMENT, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [CODE_COMMITMENT, pad(12)]
    pub proc compute_storage_commitment
        exec.active_account::compute_storage_commitment
        # => [STORAGE_COMMITMENT, pad(16)]

        swapw dropw
        # => [STORAGE_COMMITMENT, pad(12)]
    end

    #! Inputs:  [ASSET, pad(12)]
    #! Outputs: [ASSET', pad(12)]
    pub proc add_asset
        exec.native_account::add_asset
        # => [ASSET', pad(12)]
    end

    #! Inputs:  [ASSET, pad(12)]
    #! Outputs: [ASSET, pad(12)]
    pub proc remove_asset
        exec.native_account::remove_asset
        # => [ASSET, pad(12)]
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [3, pad(12)]
    pub proc account_procedure_1
        push.1.2 add

        # truncate the stack
        swap drop
    end

    #! Inputs:  [pad(16)]
    #! Outputs: [1, pad(12)]
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
        .into_library()
});

static MOCK_ACCOUNT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("mock::account", MOCK_ACCOUNT_CODE)
        .expect("mock account code should be valid")
        .into_library()
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

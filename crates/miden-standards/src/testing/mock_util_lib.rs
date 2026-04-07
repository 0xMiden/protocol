use alloc::sync::Arc;

use miden_protocol::assembly::Library;
use miden_protocol::assembly::diagnostics::NamedSource;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;

use crate::StandardsLib;

const MOCK_UTIL_LIBRARY_CODE: &str = "
    use miden::protocol::output_note
    use miden::standards::wallets::basic->wallet

    #! Inputs:  []
    #! Outputs: [note_idx]
    pub proc create_default_note
        push.1.2.3.4           # = RECIPIENT
        push.2                 # = NoteType::Private
        push.0                 # = NoteTag
        # => [tag, note_type, RECIPIENT]

        exec.output_note::create
        # => [note_idx]
    end

    #! Inputs:  [ASSET_KEY, ASSET_VALUE]
    #! Outputs: []
    pub proc create_default_note_with_asset
        exec.create_default_note
        # => [note_idx, ASSET_KEY, ASSET_VALUE]

        movdn.8
        # => [ASSET_KEY, ASSET_VALUE, note_idx]

        exec.output_note::add_asset
        # => []
    end

    #! Inputs:  [ASSET_KEY, ASSET_VALUE]
    #! Outputs: []
    pub proc create_default_note_with_moved_asset
        exec.create_default_note
        # => [note_idx, ASSET_KEY, ASSET_VALUE]

        movdn.8
        # => [ASSET_KEY, ASSET_VALUE, note_idx]

        exec.move_asset_to_note
        # => []
    end

    #! Inputs:  [ASSET_KEY, ASSET_VALUE, note_idx]
    #! Outputs: []
    pub proc move_asset_to_note
        repeat.7 push.0 movdn.9 end
        # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]

        call.wallet::move_asset_to_note

        dropw dropw dropw dropw
    end
";

static MOCK_UTIL_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    Arc::unwrap_or_clone(
        TransactionKernel::assembler()
            .with_dynamic_library(StandardsLib::default())
            .expect("dynamically linking standards library should work")
            .assemble_library([NamedSource::new("mock::util", MOCK_UTIL_LIBRARY_CODE)])
            .expect("mock util library should be valid"),
    )
});

/// Returns the mock test [`Library`] under the `mock::util` namespace.
///
/// This provides convenient wrappers for testing purposes.
pub fn mock_util_library() -> Library {
    MOCK_UTIL_LIBRARY.clone()
}

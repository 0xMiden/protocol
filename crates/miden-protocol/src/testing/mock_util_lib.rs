use miden_assembly::diagnostics::NamedSource;

use crate::assembly::Library;
use crate::transaction::TransactionKernel;
use crate::utils::sync::LazyLock;

const MOCK_UTIL_LIBRARY_CODE: &str = "
    use miden::protocol::output_note

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

    #! Inputs:  [ASSET]
    #! Outputs: []
    pub proc create_default_note_with_asset
        exec.create_default_note
        # => [note_idx, ASSET]

        movdn.4
        # => [ASSET, note_idx]

        exec.output_note::add_asset
        # => []
    end
";

static MOCK_UTIL_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    TransactionKernel::assembler()
        .assemble_library([NamedSource::new("mock::util", MOCK_UTIL_LIBRARY_CODE)])
        .expect("mock util library should be valid")
});

/// Returns the mock test [`Library`] under the `mock::util` namespace.
///
/// This provides convenient wrappers for testing purposes.
pub fn mock_util_library() -> Library {
    MOCK_UTIL_LIBRARY.clone()
}

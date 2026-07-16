use alloc::sync::Arc;

use miden_protocol::account::AccountCode;
use miden_protocol::assembly::{
    DefaultSourceManager,
    Linkage,
    ModuleKind,
    ModuleParser,
    Package,
    Path,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;

use crate::StandardsLib;
use crate::testing::mock_account_code::MockAccountCodeExt;

// Note: note creation must originate from the account context. These helpers therefore delegate to
// the account procedures exposed by the mock account, which perform the actual creation.
const MOCK_UTIL_LIBRARY_CODE: &str = "
    use miden::protocol::output_note
    use {NOTE_TYPE_PRIVATE} from miden::protocol::note
    use miden::standards::wallets::basic as wallet

    #! Inputs:  []
    #! Outputs: [note_idx]
    pub proc create_default_note
        padw padw push.0.0
        push.1.2.3.4           # = RECIPIENT
        push.NOTE_TYPE_PRIVATE # = NoteType::Private
        push.0                 # = NoteTag
        # => [tag, note_type, RECIPIENT, pad(16)]

        call.::mock::account::create_note
        # => [note_idx, pad(16)]

        movdn.15 dropw dropw dropw drop drop drop
        # => [note_idx]
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE]
    #! Outputs: []
    pub proc create_default_note_with_asset
        exec.create_default_note
        # => [note_idx, ASSET_ID, ASSET_VALUE]

        movdn.8
        # => [ASSET_ID, ASSET_VALUE, note_idx]

        exec.output_note::add_asset
        # => []
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE]
    #! Outputs: []
    pub proc create_default_note_with_moved_asset
        exec.create_default_note
        # => [note_idx, ASSET_ID, ASSET_VALUE]

        movdn.8
        # => [ASSET_ID, ASSET_VALUE, note_idx]

        exec.move_asset_to_note
        # => []
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE, note_idx]
    #! Outputs: []
    pub proc move_asset_to_note
        repeat.7 push.0 movdn.9 end
        # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

        call.wallet::move_asset_to_note

        dropw dropw dropw dropw
    end
";

static MOCK_UTIL_LIBRARY: LazyLock<Package> = LazyLock::new(|| {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new("mock::util")), MOCK_UTIL_LIBRARY_CODE, source_manager.clone())
        .expect("mock util library should parse");
    let mut assembler = TransactionKernel::assembler_with_source_manager(source_manager);
    assembler
        .link_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
        .expect("dynamically linking standards library should work");
    // Link the mock account library so the helpers' delegating `mock::account::*` calls resolve.
    assembler
        .link_package(Arc::new(AccountCode::mock_account_library()), Linkage::Dynamic)
        .expect("dynamically linking mock account library should work");
    *assembler
        .assemble_library("mock-util", root, None::<&str>)
        .expect("mock util library should be valid")
});

/// Returns the mock test [`Package`] under the `mock::util` namespace.
///
/// This provides convenient wrappers for testing purposes.
pub fn mock_util_library() -> Package {
    MOCK_UTIL_LIBRARY.clone()
}

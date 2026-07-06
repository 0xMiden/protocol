use alloc::sync::Arc;

use crate::assembly::{Assembler, DefaultSourceManager, Library, ModuleKind, ModuleParser, Path};

/// Assembles a single-module test library.
pub fn assemble_test_library(name: &str, path: &str, source: &str) -> Library {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new(path)), source, source_manager.clone())
        .expect("test library source should parse");

    *Assembler::new(source_manager)
        .assemble_library(name, root, None::<&str>)
        .expect("test library source should assemble")
}

use alloc::sync::Arc;

use crate::assembly::{Assembler, DefaultSourceManager, ModuleKind, ModuleParser, Package, Path};

/// Assembles a single-module test package.
pub fn assemble_test_package(name: &str, path: &str, source: &str) -> Package {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new(path)), source, source_manager.clone())
        .expect("test package source should parse");

    *Assembler::new(source_manager)
        .assemble_library(name, root, None::<&str>)
        .expect("test package source should assemble")
}

use alloc::sync::Arc;

use crate::ProtocolLib;
use crate::assembly::{
    Assembler,
    DefaultSourceManager,
    Linkage,
    ModuleKind,
    ModuleParser,
    Package,
    Path,
};

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

/// Assembles a single-module test package that can use the `miden::protocol` library.
pub fn assemble_test_package_with_protocol(name: &str, path: &str, source: &str) -> Package {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = ModuleParser::new(Some(ModuleKind::Library))
        .parse_str(Some(Path::new(path)), source, source_manager.clone())
        .expect("test package source should parse");

    *Assembler::new(source_manager)
        .with_package(ProtocolLib::default().package(), Linkage::Dynamic)
        .expect("protocol package should link")
        .assemble_library(name, root, None::<&str>)
        .expect("test package source should assemble")
}

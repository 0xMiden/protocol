/// The errors from the MASM code of the Miden standards.
///
/// Besides asserting on failures in tests, the constants let code recognize why the execution of a
/// standards procedure failed, through [`MasmError::matches_execution_error`].
///
/// [`MasmError::matches_execution_error`]: miden_protocol::errors::MasmError::matches_execution_error
pub mod standards {
    include!(concat!(env!("OUT_DIR"), "/standards_errors.rs"));
}

mod code_builder_errors;

pub use code_builder_errors::CodeBuilderError;

/// The errors from the MASM code of the Miden standards.
#[cfg(any(feature = "testing", test))]
#[rustfmt::skip]
pub mod standards;

mod code_builder_errors;
pub use code_builder_errors::CodeBuilderError;

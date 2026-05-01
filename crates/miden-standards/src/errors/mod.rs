/// The errors from the MASM code of the Miden standards.
#[cfg(any(feature = "testing", test))]
pub mod standards {
    include!(concat!(env!("OUT_DIR"), "/standards_errors.rs"));
}

mod code_builder_errors;

pub use code_builder_errors::CodeBuilderError;

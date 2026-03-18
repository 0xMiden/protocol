/// The errors from the MASM code of the Miden standards.
#[cfg(any(feature = "testing", test))]
pub mod standards {
    include!(concat!(env!("OUT_DIR"), "/standards_errors.rs"));
}

mod code_builder_errors;
mod name_utf8_error;

pub use code_builder_errors::CodeBuilderError;
pub use name_utf8_error::NameUtf8Error;

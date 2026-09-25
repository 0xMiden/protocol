use alloc::vec::Vec;

use crate::Word;
use crate::protocol_config::KernelConfig;

impl KernelConfig {
    /// Creates a placeholder [`KernelConfig`] for a kernel
    pub fn dummy() -> Self {
        Self::new(Word::empty(), Vec::new()).expect("an empty kernel config should be valid")
    }
}

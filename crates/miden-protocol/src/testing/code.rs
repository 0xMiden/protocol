use crate::Word;
use crate::code::ProcedureRoot;

impl ProcedureRoot {
    /// Returns a procedure root whose leaf is distinct for every `value`.
    pub fn mock(value: u32) -> ProcedureRoot {
        ProcedureRoot::from_raw(Word::from([value, value, value, value]))
    }
}

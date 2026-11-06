use crate::ProtocolLib;
use crate::code::ProcedureRoot;

impl ProtocolLib {
    /// Returns the root of the procedure of the protocol library with the provided path.
    pub fn procedure_root(path: &str) -> ProcedureRoot {
        ProtocolLib::default()
            .package()
            .get_procedure_root_by_path(path)
            .map(ProcedureRoot::from_raw)
            .unwrap_or_else(|| panic!("protocol library should export {path}"))
    }
}

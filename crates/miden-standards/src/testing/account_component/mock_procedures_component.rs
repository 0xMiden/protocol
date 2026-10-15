use alloc::format;
use alloc::string::String;

use miden_protocol::account::AccountComponent;
use miden_protocol::account::component::AccountComponentMetadata;

use crate::code_builder::CodeBuilder;

// MOCK PROCEDURES COMPONENT
// ================================================================================================

/// A mock account component with a configurable number of procedures, to build account code of a
/// specific size.
pub struct MockProceduresComponent {
    num_procedures: usize,
}

impl MockProceduresComponent {
    /// Constructs a [`MockProceduresComponent`] with `num_procedures` distinct procedures.
    pub fn new(num_procedures: usize) -> Self {
        Self { num_procedures }
    }
}

impl From<MockProceduresComponent> for AccountComponent {
    fn from(mock_component: MockProceduresComponent) -> Self {
        // Each procedure pushes a distinct value, so that no two procedures share a MAST root.
        let source: String = (0..mock_component.num_procedures)
            .map(|idx| {
                format!("@account_procedure\npub proc procedure_{idx}\n push.{idx} drop\nend\n")
            })
            .collect();
        let component_code = CodeBuilder::default()
            .compile_component_code("miden::testing::mock_procedures", source)
            .expect("mock procedures code should be valid");
        let metadata = AccountComponentMetadata::new("miden::testing::mock_procedures")
            .with_description("Mock account component with a configurable number of procedures");

        AccountComponent::new(component_code, vec![], metadata)
            .expect("mock procedures component should be valid")
    }
}

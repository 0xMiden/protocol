use alloc::string::ToString;
use alloc::sync::Arc;

use miden_protocol::account::AccountComponentCode;
use miden_protocol::assembly::{
    Assembler,
    DefaultSourceManager,
    Library,
    Parse,
    ParseOptions,
    Path,
    SourceManagerSync,
};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{TransactionKernel, TransactionScript};

use crate::errors::CodeBuilderError;
use crate::standards_lib::StandardsLib;

// CODE BUILDER
// ================================================================================================

/// A builder for compiling account components, note scripts, and transaction scripts with optional
/// library dependencies.
///
/// The [`CodeBuilder`] simplifies the process of creating transaction scripts by providing:
/// - A clean API for adding multiple libraries with static or dynamic linking
/// - Automatic assembler configuration with all added libraries
/// - Debug mode support
/// - Builder pattern support for method chaining
///
/// ## Static vs Dynamic Linking
///
/// **Static Linking** (`link_static_library()` / `with_statically_linked_library()`):
/// - Use when you control and know the library code
/// - The library code is copied into the script code
/// - Best for most user-written libraries and dependencies
/// - Results in larger script size but ensures the code is always available
///
/// **Dynamic Linking** (`link_dynamic_library()` / `with_dynamically_linked_library()`):
/// - Use when making Foreign Procedure Invocation (FPI) calls
/// - The library code is available on-chain and referenced, not copied
/// - Results in smaller script size but requires the code to be available on-chain
///
/// ## Typical Workflow
///
/// 1. Create a new CodeBuilder with debug mode preference
/// 2. Add any required modules using `link_module()` or `with_linked_module()`
/// 3. Add libraries using `link_static_library()` / `link_dynamic_library()` as appropriate
/// 4. Compile your script with `compile_note_script()` or `compile_tx_script()`
///
/// Note that the compiling methods consume the CodeBuilder, so if you need to compile
/// multiple scripts with the same configuration, you should clone the builder first.
///
/// ## Builder Pattern Example
///
/// ```no_run
/// # use anyhow::Context;
/// # use miden_standards::code_builder::CodeBuilder;
/// # use miden_protocol::assembly::Library;
/// # use miden_protocol::CoreLibrary;
/// # fn example() -> anyhow::Result<()> {
/// # let module_code = "pub proc test push.1 add end";
/// # let script_code = "begin nop end";
/// # // Create sample libraries for the example
/// # let my_lib: Library = CoreLibrary::default().into(); // Convert CoreLibrary to Library
/// # let fpi_lib: Library = CoreLibrary::default().into();
/// let script = CodeBuilder::default()
///     .with_linked_module("my::module", module_code).context("failed to link module")?
///     .with_statically_linked_library(&my_lib).context("failed to link static library")?
///     .with_dynamically_linked_library(&fpi_lib).context("failed to link dynamic library")?  // For FPI calls
///     .compile_tx_script(script_code).context("failed to parse tx script")?;
/// # Ok(())
/// # }
/// ```
///
/// # Note
/// The CodeBuilder automatically includes the `miden` and `std` libraries, which
/// provide access to transaction kernel procedures. Due to being available on-chain
/// these libraries are linked dynamically and do not add to the size of built script.
#[derive(Clone)]
pub struct CodeBuilder {
    assembler: Assembler,
    source_manager: Arc<dyn SourceManagerSync>,
}

impl CodeBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new CodeBuilder.
    pub fn new() -> Self {
        Self::with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Creates a new CodeBuilder with the specified source manager.
    ///
    /// # Arguments
    /// * `source_manager` - The source manager to use with the internal `Assembler`
    pub fn with_source_manager(source_manager: Arc<dyn SourceManagerSync>) -> Self {
        let assembler = TransactionKernel::assembler_with_source_manager(source_manager.clone())
            .with_dynamic_library(StandardsLib::default())
            .expect("linking std lib should work");
        Self { assembler, source_manager }
    }

    // LIBRARY MANAGEMENT
    // --------------------------------------------------------------------------------------------

    /// Parses and links a module to the code builder.
    ///
    /// This method compiles the provided module code and adds it directly to the assembler
    /// for use in script compilation.
    ///
    /// # Arguments
    /// * `module_path` - The path identifier for the module (e.g., "my_lib::my_module")
    /// * `module_code` - The source code of the module to compile and link
    ///
    /// # Errors
    /// Returns an error if:
    /// - The module path is invalid
    /// - The module code cannot be parsed
    /// - The module cannot be assembled
    pub fn link_module(
        &mut self,
        module_path: impl AsRef<str>,
        module_code: impl Parse,
    ) -> Result<(), CodeBuilderError> {
        let mut parse_options = ParseOptions::for_library();
        parse_options.path = Some(Path::new(module_path.as_ref()).into());

        let module = module_code.parse_with_options(self.source_manager(), parse_options).map_err(
            |err| CodeBuilderError::build_error_with_report("failed to parse module code", err),
        )?;

        self.assembler.compile_and_statically_link(module).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to assemble module", err)
        })?;

        Ok(())
    }

    /// Statically links the given library.
    ///
    /// Static linking means the library code is copied into the script code.
    /// Use this for most libraries that are not available on-chain.
    ///
    /// # Arguments
    /// * `library` - The compiled library to statically link
    ///
    /// # Errors
    /// Returns an error if:
    /// - adding the library to the assembler failed
    pub fn link_static_library(&mut self, library: &Library) -> Result<(), CodeBuilderError> {
        self.assembler.link_static_library(library).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to add static library", err)
        })
    }

    /// Dynamically links a library.
    ///
    /// This is useful to dynamically link the [`Library`] of a foreign account
    /// that is invoked using foreign procedure invocation (FPI). Its code is available
    /// on-chain and so it does not have to be copied into the script code.
    ///
    /// For all other use cases not involving FPI, link the library statically.
    ///
    /// # Arguments
    /// * `library` - The compiled library to dynamically link
    ///
    /// # Errors
    /// Returns an error if the library cannot be added to the assembler
    pub fn link_dynamic_library(&mut self, library: &Library) -> Result<(), CodeBuilderError> {
        self.assembler.link_dynamic_library(library).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to add dynamic library", err)
        })
    }

    /// Builder-style method to statically link a library and return the modified builder.
    ///
    /// This enables method chaining for convenient builder patterns.
    ///
    /// # Arguments
    /// * `library` - The compiled library to statically link
    ///
    /// # Errors
    /// Returns an error if the library cannot be added to the assembler
    pub fn with_statically_linked_library(
        mut self,
        library: &Library,
    ) -> Result<Self, CodeBuilderError> {
        self.link_static_library(library)?;
        Ok(self)
    }

    /// Builder-style method to dynamically link a library and return the modified builder.
    ///
    /// This enables method chaining for convenient builder patterns.
    ///
    /// # Arguments
    /// * `library` - The compiled library to dynamically link
    ///
    /// # Errors
    /// Returns an error if the library cannot be added to the assembler
    pub fn with_dynamically_linked_library(
        mut self,
        library: impl AsRef<Library>,
    ) -> Result<Self, CodeBuilderError> {
        self.link_dynamic_library(library.as_ref())?;
        Ok(self)
    }

    /// Builder-style method to link a module and return the modified builder.
    ///
    /// This enables method chaining for convenient builder patterns.
    ///
    /// # Arguments
    /// * `module_path` - The path identifier for the module (e.g., "my_lib::my_module")
    /// * `module_code` - The source code of the module to compile and link
    ///
    /// # Errors
    /// Returns an error if the module cannot be compiled or added to the assembler
    pub fn with_linked_module(
        mut self,
        module_path: impl AsRef<str>,
        module_code: impl Parse,
    ) -> Result<Self, CodeBuilderError> {
        self.link_module(module_path, module_code)?;
        Ok(self)
    }

    // COMPILATION
    // --------------------------------------------------------------------------------------------

    /// Compiles the provided module path and MASM code into an [`AccountComponentCode`].
    /// The resulting code can be used to create account components.
    ///
    /// # Arguments
    /// * `component_path` - The path to the account code module (e.g., `my_account::my_module`)
    /// * `component_code` - The account component source code
    ///
    /// # Errors
    /// Returns an error if:
    /// - Compiling the account component code fails
    pub fn compile_component_code(
        self,
        component_path: impl AsRef<str>,
        component_code: impl Parse,
    ) -> Result<AccountComponentCode, CodeBuilderError> {
        let CodeBuilder { assembler, source_manager } = self;

        let mut parse_options = ParseOptions::for_library();
        parse_options.path = Some(Path::new(component_path.as_ref()).into());

        let module =
            component_code
                .parse_with_options(source_manager, parse_options)
                .map_err(|err| {
                    CodeBuilderError::build_error_with_report("failed to parse component code", err)
                })?;

        let library = assembler.assemble_library([module]).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to parse component code", err)
        })?;

        Ok(AccountComponentCode::from(library))
    }

    /// Compiles the provided MASM code into a [`TransactionScript`].
    ///
    /// The parsed script will have access to all modules that have been added to this builder.
    ///
    /// # Arguments
    /// * `tx_script` - The transaction script source code
    ///
    /// # Errors
    /// Returns an error if:
    /// - The transaction script compiling fails
    pub fn compile_tx_script(
        self,
        tx_script: impl Parse,
    ) -> Result<TransactionScript, CodeBuilderError> {
        let assembler = self.assembler;

        let program = assembler.assemble_program(tx_script).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to parse transaction script", err)
        })?;
        Ok(TransactionScript::new(program))
    }

    /// Compiles the provided MASM code into a [`NoteScript`].
    ///
    /// The parsed script will have access to all modules that have been added to this builder.
    ///
    /// # Arguments
    /// * `program` - The note script source code
    ///
    /// # Errors
    /// Returns an error if:
    /// - The note script compiling fails
    pub fn compile_note_script(self, program: impl Parse) -> Result<NoteScript, CodeBuilderError> {
        let assembler = self.assembler;

        let program = assembler.assemble_program(program).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to parse note script", err)
        })?;
        Ok(NoteScript::new(program))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Access the [`Assembler`]'s [`SourceManagerSync`].
    pub fn source_manager(&self) -> Arc<dyn SourceManagerSync> {
        self.source_manager.clone()
    }

    // TESTING CONVENIENCE FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a [`CodeBuilder`] with the transaction kernel as a library.
    ///
    /// This assembler is the same as [`TransactionKernel::assembler`] but additionally includes the
    /// kernel library on the namespace of `$kernel`. The `$kernel` library is added separately
    /// because even though the library (`api.masm`) and the kernel binary (`main.masm`) include
    /// this code, it is not otherwise accessible. By adding it separately, we can invoke procedures
    /// from the kernel library to test them individually.
    #[cfg(any(feature = "testing", test))]
    pub fn with_kernel_library(source_manager: Arc<dyn SourceManagerSync>) -> Self {
        let mut builder = Self::with_source_manager(source_manager);
        if let Err(err) = builder.link_dynamic_library(&TransactionKernel::library()) {
            let err_msg = err.to_string();
            if !err_msg.contains("duplicate definition found for module '::$kernel'") {
                panic!("failed to link kernel library: {err}");
            }
        }
        builder
    }

    /// Returns a [`CodeBuilder`] with the `mock::{account, faucet, util}` libraries.
    ///
    /// This assembler includes:
    /// - [`MockAccountCodeExt::mock_account_library`][account_lib],
    /// - [`MockAccountCodeExt::mock_faucet_library`][faucet_lib],
    /// - [`mock_util_library`][util_lib]
    ///
    /// [account_lib]: crate::testing::mock_account_code::MockAccountCodeExt::mock_account_library
    /// [faucet_lib]: crate::testing::mock_account_code::MockAccountCodeExt::mock_faucet_library
    /// [util_lib]: miden_protocol::testing::mock_util_lib::mock_util_library
    #[cfg(any(feature = "testing", test))]
    pub fn with_mock_libraries() -> Self {
        Self::with_mock_libraries_with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Returns the mock account and faucet libraries used in testing.
    #[cfg(any(feature = "testing", test))]
    pub fn mock_libraries() -> impl Iterator<Item = Library> {
        use miden_protocol::account::AccountCode;

        use crate::testing::mock_account_code::MockAccountCodeExt;

        vec![AccountCode::mock_account_library(), AccountCode::mock_faucet_library()].into_iter()
    }

    #[cfg(any(feature = "testing", test))]
    pub fn with_mock_libraries_with_source_manager(
        source_manager: Arc<dyn SourceManagerSync>,
    ) -> Self {
        use miden_protocol::testing::mock_util_lib::mock_util_library;

        // Start with the builder linking against the transaction kernel, protocol library and
        // standards library, and ensure the kernel library is available under `$kernel`.
        let mut builder = Self::with_kernel_library(source_manager);

        // Add mock account/faucet libs (built in debug mode) and mock util.
        for library in Self::mock_libraries() {
            builder
                .link_dynamic_library(&library)
                .expect("failed to link mock account libraries");
        }
        builder
            .link_static_library(&mock_util_library())
            .expect("failed to link mock util library");

        builder
    }
}

impl Default for CodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl From<CodeBuilder> for Assembler {
    fn from(builder: CodeBuilder) -> Self {
        builder.assembler
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use miden_protocol::assembly::diagnostics::NamedSource;

    use super::*;

    #[test]
    fn test_code_builder_new() {
        let _builder = CodeBuilder::default();
        // Test that the builder can be created successfully
    }

    #[test]
    fn test_code_builder_basic_script_compiling() -> anyhow::Result<()> {
        let builder = CodeBuilder::default();
        builder
            .compile_tx_script("begin nop end")
            .context("failed to parse basic tx script")?;
        Ok(())
    }

    #[test]
    fn test_create_library_and_create_tx_script() -> anyhow::Result<()> {
        let script_code = "
            use external_contract::counter_contract

            begin
                call.counter_contract::increment
            end
        ";

        let account_code = "
            use miden::protocol::active_account
            use miden::protocol::native_account
            use miden::core::sys

            pub proc increment
                push.0
                exec.active_account::get_item
                push.1 add
                push.0
                exec.native_account::set_item
                exec.sys::truncate_stack
            end
        ";

        let library_path = "external_contract::counter_contract";

        let mut builder_with_lib = CodeBuilder::default();
        builder_with_lib
            .link_module(library_path, account_code)
            .context("failed to link module")?;
        builder_with_lib
            .compile_tx_script(script_code)
            .context("failed to parse tx script")?;

        Ok(())
    }

    #[test]
    fn test_parse_library_and_add_to_builder() -> anyhow::Result<()> {
        let script_code = "
            use external_contract::counter_contract

            begin
                call.counter_contract::increment
            end
        ";

        let account_code = "
            use miden::protocol::active_account
            use miden::protocol::native_account
            use miden::core::sys

            pub proc increment
                push.0
                exec.active_account::get_item
                push.1 add
                push.0
                exec.native_account::set_item
                exec.sys::truncate_stack
            end
        ";

        let library_path = "external_contract::counter_contract";

        // Test single library
        let mut builder_with_lib = CodeBuilder::default();
        builder_with_lib
            .link_module(library_path, account_code)
            .context("failed to link module")?;
        builder_with_lib
            .compile_tx_script(script_code)
            .context("failed to parse tx script")?;

        // Test multiple libraries
        let mut builder_with_libs = CodeBuilder::default();
        builder_with_libs
            .link_module(library_path, account_code)
            .context("failed to link first module")?;
        builder_with_libs
            .link_module("test::lib", "pub proc test nop end")
            .context("failed to link second module")?;
        builder_with_libs
            .compile_tx_script(script_code)
            .context("failed to parse tx script with multiple libraries")?;

        Ok(())
    }

    #[test]
    fn test_builder_style_chaining() -> anyhow::Result<()> {
        let script_code = "
            use external_contract::counter_contract

            begin
                call.counter_contract::increment
            end
        ";

        let account_code = "
            use miden::protocol::active_account
            use miden::protocol::native_account
            use miden::core::sys

            pub proc increment
                push.0
                exec.active_account::get_item
                push.1 add
                push.0
                exec.native_account::set_item
                exec.sys::truncate_stack
            end
        ";

        // Test builder-style chaining with modules
        let builder = CodeBuilder::default()
            .with_linked_module("external_contract::counter_contract", account_code)
            .context("failed to link module")?;

        builder.compile_tx_script(script_code).context("failed to parse tx script")?;

        Ok(())
    }

    #[test]
    fn test_multiple_chained_modules() -> anyhow::Result<()> {
        let script_code =
            "use test::lib1 use test::lib2 begin exec.lib1::test1 exec.lib2::test2 end";

        // Test chaining multiple modules
        let builder = CodeBuilder::default()
            .with_linked_module("test::lib1", "pub proc test1 push.1 add end")
            .context("failed to link first module")?
            .with_linked_module("test::lib2", "pub proc test2 push.2 add end")
            .context("failed to link second module")?;

        builder.compile_tx_script(script_code).context("failed to parse tx script")?;

        Ok(())
    }

    #[test]
    fn test_static_and_dynamic_linking() -> anyhow::Result<()> {
        let script_code = "
            use contracts::static_contract

            begin
                call.static_contract::increment_1
            end
        ";

        let account_code_1 = "
            pub proc increment_1
                push.0 drop
            end
        ";

        let account_code_2 = "
            pub proc increment_2
                push.0 drop
            end
        ";

        // Create libraries using the assembler
        let temp_assembler = TransactionKernel::assembler();

        let static_lib = temp_assembler
            .clone()
            .assemble_library([NamedSource::new("contracts::static_contract", account_code_1)])
            .map_err(|e| anyhow::anyhow!("failed to assemble static library: {}", e))?;

        let dynamic_lib = temp_assembler
            .assemble_library([NamedSource::new("contracts::dynamic_contract", account_code_2)])
            .map_err(|e| anyhow::anyhow!("failed to assemble dynamic library: {}", e))?;

        // Test linking both static and dynamic libraries
        let builder = CodeBuilder::default()
            .with_statically_linked_library(&static_lib)
            .context("failed to link static library")?
            .with_dynamically_linked_library(&dynamic_lib)
            .context("failed to link dynamic library")?;

        builder
            .compile_tx_script(script_code)
            .context("failed to parse tx script with static and dynamic libraries")?;

        Ok(())
    }
}

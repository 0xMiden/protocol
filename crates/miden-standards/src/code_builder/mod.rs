use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::account::AccountComponentCode;
use miden_protocol::assembly::diagnostics::Report;
use miden_protocol::assembly::{
    Assembler,
    DefaultSourceManager,
    Linkage,
    Module,
    ModuleKind,
    ModuleParser,
    Package,
    Path,
    SourceFile,
    SourceManager,
    SourceManagerSync,
};
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::{TransactionKernel, TransactionScript};
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Word};

use crate::errors::CodeBuilderError;
use crate::standards_lib::StandardsLib;

const NOTE_SCRIPT_MODULE_PATH: &str = "::note_script";
const TX_SCRIPT_MODULE_PATH: &str = "::tx_script";

/// A value that can provide a compiled Miden package to the code builder.
pub trait CodeBuilderPackage {
    fn as_code_builder_package(&self) -> &Package;
}

impl<T> CodeBuilderPackage for &T
where
    T: CodeBuilderPackage + ?Sized,
{
    fn as_code_builder_package(&self) -> &Package {
        (*self).as_code_builder_package()
    }
}

impl CodeBuilderPackage for Package {
    fn as_code_builder_package(&self) -> &Package {
        self
    }
}

impl CodeBuilderPackage for Box<Package> {
    fn as_code_builder_package(&self) -> &Package {
        self
    }
}

impl CodeBuilderPackage for AccountComponentCode {
    fn as_code_builder_package(&self) -> &Package {
        self.as_package()
    }
}

/// A source value that can be compiled into a note or transaction script.
pub trait CodeBuilderScriptSource {
    /// Parses this source into a library module, assigning `default_path` as the module path
    /// when the source does not provide one.
    fn parse_script(
        self,
        default_path: &Path,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report>;
}

fn parse_script_str(
    source: impl AsRef<str>,
    default_path: &Path,
    warnings_as_errors: bool,
    source_manager: Arc<dyn SourceManager>,
) -> Result<Box<Module>, Report> {
    let mut parser = ModuleParser::new(Some(ModuleKind::Library));
    parser.set_warnings_as_errors(warnings_as_errors);
    parser.parse_str(Some(default_path), source.as_ref(), source_manager)
}

fn set_default_module_path(mut module: Box<Module>, default_path: &Path) -> Box<Module> {
    if module.path().is_empty() {
        module.set_path(default_path);
    }
    module
}

macro_rules! impl_script_source_for_str {
    ($($source:ty),* $(,)?) => {
        $(
            impl CodeBuilderScriptSource for $source {
                fn parse_script(
                    self,
                    default_path: &Path,
                    warnings_as_errors: bool,
                    source_manager: Arc<dyn SourceManager>,
                ) -> Result<Box<Module>, Report> {
                    parse_script_str(self, default_path, warnings_as_errors, source_manager)
                }
            }
        )*
    };
}

impl_script_source_for_str!(&str, &String, String, Box<str>, Cow<'_, str>);

impl CodeBuilderScriptSource for Arc<SourceFile> {
    fn parse_script(
        self,
        default_path: &Path,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        let mut parser = ModuleParser::new(Some(ModuleKind::Library));
        parser.set_warnings_as_errors(warnings_as_errors);
        parser.parse(Some(default_path), self, source_manager)
    }
}

impl CodeBuilderScriptSource for Module {
    fn parse_script(
        self,
        default_path: &Path,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(set_default_module_path(Box::new(self), default_path))
    }
}

impl CodeBuilderScriptSource for Box<Module> {
    fn parse_script(
        self,
        default_path: &Path,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(set_default_module_path(self, default_path))
    }
}

impl CodeBuilderScriptSource for Arc<Module> {
    fn parse_script(
        self,
        default_path: &Path,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(set_default_module_path(Box::new(Arc::unwrap_or_clone(self)), default_path))
    }
}

#[cfg(feature = "std")]
impl CodeBuilderScriptSource for &std::path::Path {
    fn parse_script(
        self,
        default_path: &Path,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        let mut parser = ModuleParser::new(Some(ModuleKind::Library));
        parser.set_warnings_as_errors(warnings_as_errors);
        parser.parse_file(Some(default_path), self, source_manager)
    }
}

#[cfg(feature = "std")]
impl CodeBuilderScriptSource for std::path::PathBuf {
    fn parse_script(
        self,
        default_path: &Path,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        self.as_path().parse_script(default_path, warnings_as_errors, source_manager)
    }
}

// CODE BUILDER
// ================================================================================================

/// A builder for compiling account components, note scripts, and transaction scripts with optional
/// package dependencies.
///
/// The [`CodeBuilder`] simplifies the process of creating transaction scripts by providing:
/// - A clean API for adding multiple packages with static or dynamic linking
/// - Automatic assembler configuration with all added packages
/// - Debug mode support
/// - Builder pattern support for method chaining
///
/// ## Static vs Dynamic Linking
///
/// **Static Linking** (`link_static_package()` / `with_statically_linked_package()`):
/// - Use when you control and know the package code
/// - The package code is copied into the script code
/// - Best for most user-written packages and dependencies
/// - Results in larger script size but ensures the code is always available
///
/// **Dynamic Linking** (`link_dynamic_package()` / `with_dynamically_linked_package()`):
/// - Use when making Foreign Procedure Invocation (FPI) calls
/// - The package code is available on-chain and referenced, not copied
/// - Results in smaller script size but requires the code to be available on-chain
///
/// ## Typical Workflow
///
/// 1. Create a new CodeBuilder with debug mode preference
/// 2. Add any required modules using `link_module()` or `with_linked_module()`
/// 3. Add packages using `link_static_package()` / `link_dynamic_package()` as appropriate
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
/// # use miden_standards::StandardsLib;
/// # use miden_protocol::assembly::Package;
/// # use miden_protocol::ProtocolLib;
/// # fn example() -> anyhow::Result<()> {
/// # let module_code = "pub proc test push.1 add end";
/// # let script_code = "@transaction_script pub proc main nop end";
/// # // Create sample packages for the example
/// # let my_lib: Package = StandardsLib::default().into();
/// # let fpi_lib: Package = ProtocolLib::default().into();
/// let script = CodeBuilder::default()
///     .with_linked_module("my::module", module_code).context("failed to link module")?
///     .with_statically_linked_package(&my_lib).context("failed to link static package")?
///     .with_dynamically_linked_package(&fpi_lib).context("failed to link dynamic package")?  // For FPI calls
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
    advice_map: AdviceMap,
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
        let mut assembler =
            TransactionKernel::assembler_with_source_manager(source_manager.clone());
        assembler
            .link_package(StandardsLib::default().package(), Linkage::Dynamic)
            .expect("linking std lib should work");
        Self {
            assembler,
            source_manager,
            advice_map: AdviceMap::default(),
        }
    }

    // CONFIGURATION
    // --------------------------------------------------------------------------------------------

    /// Configures the assembler to treat warning diagnostics as errors.
    ///
    /// When enabled, any warning emitted during compilation will be promoted to an error,
    /// causing the compilation to fail.
    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.assembler = self.assembler.with_warnings_as_errors(yes);
        self
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
        module_code: impl ToString,
    ) -> Result<(), CodeBuilderError> {
        let mut parser = ModuleParser::new(Some(ModuleKind::Library));
        let module = parser
            .parse_str(Some(Path::new(module_path.as_ref())), module_code, self.source_manager())
            .map_err(|err| {
                CodeBuilderError::build_error_with_report("failed to parse module code", err)
            })?;

        self.assembler.compile_and_statically_link(module).map_err(|err| {
            CodeBuilderError::build_error_with_report("failed to assemble module", err)
        })?;

        Ok(())
    }

    /// Statically links the given package.
    ///
    /// Static linking means the package code is copied into the script code.
    /// Use this for most packages that are not available on-chain.
    ///
    /// # Arguments
    /// * `package` - The compiled package to statically link
    ///
    /// # Errors
    /// Returns an error if:
    /// - adding the package to the assembler failed
    pub fn link_static_package(&mut self, package: &Package) -> Result<(), CodeBuilderError> {
        self.assembler
            .link_package(Arc::new(package.clone()), Linkage::Static)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report("failed to add static package", err)
            })
    }

    /// Dynamically links a package.
    ///
    /// This is useful to dynamically link the [`Package`] of a foreign account
    /// that is invoked using foreign procedure invocation (FPI). Its code is available
    /// on-chain and so it does not have to be copied into the script code.
    ///
    /// For all other use cases not involving FPI, link the package statically.
    ///
    /// # Arguments
    /// * `package` - The compiled package to dynamically link
    ///
    /// # Errors
    /// Returns an error if the package cannot be added to the assembler
    pub fn link_dynamic_package(&mut self, package: &Package) -> Result<(), CodeBuilderError> {
        self.assembler
            .link_package(Arc::new(package.clone()), Linkage::Dynamic)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report("failed to add dynamic package", err)
            })
    }

    /// Builder-style method to statically link a package and return the modified builder.
    ///
    /// This enables method chaining for convenient builder patterns.
    ///
    /// # Arguments
    /// * `package` - The compiled package to statically link
    ///
    /// # Errors
    /// Returns an error if the package cannot be added to the assembler
    pub fn with_statically_linked_package(
        mut self,
        package: &Package,
    ) -> Result<Self, CodeBuilderError> {
        self.link_static_package(package)?;
        Ok(self)
    }

    /// Builder-style method to dynamically link a package and return the modified builder.
    ///
    /// This enables method chaining for convenient builder patterns.
    ///
    /// # Arguments
    /// * `package` - The compiled package to dynamically link
    ///
    /// # Errors
    /// Returns an error if the package cannot be added to the assembler
    pub fn with_dynamically_linked_package(
        mut self,
        package: impl CodeBuilderPackage,
    ) -> Result<Self, CodeBuilderError> {
        self.link_dynamic_package(package.as_code_builder_package())?;
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
        module_code: impl ToString,
    ) -> Result<Self, CodeBuilderError> {
        self.link_module(module_path, module_code)?;
        Ok(self)
    }

    // ADVICE MAP MANAGEMENT
    // --------------------------------------------------------------------------------------------

    /// Adds an entry to the advice map that will be included in compiled scripts.
    ///
    /// The advice map allows passing non-deterministic inputs to the VM that can be
    /// accessed using `adv.push_mapval` instruction.
    ///
    /// # Arguments
    /// * `key` - The key for the advice map entry (a Word)
    /// * `value` - The values to associate with this key
    pub fn add_advice_map_entry(&mut self, key: Word, value: impl Into<Vec<Felt>>) {
        self.advice_map.insert(key, value.into());
    }

    /// Builder-style method to add an advice map entry.
    ///
    /// # Arguments
    /// * `key` - The key for the advice map entry (a Word)
    /// * `value` - The values to associate with this key
    pub fn with_advice_map_entry(mut self, key: Word, value: impl Into<Vec<Felt>>) -> Self {
        self.add_advice_map_entry(key, value);
        self
    }

    /// Extends the advice map with entries from another advice map.
    ///
    /// # Arguments
    /// * `advice_map` - The advice map to merge into this builder's advice map
    pub fn extend_advice_map(&mut self, advice_map: AdviceMap) {
        self.advice_map.extend(advice_map);
    }

    /// Builder-style method to extend the advice map.
    ///
    /// # Arguments
    /// * `advice_map` - The advice map to merge into this builder's advice map
    pub fn with_extended_advice_map(mut self, advice_map: AdviceMap) -> Self {
        self.extend_advice_map(advice_map);
        self
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Applies the advice map to a package if it's non-empty.
    ///
    /// This avoids cloning the MAST forest when there are no advice map entries.
    fn apply_advice_map_to_package(advice_map: AdviceMap, package: Package) -> Package {
        if advice_map.is_empty() {
            package
        } else {
            package.with_advice_map(advice_map)
        }
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
        component_code: impl ToString,
    ) -> Result<AccountComponentCode, CodeBuilderError> {
        let CodeBuilder { assembler, source_manager, advice_map } = self;

        let mut parser = ModuleParser::new(Some(ModuleKind::Library));
        let module = parser
            .parse_str(Some(Path::new(component_path.as_ref())), component_code, source_manager)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report("failed to parse component code", err)
            })?;

        let package = assembler
            .assemble_library("account-component", module, None::<Box<Module>>)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report("failed to parse component code", err)
            })?;

        Ok(AccountComponentCode::from(Self::apply_advice_map_to_package(
            advice_map, *package,
        )))
    }

    /// Compiles the provided MASM code into a [`TransactionScript`].
    ///
    /// The parsed script will have access to all modules that have been added to this builder.
    ///
    /// # Arguments
    /// - `tx_script` - the transaction script source code which is expected to have a single public
    ///   procedure marked with the @transaction_script attribute.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The transaction script compiling fails
    pub fn compile_tx_script(
        self,
        tx_script: impl CodeBuilderScriptSource,
    ) -> Result<TransactionScript, CodeBuilderError> {
        let CodeBuilder { assembler, source_manager, advice_map } = self;

        let module = tx_script
            .parse_script(
                Path::new(TX_SCRIPT_MODULE_PATH),
                assembler.warnings_as_errors(),
                source_manager,
            )
            .map_err(|err| {
                CodeBuilderError::build_error_with_report(
                    "failed to parse transaction script package",
                    err,
                )
            })?;

        let tx_script_package = assembler
            .assemble_library("transaction-script", module, None::<Box<Module>>)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report(
                    "failed to parse transaction script package",
                    err,
                )
            })?;

        let tx_script = TransactionScript::from_package(&tx_script_package).map_err(|err| {
            CodeBuilderError::build_error_with_source(
                "failed to create transaction script from package",
                err,
            )
        })?;

        Ok(tx_script.with_advice_map(advice_map))
    }

    /// Compiles the provided MASM code into a [`NoteScript`].
    ///
    /// The parsed script will have access to all modules that have been added to this builder.
    ///
    /// # Arguments
    /// - `source` - the note script source code which is expected to have a single public procedure
    ///   marked with the @note_script attribute.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The note script compiling fails
    pub fn compile_note_script(
        self,
        source: impl CodeBuilderScriptSource,
    ) -> Result<NoteScript, CodeBuilderError> {
        let CodeBuilder { assembler, source_manager, advice_map } = self;

        let module = source
            .parse_script(
                Path::new(NOTE_SCRIPT_MODULE_PATH),
                assembler.warnings_as_errors(),
                source_manager,
            )
            .map_err(|err| {
                CodeBuilderError::build_error_with_report(
                    "failed to parse note script package",
                    err,
                )
            })?;

        let note_script_package = assembler
            .assemble_library("note-script", module, None::<Box<Module>>)
            .map_err(|err| {
                CodeBuilderError::build_error_with_report(
                    "failed to parse note script package",
                    err,
                )
            })?;

        let note_script = NoteScript::from_package(&note_script_package).map_err(|err| {
            CodeBuilderError::build_error_with_source(
                "failed to create note script from package",
                err,
            )
        })?;

        Ok(note_script.with_advice_map(advice_map))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Access the [`Assembler`]'s [`SourceManagerSync`].
    pub fn source_manager(&self) -> Arc<dyn SourceManagerSync> {
        self.source_manager.clone()
    }

    // TESTING CONVENIENCE FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a [`CodeBuilder`] with the transaction kernel core package linked.
    ///
    /// This assembler is the same as [`TransactionKernel::assembler`] but additionally includes the
    /// kernel core package on the namespace of `miden::tx_kernel_core`. The `miden::tx_kernel_core`
    /// package is added separately because even though the library (`api.masm`) and the kernel
    /// binary (`main.masm`) include this code, it is not otherwise accessible. By adding it
    /// separately, we can invoke procedures from the kernel core package to test them individually.
    #[cfg(any(feature = "testing", test))]
    pub fn with_kernel_core_package(source_manager: Arc<dyn SourceManagerSync>) -> Self {
        let mut builder = Self::with_source_manager(source_manager);
        builder
            .link_dynamic_package(&TransactionKernel::core_package())
            .expect("failed to link transaction kernel core package");
        builder
    }

    /// Returns a [`CodeBuilder`] with the `mock::{account, faucet, util}` packages.
    ///
    /// This assembler includes:
    /// - [`MockAccountCodeExt::mock_account_package`][account_pkg],
    /// - [`MockAccountCodeExt::mock_faucet_package`][faucet_pkg],
    /// - [`mock_util_package`][util_pkg]
    ///
    /// [account_pkg]: crate::testing::mock_account_code::MockAccountCodeExt::mock_account_package
    /// [faucet_pkg]: crate::testing::mock_account_code::MockAccountCodeExt::mock_faucet_package
    /// [util_pkg]: crate::testing::mock_util_package::mock_util_package
    #[cfg(any(feature = "testing", test))]
    pub fn with_mock_packages() -> Self {
        Self::with_mock_packages_with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Returns the mock account and faucet packages used in testing.
    #[cfg(any(feature = "testing", test))]
    pub fn mock_packages() -> impl Iterator<Item = Package> {
        use miden_protocol::account::AccountCode;

        use crate::testing::mock_account_code::MockAccountCodeExt;

        vec![AccountCode::mock_account_package(), AccountCode::mock_faucet_package()].into_iter()
    }

    #[cfg(any(feature = "testing", test))]
    pub fn with_mock_packages_with_source_manager(
        source_manager: Arc<dyn SourceManagerSync>,
    ) -> Self {
        use crate::testing::mock_util_package::mock_util_package;

        // Start with the builder linking against the transaction kernel, protocol package and
        // standards package.
        let mut builder = Self::with_kernel_core_package(source_manager);

        // Add mock account/faucet packages (built in debug mode) and mock util.
        for package in Self::mock_packages() {
            builder
                .link_dynamic_package(&package)
                .expect("failed to link mock account packages");
        }
        builder
            .link_static_package(&mock_util_package())
            .expect("failed to link mock util package");

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
    use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;

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
            .compile_tx_script("@transaction_script pub proc main nop end")
            .context("failed to parse basic tx script")?;
        Ok(())
    }

    #[test]
    fn test_create_library_and_create_tx_script() -> anyhow::Result<()> {
        let script_code = "
            use external_contract::counter_contract

            @transaction_script
            pub proc main
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

            @transaction_script
            pub proc main
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

            @transaction_script
            pub proc main
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
        let script_code = "
            use test::lib1
            use test::lib2

            @transaction_script
            pub proc main
                exec.lib1::test1
                exec.lib2::test2
            end
        ";

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

            @transaction_script
            pub proc main
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
        let source_manager = Arc::new(DefaultSourceManager::default());
        let mut parser = ModuleParser::new(Some(ModuleKind::Library));
        let static_module = parser
            .parse_str(
                Some(Path::new("contracts::static_contract")),
                account_code_1,
                source_manager.clone(),
            )
            .map_err(|e| anyhow::anyhow!("failed to parse static package: {}", e))?;
        let dynamic_module = parser
            .parse_str(
                Some(Path::new("contracts::dynamic_contract")),
                account_code_2,
                source_manager.clone(),
            )
            .map_err(|e| anyhow::anyhow!("failed to parse dynamic package: {}", e))?;
        let temp_assembler = TransactionKernel::assembler_with_source_manager(source_manager);

        let static_lib = temp_assembler
            .clone()
            .assemble_library("static-contract", static_module, None::<&str>)
            .map_err(|e| anyhow::anyhow!("failed to assemble static package: {}", e))?;

        let dynamic_lib = temp_assembler
            .assemble_library("dynamic-contract", dynamic_module, None::<&str>)
            .map_err(|e| anyhow::anyhow!("failed to assemble dynamic package: {}", e))?;

        // Test linking both static and dynamic libraries
        let builder = CodeBuilder::default()
            .with_statically_linked_package(&static_lib)
            .context("failed to link static package")?
            .with_dynamically_linked_package(&dynamic_lib)
            .context("failed to link dynamic package")?;

        builder
            .compile_tx_script(script_code)
            .context("failed to parse tx script with static and dynamic libraries")?;

        Ok(())
    }

    #[test]
    fn test_code_builder_warnings_as_errors() {
        let assembler: Assembler = CodeBuilder::default().with_warnings_as_errors(true).into();
        assert!(assembler.warnings_as_errors());
    }

    #[test]
    fn test_code_builder_with_advice_map_entry() -> anyhow::Result<()> {
        let key = Word::from([1u32, 2, 3, 4]);
        let value = vec![Felt::new_unchecked(42), Felt::new_unchecked(43)];

        let script = CodeBuilder::default()
            .with_advice_map_entry(key, value.clone())
            .compile_tx_script("@transaction_script pub proc main nop end")
            .context("failed to compile tx script with advice map")?;

        let mast = script.mast();
        let stored_value = mast.advice_map().get(&key).expect("advice map entry should be present");
        assert_eq!(stored_value.as_ref(), value.as_slice());

        Ok(())
    }

    #[test]
    fn test_code_builder_extend_advice_map() -> anyhow::Result<()> {
        let key1 = Word::from([1u32, 0, 0, 0]);
        let key2 = Word::from([2u32, 0, 0, 0]);

        let mut advice_map = AdviceMap::default();
        advice_map.insert(key1, vec![Felt::ONE]);
        advice_map.insert(key2, vec![Felt::new_unchecked(2)]);

        let script = CodeBuilder::default()
            .with_extended_advice_map(advice_map)
            .compile_tx_script("@transaction_script pub proc main nop end")
            .context("failed to compile tx script")?;

        let mast = script.mast();
        assert!(mast.advice_map().get(&key1).is_some(), "key1 should be present");
        assert!(mast.advice_map().get(&key2).is_some(), "key2 should be present");

        Ok(())
    }

    #[test]
    fn test_code_builder_advice_map_in_note_script() -> anyhow::Result<()> {
        let key = Word::from([5u32, 6, 7, 8]);
        let value = vec![Felt::new_unchecked(100)];

        let script = CodeBuilder::default()
            .with_advice_map_entry(key, value.clone())
            .compile_note_script(DEFAULT_NOTE_SCRIPT)
            .context("failed to compile note script with advice map")?;

        let mast = script.mast();
        let stored_value = mast
            .advice_map()
            .get(&key)
            .expect("advice map entry should be present in note script");
        assert_eq!(stored_value.as_ref(), value.as_slice());

        Ok(())
    }

    #[test]
    fn test_code_builder_advice_map_in_component_code() -> anyhow::Result<()> {
        let key = Word::from([11u32, 22, 33, 44]);
        let value = vec![Felt::new_unchecked(500)];

        let component_code = CodeBuilder::default()
            .with_advice_map_entry(key, value.clone())
            .compile_component_code("test::component", "pub proc test nop end")
            .context("failed to compile component code with advice map")?;

        let mast = component_code.mast_forest();
        let stored_value = mast
            .advice_map()
            .get(&key)
            .expect("advice map entry should be present in component code");
        assert_eq!(stored_value.as_ref(), value.as_slice());

        Ok(())
    }
}

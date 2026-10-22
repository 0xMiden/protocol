use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_core_lib::CoreLibrary;

use crate::account::{AccountHeader, AccountId};
use crate::assembly::debuginfo::SourceManagerSync;
use crate::assembly::{Assembler, DefaultSourceManager, Linkage};
use crate::block::BlockNumber;
use crate::block::code_tree::{CodePatch, CodePatchCommitment};
use crate::crypto::SequentialCommit;
use crate::errors::TransactionOutputError;
use crate::protocol::ProtocolLib;
use crate::transaction::{
    RawOutputNote,
    RawOutputNotes,
    TransactionInputs,
    TransactionLogs,
    TransactionOutputs,
};
use crate::utils::sync::LazyLock;
use crate::vm::{
    AdviceInputs,
    DebugSourceNodeId,
    Package,
    PackageDebugInfo,
    Program,
    ProgramInfo,
    StackInputs,
    StackOutputs,
};
use crate::{DoubleWord, Felt, Hasher, Word};

mod procedures {
    include!(concat!(env!("OUT_DIR"), "/procedures.rs"));
}

pub mod memory;

mod advice_inputs;
mod tx_event_id;

pub use advice_inputs::TransactionAdviceInputs;
pub use tx_event_id::TransactionEventId;

// CONSTANTS
// ================================================================================================

// Initialize the transaction kernel package only once
static KERNEL_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    let kernel_package_bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/miden-tx-kernel.masp"));
    Arc::new(
        // These bytes are produced by this crate's build script and embedded in the binary.
        Package::read_from_bytes_trusted(kernel_package_bytes)
            .expect("failed to deserialize transaction kernel package"),
    )
});

// Initialize the kernel main package only once
static KERNEL_MAIN_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    let kernel_main_bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/miden-tx-kernel:main.masp"));
    Arc::new(
        // These bytes are produced by this crate's build script and embedded in the binary.
        Package::read_from_bytes_trusted(kernel_main_bytes)
            .expect("failed to deserialize transaction kernel main package"),
    )
});

// Initialize the kernel main program only once
static KERNEL_MAIN: LazyLock<Program> = LazyLock::new(|| {
    KERNEL_MAIN_PACKAGE
        .try_into_program()
        .expect("transaction kernel main package should contain a program")
});

// Initialize the transaction script executor package only once
static TX_SCRIPT_MAIN_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    let tx_script_main_bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/kernels/miden-tx-kernel:tx-script-main.masp"
    ));
    Arc::new(
        // These bytes are produced by this crate's build script and embedded in the binary.
        Package::read_from_bytes_trusted(tx_script_main_bytes)
            .expect("failed to deserialize tx script executor package"),
    )
});

// Initialize the transaction script executor program only once
static TX_SCRIPT_MAIN: LazyLock<Program> = LazyLock::new(|| {
    TX_SCRIPT_MAIN_PACKAGE
        .try_into_program()
        .expect("tx script executor package should contain a program")
});

static KERNEL_MAIN_DEBUG_INFO: LazyLock<Option<Arc<PackageDebugInfo>>> =
    LazyLock::new(|| package_debug_info(&KERNEL_MAIN_PACKAGE, "transaction kernel main"));

static TX_SCRIPT_MAIN_DEBUG_INFO: LazyLock<Option<Arc<PackageDebugInfo>>> =
    LazyLock::new(|| package_debug_info(&TX_SCRIPT_MAIN_PACKAGE, "tx script executor"));

// TRANSACTION KERNEL
// ================================================================================================

pub struct TransactionKernel;

impl TransactionKernel {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Array of kernel procedures.
    pub const PROCEDURES: &'static [Word] = &procedures::KERNEL_PROCEDURES;

    // KERNEL SOURCE CODE
    // --------------------------------------------------------------------------------------------

    /// Returns the assembled transaction kernel as a [`Package`].
    pub fn package() -> Arc<Package> {
        KERNEL_PACKAGE.clone()
    }

    /// Returns an AST of the transaction kernel executable program.
    ///
    /// # Panics
    /// Panics if the transaction kernel source is not well-formed.
    pub fn main() -> Program {
        KERNEL_MAIN.clone()
    }

    /// Returns package-owned debug information for the transaction kernel executable program.
    ///
    /// # Panics
    /// Panics if the embedded transaction kernel package contains malformed debug information.
    pub fn main_debug_info() -> Option<Arc<PackageDebugInfo>> {
        KERNEL_MAIN_DEBUG_INFO.clone()
    }

    /// Returns the source/debug occurrence for the transaction kernel executable entrypoint.
    pub fn main_entrypoint_source_node() -> Option<DebugSourceNodeId> {
        package_entrypoint_source_node(&KERNEL_MAIN_PACKAGE, KERNEL_MAIN_DEBUG_INFO.as_deref())
    }

    /// Returns an AST of the transaction script executor program.
    ///
    /// # Panics
    /// Panics if the transaction kernel source is not well-formed.
    pub fn tx_script_main() -> Program {
        TX_SCRIPT_MAIN.clone()
    }

    /// Returns package-owned debug information for the transaction script executor program.
    ///
    /// # Panics
    /// Panics if the embedded transaction script executor package contains malformed debug
    /// information.
    pub fn tx_script_main_debug_info() -> Option<Arc<PackageDebugInfo>> {
        TX_SCRIPT_MAIN_DEBUG_INFO.clone()
    }

    /// Returns the source/debug occurrence for the transaction script executor entrypoint.
    pub fn tx_script_main_entrypoint_source_node() -> Option<DebugSourceNodeId> {
        package_entrypoint_source_node(
            &TX_SCRIPT_MAIN_PACKAGE,
            TX_SCRIPT_MAIN_DEBUG_INFO.as_deref(),
        )
    }

    /// Returns [ProgramInfo] for the transaction kernel executable program.
    ///
    /// # Panics
    /// Panics if the transaction kernel source is not well-formed.
    pub fn program_info() -> ProgramInfo {
        // TODO: make static
        let program_hash = Self::main().hash();
        let kernel = Self::package()
            .to_kernel_descriptor()
            .expect("transaction kernel package should describe a valid kernel");

        ProgramInfo::new(program_hash, kernel)
    }

    /// Transforms the provided [`TransactionInputs`] into stack and advice
    /// inputs needed to execute a transaction kernel for a specific transaction.
    pub fn prepare_inputs(tx_inputs: &TransactionInputs) -> (StackInputs, TransactionAdviceInputs) {
        let account = tx_inputs.account();

        let stack_inputs = TransactionKernel::build_input_stack(
            account.id(),
            account.initial_commitment(),
            tx_inputs.input_notes().commitment(),
            tx_inputs.block_header().commitment(),
            tx_inputs.block_header().block_num(),
        );

        let tx_advice_inputs = TransactionAdviceInputs::new(tx_inputs);

        (stack_inputs, tx_advice_inputs)
    }

    // ASSEMBLER CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new Miden assembler instantiated with the transaction kernel and loaded with the
    /// core lib as well as with miden-lib.
    pub fn assembler() -> Assembler {
        Self::assembler_with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Returns a new assembler instantiated with the transaction kernel and loaded with the
    /// core lib as well as with miden-lib.
    pub fn assembler_with_source_manager(source_manager: Arc<dyn SourceManagerSync>) -> Assembler {
        #[cfg(all(any(feature = "testing", test), feature = "std"))]
        source_manager_ext::load_masm_source_files(&source_manager);

        let mut assembler = Assembler::with_kernel(source_manager, Self::package())
            .expect("failed to load transaction kernel");
        assembler
            .link_package(CoreLibrary::default().package(), Linkage::Dynamic)
            .expect("failed to load std-lib");
        assembler
            .link_package(ProtocolLib::default().package(), Linkage::Dynamic)
            .expect("failed to load miden-lib");
        assembler
    }

    // STACK INPUTS / OUTPUTS
    // --------------------------------------------------------------------------------------------

    /// Returns the stack with the public inputs required by the transaction kernel.
    ///
    /// The initial stack is defined:
    ///
    /// ```text
    /// [
    ///     BLOCK_COMMITMENT,
    ///     INITIAL_ACCOUNT_COMMITMENT,
    ///     INPUT_NOTES_COMMITMENT,
    ///     account_id_suffix, account_id_prefix, block_num
    /// ]
    /// ```
    ///
    /// Where:
    /// - BLOCK_COMMITMENT is the commitment to the reference block of the transaction.
    /// - block_num is the reference block number.
    /// - account_id_{prefix,suffix} are the prefix and suffix felts of the account that the
    ///   transaction is being executed against.
    /// - INITIAL_ACCOUNT_COMMITMENT is the account state prior to the transaction, EMPTY_WORD for
    ///   new accounts.
    /// - INPUT_NOTES_COMMITMENT, see `transaction::api::get_input_notes_commitment`.
    pub fn build_input_stack(
        account_id: AccountId,
        initial_account_commitment: Word,
        input_notes_commitment: Word,
        block_commitment: Word,
        block_num: BlockNumber,
    ) -> StackInputs {
        // Note: Must be kept in sync with the transaction's kernel prepare_transaction procedure
        let mut inputs: Vec<Felt> = Vec::with_capacity(14);
        inputs.extend_from_slice(block_commitment.as_elements());
        inputs.extend_from_slice(initial_account_commitment.as_elements());
        inputs.extend(input_notes_commitment);
        inputs.push(account_id.suffix());
        inputs.push(account_id.prefix().as_felt());
        inputs.push(Felt::from(block_num));

        StackInputs::new(&inputs).expect("number of stack inputs should be <= 16")
    }

    /// Builds the stack for expected transaction execution outputs.
    /// The transaction kernel's output stack is formed like so:
    ///
    /// ```text
    /// [
    ///     OUTPUT_NOTES_COMMITMENT,
    ///     ACCOUNT_UPDATE_COMMITMENT,
    ///     CODE_PATCH_COMMITMENT,
    ///     LOGS_EXPIRATION_COMMITMENT,
    /// ]
    /// ```
    ///
    /// Where:
    /// - OUTPUT_NOTES_COMMITMENT is a commitment to the output notes.
    /// - ACCOUNT_UPDATE_COMMITMENT is the hash of the the final account commitment and account
    ///   patch commitment.
    /// - CODE_PATCH_COMMITMENT is the commitment to the [`CodePatch`] of the transaction.
    /// - LOGS_EXPIRATION_COMMITMENT is the hash of the transaction logs commitment and the
    ///   expiration word `[expiration_block_num, 0, 0, 0]`, where expiration_block_num is the block
    ///   number at which the transaction will expire.
    pub fn build_output_stack(
        final_account_commitment: Word,
        account_patch_commitment: Word,
        output_notes_commitment: Word,
        code_patch_commitment: CodePatchCommitment,
        expiration_block_num: BlockNumber,
        logs_commitment: Word,
    ) -> StackOutputs {
        let account_update_commitment =
            Hasher::merge(&[final_account_commitment, account_patch_commitment]);
        let logs_expiration_commitment =
            Hasher::merge(&[logs_commitment, Self::expiration_word(expiration_block_num)]);

        let mut outputs: Vec<Felt> = Vec::with_capacity(Word::NUM_ELEMENTS * 4);
        outputs.extend(output_notes_commitment);
        outputs.extend(account_update_commitment);
        outputs.extend(code_patch_commitment.as_word());
        outputs.extend(logs_expiration_commitment);

        StackOutputs::new(&outputs).expect("number of stack outputs should be <= 16")
    }

    /// Extracts transaction output data from the provided stack outputs.
    ///
    /// Returns the output notes commitment, account update commitment, code patch commitment and
    /// logs expiration commitment. See [`Self::build_output_stack`] for the stack layout.
    pub fn parse_output_stack(
        stack: &StackOutputs, // FIXME TODO add an extension trait for this one
    ) -> (Word, Word, CodePatchCommitment, Word) {
        let output_notes_commitment = stack
            .get_word(TransactionOutputs::OUTPUT_NOTES_COMMITMENT_WORD_IDX)
            .expect("output_notes_commitment (first word) missing");

        let account_update_commitment = stack
            .get_word(TransactionOutputs::ACCOUNT_UPDATE_COMMITMENT_WORD_IDX)
            .expect("account_update_commitment (second word) missing");

        let code_patch_commitment = stack
            .get_word(TransactionOutputs::CODE_PATCH_COMMITMENT_WORD_IDX)
            .map(CodePatchCommitment::from_raw)
            .expect("code_patch_commitment (third word) missing");

        let logs_expiration_commitment = stack
            .get_word(TransactionOutputs::LOGS_EXPIRATION_COMMITMENT_WORD_IDX)
            .expect("logs_expiration_commitment (fourth word) missing");

        (
            output_notes_commitment,
            account_update_commitment,
            code_patch_commitment,
            logs_expiration_commitment,
        )
    }

    // TRANSACTION OUTPUT PARSER
    // --------------------------------------------------------------------------------------------

    /// Returns [TransactionOutputs] constructed from the provided output stack and advice map.
    ///
    /// See [`Self::build_output_stack`] for the layout of the output stack.
    ///
    /// The actual data describing the new account state, output notes and the expiration block
    /// number is expected to be located in the provided advice map under keys
    /// `OUTPUT_NOTES_COMMITMENT`, `ACCOUNT_UPDATE_COMMITMENT` and `LOGS_EXPIRATION_COMMITMENT`,
    /// where the final account header is located under `FINAL_ACCOUNT_COMMITMENT`.
    pub fn from_transaction_parts(
        stack: &StackOutputs,
        advice_inputs: &AdviceInputs,
        output_notes: Vec<RawOutputNote>,
        logs: TransactionLogs,
        code_patch: CodePatch,
    ) -> Result<TransactionOutputs, TransactionOutputError> {
        let (
            output_notes_commitment,
            account_update_commitment,
            code_patch_commitment,
            logs_expiration_commitment,
        ) = Self::parse_output_stack(stack);

        let (logs_commitment, expiration_block_num) =
            Self::parse_logs_expiration_commitment(logs_expiration_commitment, advice_inputs)?;

        if logs.commitment() != logs_commitment {
            return Err(TransactionOutputError::LogsCommitmentInconsistent);
        }

        // TODO(#4006): read the code patch from the advice map under CODE_PATCH_COMMITMENT once
        // the transaction kernel builds the code patch.
        if code_patch.commitment() != code_patch_commitment {
            return Err(TransactionOutputError::CodePatchCommitmentInconsistent {
                actual: code_patch.commitment(),
                expected: code_patch_commitment,
            });
        }

        let (final_account_commitment, account_patch_commitment) =
            Self::parse_account_update_commitment(account_update_commitment, advice_inputs)?;

        // parse final account state
        let final_account_data = advice_inputs
            .map()
            .get(&final_account_commitment)
            .ok_or(TransactionOutputError::FinalAccountCommitmentMissingInAdviceMap)?;

        let account = AccountHeader::try_from_elements(final_account_data)
            .map_err(TransactionOutputError::FinalAccountHeaderParseFailure)?;

        // validate output notes
        let output_notes = RawOutputNotes::new(output_notes)?;
        if output_notes_commitment != output_notes.commitment() {
            return Err(TransactionOutputError::OutputNotesCommitmentInconsistent {
                actual: output_notes.commitment(),
                expected: output_notes_commitment,
            });
        }

        Ok(TransactionOutputs::new(
            account,
            account_patch_commitment,
            output_notes,
            expiration_block_num,
            logs,
            code_patch,
        ))
    }

    /// Returns the final account commitment and account patch commitment extracted from the account
    /// update commitment.
    fn parse_account_update_commitment(
        account_update_commitment: Word,
        advice_inputs: &AdviceInputs,
    ) -> Result<(Word, Word), TransactionOutputError> {
        let account_update_data =
            advice_inputs.map().get(&account_update_commitment).ok_or_else(|| {
                TransactionOutputError::AccountUpdateCommitment(
                    "failed to find ACCOUNT_UPDATE_COMMITMENT in advice map".into(),
                )
            })?;

        let account_update = DoubleWord::try_from(account_update_data.as_ref()).map_err(|_| {
            TransactionOutputError::AccountUpdateCommitment(
                "expected account update commitment advice map entry to contain exactly 8 elements"
                    .into(),
            )
        })?;
        let (final_account_commitment, account_patch_commitment) = account_update.into_tuple();

        let computed_account_update_commitment =
            Hasher::merge(&[final_account_commitment, account_patch_commitment]);

        if computed_account_update_commitment != account_update_commitment {
            let err_message = format!(
                "transaction outputs account update commitment {account_update_commitment} but commitment computed from its advice map entries was {computed_account_update_commitment}"
            );
            return Err(TransactionOutputError::AccountUpdateCommitment(err_message.into()));
        }

        Ok((final_account_commitment, account_patch_commitment))
    }

    /// Returns the logs commitment and expiration block number extracted from the logs expiration
    /// commitment.
    fn parse_logs_expiration_commitment(
        logs_expiration_commitment: Word,
        advice_inputs: &AdviceInputs,
    ) -> Result<(Word, BlockNumber), TransactionOutputError> {
        let logs_expiration_data =
            advice_inputs.map().get(&logs_expiration_commitment).ok_or_else(|| {
                TransactionOutputError::LogsExpirationCommitment(
                    "failed to find LOGS_EXPIRATION_COMMITMENT in advice map".into(),
                )
            })?;

        let logs_expiration =
            DoubleWord::try_from(logs_expiration_data.as_ref()).map_err(|_| {
                TransactionOutputError::LogsExpirationCommitment(
                    "expected logs expiration commitment advice map entry to contain exactly 8 elements"
                        .into(),
                )
            })?;
        let (logs_commitment, expiration_word) = logs_expiration.into_tuple();

        let computed_logs_expiration_commitment =
            Hasher::merge(&[logs_commitment, expiration_word]);

        if computed_logs_expiration_commitment != logs_expiration_commitment {
            let err_message = format!(
                "transaction outputs logs expiration commitment {logs_expiration_commitment} but commitment computed from its advice map entries was {computed_logs_expiration_commitment}"
            );
            return Err(TransactionOutputError::LogsExpirationCommitment(err_message.into()));
        }

        let expiration_block_num = u32::try_from(expiration_word[0].as_canonical_u64())
            .map(BlockNumber::from)
            .map_err(|_| {
                TransactionOutputError::LogsExpirationCommitment(
                    "expiration block number should be smaller than u32::MAX".into(),
                )
            })?;

        if Self::expiration_word(expiration_block_num) != expiration_word {
            return Err(TransactionOutputError::LogsExpirationCommitment(
                "expiration word should contain zeros after the expiration block number".into(),
            ));
        }

        Ok((logs_commitment, expiration_block_num))
    }

    /// Returns the word the expiration block number is committed to in the logs expiration
    /// commitment.
    fn expiration_word(expiration_block_num: BlockNumber) -> Word {
        Word::new([Felt::from(expiration_block_num), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Computes the sequential hash of all kernel procedures.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

fn package_debug_info(package: &Package, package_name: &str) -> Option<Arc<PackageDebugInfo>> {
    package
        .debug_info()
        .unwrap_or_else(|err| panic!("failed to read {package_name} debug info: {err}"))
        .map(Arc::new)
}

fn package_entrypoint_source_node(
    package: &Package,
    debug_info: Option<&PackageDebugInfo>,
) -> Option<DebugSourceNodeId> {
    let source_node_id = package.entrypoint_source_node()?;
    debug_info?.source_node(source_node_id)?;
    Some(source_node_id)
}

#[cfg(any(feature = "testing", test))]
impl TransactionKernel {
    const KERNEL_CORE_PACKAGE_BYTES: &'static [u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/kernels/miden-tx-kernel-core.masp"));

    /// Returns the transaction kernel procedures as a [`Package`] linkable under the
    /// `miden::tx_kernel_core` namespace.
    ///
    /// Unlike [`TransactionKernel::package()`], which returns the assembled kernel itself, this
    /// package exposes the kernel procedures as a regular library so that they can be invoked
    /// individually in tests.
    pub fn core_package() -> Package {
        // These bytes are produced by this crate's build script and embedded in the binary.
        Package::read_from_bytes_trusted(Self::KERNEL_CORE_PACKAGE_BYTES)
            .expect("failed to deserialize transaction kernel core package")
    }
}

impl SequentialCommit for TransactionKernel {
    type Commitment = Word;

    /// Returns kernel procedures as vector of Felts.
    fn to_elements(&self) -> Vec<Felt> {
        Word::words_as_elements(Self::PROCEDURES).to_vec()
    }
}

#[cfg(all(any(feature = "testing", test), feature = "std"))]
pub(crate) mod source_manager_ext {
    use std::path::{Path, PathBuf};
    use std::vec::Vec;
    use std::{fs, io};

    use crate::assembly::SourceManager;
    use crate::assembly::debuginfo::SourceManagerExt;

    /// Loads all files with a .masm extension in the `asm` directory into the provided source
    /// manager.
    ///
    /// This source manager is passed to the [`super::TransactionKernel::assembler`] from which it
    /// can be passed on to the VM processor. If an error occurs, the sources can be used to provide
    /// a pointer to the failed location.
    pub fn load_masm_source_files(source_manager: &dyn SourceManager) {
        if let Err(err) = load(source_manager) {
            // Stringifying the error is not ideal (we may loose some source errors) but this
            // should never really error anyway.
            std::eprintln!("failed to load MASM sources into source manager: {err}");
        }
    }

    /// Implements the logic of the above function with error handling.
    fn load(source_manager: &dyn SourceManager) -> io::Result<()> {
        for file in get_masm_files(concat!(env!("CARGO_MANIFEST_DIR"), "/asm"))? {
            source_manager.load_file(&file).map_err(io::Error::other)?;
        }

        Ok(())
    }

    /// Returns a vector with paths to all MASM files in the specified directory and recursive
    /// directories.
    ///
    /// All non-MASM files are skipped.
    fn get_masm_files<P: AsRef<Path>>(dir_path: P) -> io::Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        match fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let entry_path = entry.path();
                            if entry_path.is_dir() {
                                files.extend(get_masm_files(entry_path)?);
                            } else if entry_path
                                .extension()
                                .map(|ext| ext == "masm")
                                .unwrap_or(false)
                            {
                                files.push(entry_path);
                            }
                        },
                        Err(e) => {
                            return Err(io::Error::other(format!(
                                "error reading directory entry: {e}",
                            )));
                        },
                    }
                }
            },
            Err(e) => {
                return Err(io::Error::other(format!("error reading directory: {e}")));
            },
        }

        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::kernel::memory::KERNEL_PROCEDURES_PTR;
    use crate::word;

    /// The root of `exec_kernel_proc`.
    ///
    /// Every kernel caller commits to this root through its `syscall` instructions, so this root
    /// must be stable.
    const EXEC_KERNEL_PROC_ROOT: Word =
        word!("0x5234d0969f1a3e08bcd099fd71220f5c354eac99ab6a750368560722c5b8b113");

    #[test]
    fn exec_kernel_proc_root_is_stable() {
        let root = TransactionKernel::package()
            .get_procedure_root_by_path("$kernel::exec_kernel_proc")
            .unwrap();

        assert_eq!(
            root, EXEC_KERNEL_PROC_ROOT,
            "exec_kernel_proc root {root} was not the expected {EXEC_KERNEL_PROC_ROOT}"
        );
    }

    /// `exec_kernel_proc` derives the procedure pointer from the procedure offset alone, which is
    /// only correct while the kernel procedures section begins at address 0.
    #[test]
    fn kernel_procedures_section_begins_at_zero() {
        assert_eq!(KERNEL_PROCEDURES_PTR, 0);
    }

    #[test]
    fn tx_kernel_exports_only_exec_kernel_proc() {
        let kernel_prog_info = TransactionKernel::program_info();
        let proc_hashes = kernel_prog_info.kernel().proc_hashes();

        assert_eq!(proc_hashes.len(), 1, "only one proc should be a syscallable export");

        assert_eq!(
            TransactionKernel::package()
                .get_procedure_root_by_path("$kernel::exec_kernel_proc")
                .unwrap(),
            proc_hashes[0],
            "only exec_kernel_proc should be a syscallable export"
        );
    }
}

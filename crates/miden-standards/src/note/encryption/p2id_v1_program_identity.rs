// Approved identity of the v1 P2ID encryption program. `encryption.rs` builds verification
// claims from it, and `build.rs` fails if the assembled program differs.

/// MAST root of the encryption program, which embeds the P2ID note script root in its note ID
/// computation.
const P2ID_V1_PROGRAM_ROOT: Word =
    word!("0x39146c4b734116418c6530bd92685253fa7ad6eb562e9b5ec38f3536dbe5cf77");

/// Kernel procedures in the v1 claim. The only entry is the transaction kernel's
/// `exec_kernel_proc`.
///
/// This executable depends on `miden-protocol`, which brings in the transaction kernel when the
/// executable is assembled. The verifier must use the resulting kernel descriptor in its claim,
/// even though the program makes no syscalls.
const P2ID_V1_KERNEL_PROCEDURES: [Word; 1] =
    [word!("0x36487e3bbe94e16c3354070026b6743f4bcda1633b3ab3289f02c691b94d1d10")];

//! Constant-parity test: the MASM constants and their Rust counterparts
//! must satisfy the DERIVED cross-language relations (felt offsets are byte offsets / 4;
//! the packed magic/version are the u32-LE reinterpretations of the big-endian wire
//! values; the error strings are byte-identical). One-sided edits fail mechanically —
//! the `masm-rust-constant-parity` obligation, closed at the constant layer.
//!
//! Parity is BIDIRECTIONAL: every constant parsed from the MASM sources (numeric, string, and
//! `word("…")` slot-name) must be covered by a parity row or a documented exemption, so a new
//! MASM-only constant fails this suite. The faucet shell modules are included by reference (the
//! encoding crate's `lib.rs` embeds only its own sources).

mod support;

use std::collections::BTreeMap;

use miden_protocol::note::NoteAttachmentScheme;
use miden_standards::note::NetworkAccountTarget;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_burn::{
    XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS,
};
use xusdc_encoding::note::xreserve_mint::{
    XUSDC_MINT_ATTESTATION_NUM_WORDS, XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME,
    XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF,
};
use xusdc_encoding::xreserve::encoding::{
    DepositIntent, DepositIntentField, DepositIntentHeader, MintIntent, ACCOUNT_ID_BYTES,
    ASSET_AMOUNT_BYTES, BYTES32_LEN, PUBKEY_FELTS,
};
/// The shipped MASM sources, read here as TEXT so the constants written in them can be compared
/// against their Rust counterparts. This is the only thing in the crate that reads MASM source: the
/// code that ships is the package the build script assembled, not these strings.
const DEPOSIT_INTENT_MASM: &str = include_str!("../asm/xreserve/deposit_intent.masm");
const MINT_INTENT_MASM: &str = include_str!("../asm/xreserve/mint_intent.masm");

/// The faucet attestation verification attestation-verify shell module source, read test-side by reference.
const ATTESTATION_VERIFY_MASM: &str = include_str!("../asm/xreserve/attestation_verify.masm");

/// The attestation mint policy module source (the ACTIVE mint policy; owns the merged attachment
/// transport + ASSERT-MATCH binding constants), read test-side by reference.
const MINT_POLICY_MASM: &str = include_str!("../asm/xreserve/mint_policy.masm");
const BURN_POLICY_MASM: &str = include_str!("../asm/xreserve/burn_policy.masm");

/// The faucet set_attester admin module source, read test-side by reference.
const ATTESTER_ADMIN_MASM: &str = include_str!("../asm/xreserve/attester_admin.masm");

/// The packed-memory primitives the DC-14 preimage writer is built from, read test-side by
/// reference. It owns the limb guard's error and one width constant; the wire layout stays with
/// `deposit_intent.masm`.
const PACKED_MEM_MASM: &str = include_str!("../asm/xreserve/packed_mem.masm");

/// Expected `word("…")` slot-name constants of the shell module (MASM const name → label), pinned
/// against the production slot names.
fn expected_deposit_intent_word_consts() -> Vec<(&'static str, &'static str)> {
    vec![(
        "DOMAIN_CONFIG_SLOT",
        XReserveFaucetExtension::domain_config_slot().as_str(),
    )]
}

/// Expected `word("…")` slot-name constant of the mint-intent module: the nonce registry the
/// replay guard reads, declared beside the nonce it keys on.
fn expected_mint_intent_word_consts() -> Vec<(&'static str, &'static str)> {
    vec![(
        "USED_NONCES_SLOT",
        XReserveFaucetExtension::used_nonces_slot().as_str(),
    )]
}

/// Expected `word("…")` slot-name constant of the set_attester admin module — the single MASM-side
/// declaration of the slot the attestation verification read path also keys; the shared name is the single Rust source.
/// (The `ATTESTER_ENABLED_MARKER` / `ATTESTER_DISABLED_MARKER` Word array literals are not
/// parity-parsed, like `NONCE_USED_MARKER`; the builder's Rust mirror of the enabled marker is
/// checked by execution in `build_seeded_attesters.rs`, where the MASM read path accepts the row
/// the builder wrote.)
fn expected_attester_admin_word_consts() -> Vec<(&'static str, &'static str)> {
    vec![(
        "XRESERVE_ATTESTERS_SLOT",
        XReserveFaucetExtension::xreserve_attesters_slot().as_str(),
    )]
}

/// The attestation verification attestation-verify shell's numeric constants: `PUBKEY_FELTS`, which
/// IS parity-asserted against the Rust codec in `masm_rust_constant_parity` below, plus the
/// signature-staging layout the ECDSA verifier's advice ABI forces — one scalar's limb width and
/// the `verify_signature` local buffer that holds the two rewritten scalars (procedure-local
/// addresses with no Rust counterpart; the width is the ECDSA scalar's, not a wire field's).
const ATTESTATION_COVERED_NUMS: &[&str] = &[
    "PUBKEY_FELTS",
    "SIGNATURE_SCALAR_LIMBS",
    "NATIVE_SCALARS_LOC",
    "NATIVE_SCALARS_FELTS",
];

/// Attestation mint-policy numeric consts: the merged transport's attachment scheme + the
/// attestation section word count are parity-asserted against the `XUsdcMintNote` factory
/// constants in `masm_rust_constant_parity` below (the constructor builds what the policy
/// verifies; the DC-5 scale is asserted the same way but is parser-owned, see
/// `SHELL_COVERED_NUMS`). The intent sub-region's word offset carries a derived relation row of
/// its own (== the attestation width on both sides). The `*_LOC` procedure-local offsets of
/// `check_policy` (including the derived transport sub-region and shared-layout field offsets)
/// and the `NONCE_USED_MARKER` Word array literal (not parity-parsed) are
/// policy-owned with no Rust counterpart, covered here.
const MINT_POLICY_COVERED_NUMS: &[&str] = &[
    "XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME",
    "XUSDC_MINT_ATTESTATION_NUM_FELTS",
    "DEPOSIT_INTENT_PTR",
    "XUSDC_MINT_ATTESTATION_NUM_WORDS",
    "MINT_INTENT_NUM_WORDS",
    "XUSDC_MINT_TRANSPORT_FIXED_WORDS",
    "ASSET_VALUE_LOC",
    "RECIPIENT_LOC",
    "TAG_LOC",
    "NOTE_TYPE_LOC",
    "HOOK_DATA_LEN_LOC",
    "AMOUNT_LOC",
    "ATTACHMENT_COMMITMENTS_LOC",
    "HASHED_NONCE_LOC",
    "PREIMAGE_LOC",
    "PREIMAGE_MAX_FELTS",
    "TRANSPORT_LOC",
    "ATTESTATION_LOC",
    "ATTESTATION_PUBKEY_LOC",
    "ATTESTATION_SIGNATURE_LOC",
    "MINT_INTENT_LOC",
    "MINT_INTENT_NONCE_LOC",
    "MINT_INTENT_RECIPIENT_PREFIX_LOC",
    "MINT_INTENT_RECIPIENT_SUFFIX_LOC",
    "MINT_INTENT_MAX_FEE_LOC",
    "MINT_INTENT_HOOK_DATA_LEN_LOC",
];

/// Constants used by the burn policy. Scheme and word count are compared with the Rust factory.
const BURN_POLICY_COVERED_NUMS: &[&str] = &[
    "XUSDC_BURN_WITHDRAWAL_ATTACHMENT_SCHEME",
    "XUSDC_BURN_WITHDRAWAL_ATTACHMENT_NUM_WORDS",
    "BURN_NOTE_NUM_ATTACHMENTS",
    "CHECK_BURN_POLICY_COMMITMENTS_LOC",
    "CHECK_BURN_POLICY_WITHDRAWAL_LOC",
];

/// Numeric-constant coverage sets (bidirectional sweep): every numeric const parsed
/// from a MASM source must appear in its file's set — extending a MASM file with a new
/// numeric constant REQUIRES a parity row here.
const MINT_INTENT_COVERED_NUMS: &[&str] = &[
    // carried-value widths: each carries a derived relation row below
    "BYTES32_PACKED_LIMBS",
    "ACCOUNT_ID_FELTS",
    // DC-14 carried felt offsets, each pinned directly against its Rust twin
    "MINT_INTENT_NONCE_FELT_OFF",
    "MINT_INTENT_LOCAL_TOKEN_FELT_OFF",
    "MINT_INTENT_LOCAL_DEPOSITOR_FELT_OFF",
    "MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF",
    "MINT_INTENT_REMOTE_RECIPIENT_SUFFIX_FELT_OFF",
    "MINT_INTENT_MAX_FEE_FELT_OFF",
    "MINT_INTENT_HOOK_DATA_LEN_FELT_OFF",
    "MINT_INTENT_FELTS",
    "MINT_INTENT_WORDS",
];

/// The DepositIntent module's constants: the DC-1 wire offsets and packed compares (each with a
/// parity row below), the right-alignment pads, the destination offsets `rebuild` derives from
/// them (their operands carry the rows, and the derivation is one MASM line against one Rust
/// line), and its `@locals` frame offsets, which have no Rust counterpart.
const DEPOSIT_INTENT_COVERED_NUMS: &[&str] = &[
    "MAGIC_FELT_OFF",
    "VERSION_FELT_OFF",
    "AMOUNT_FELT_OFF",
    "REMOTE_DOMAIN_FELT_OFF",
    "REMOTE_TOKEN_FELT_OFF",
    "REMOTE_RECIPIENT_FELT_OFF",
    "LOCAL_TOKEN_FELT_OFF",
    "LOCAL_DEPOSITOR_FELT_OFF",
    "MAX_FEE_FELT_OFF",
    "NONCE_FELT_OFF",
    "HOOK_DATA_LEN_FELT_OFF",
    "HOOK_DATA_FELT_OFF",
    "BYTES32_ACCOUNT_ID_LIMB_OFF",
    "UINT256_ASSET_AMOUNT_LIMB_OFF",
    "DEPOSIT_INTENT_MAGIC_PACKED",
    "DEPOSIT_INTENT_VERSION_PACKED",
    "DEPOSIT_INTENT_HEADER_BYTES",
    "WRITE_AMOUNT_FELT_OFF",
    "WRITE_REMOTE_TOKEN_FELT_OFF",
    "WRITE_REMOTE_RECIPIENT_FELT_OFF",
    "WRITE_MAX_FEE_FELT_OFF",
    "DEPOSIT_INTENT_PTR_LOC",
    "MINT_INTENT_PTR_LOC",
    "AMOUNT_LOC",
    "HOOK_DATA_LEN_LOC",
];

/// The packed-memory module's only numeric constant: the limb width of a u64, pinned against the
/// Rust `ASSET_AMOUNT_BYTES` / `BYTES_PER_PACKED_FELT` relation below.
const PACKED_MEM_COVERED_NUMS: &[&str] = &["U64_PACKED_LIMBS"];

/// Evaluates a MASM numeric constant expression: a decimal or hex literal, a reference to a
/// constant the same file already declared, or a `+`-chain of those. Returns `None` for anything
/// else — a `word("…")` literal, a Word imported from another module, or a cross-file reference
/// whose operand this file never declares — which leaves that constant out of the sweep exactly
/// as it was before expressions were understood at all.
///
/// Resolving expressions is what lets a DERIVED constant carry a parity row. Without it a layout
/// written as `A + B` would silently drop out of the bidirectional check, so keeping MASM readable
/// would cost coverage.
fn eval_masm_num(value: &str, known: &BTreeMap<String, u64>) -> Option<u64> {
    value
        .split('+')
        .map(|term| {
            let term = term.trim();
            match term.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => term
                    .parse::<u64>()
                    .ok()
                    .or_else(|| known.get(term).copied()),
            }
        })
        .try_fold(0u64, |acc, term| acc.checked_add(term?))
}

/// Parses `const NAME = <value>` / `pub const NAME = <value>` lines from a MASM source.
/// Returns (numeric constants, string constants, word("…") slot-name constants).
fn parse_masm_consts(
    src: &str,
) -> (
    BTreeMap<String, u64>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    let mut nums = BTreeMap::new();
    let mut strs = BTreeMap::new();
    let mut words = BTreeMap::new();
    for line in src.lines() {
        let line = line.trim();
        let rest = match line
            .strip_prefix("pub const ")
            .or_else(|| line.strip_prefix("const "))
        {
            Some(r) => r,
            None => continue,
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let (name, value) = (name.trim().to_string(), value.trim());
        if let Some(stripped) = value.strip_prefix('"') {
            if let Some(s) = stripped.strip_suffix('"') {
                strs.insert(name, s.to_string());
            }
        } else if let Some(label) = value.strip_prefix("word(\"") {
            if let Some(l) = label.strip_suffix("\")") {
                words.insert(name, l.to_string());
            }
        } else if let Some(v) = eval_masm_num(value, &nums) {
            nums.insert(name, v);
        }
    }
    (nums, strs, words)
}

fn num(nums: &BTreeMap<String, u64>, name: &str, file: &str) -> u64 {
    *nums
        .get(name)
        .unwrap_or_else(|| panic!("{file} must define const {name}"))
}

/// DC-1 relation: every MASM felt offset × 4 equals the Rust byte offset, the packed
/// magic/version equal the LE reinterpretation of the BE wire values, the header felt
/// count matches both sides, and the extra rows pin the reducer's scale bound and
/// limb base plus the merged transport's scheme / section-width / scale rows.
#[test]
fn masm_rust_constant_parity() {
    let (nums, _, _) = parse_masm_consts(DEPOSIT_INTENT_MASM);
    let (mi_nums, _, _) = parse_masm_consts(MINT_INTENT_MASM);

    let offsets: [(&str, DepositIntentField); 12] = [
        ("MAGIC_FELT_OFF", DepositIntentField::Magic),
        ("VERSION_FELT_OFF", DepositIntentField::Version),
        ("AMOUNT_FELT_OFF", DepositIntentField::Amount),
        ("REMOTE_DOMAIN_FELT_OFF", DepositIntentField::RemoteDomain),
        ("REMOTE_TOKEN_FELT_OFF", DepositIntentField::RemoteToken),
        (
            "REMOTE_RECIPIENT_FELT_OFF",
            DepositIntentField::RemoteRecipient,
        ),
        ("LOCAL_TOKEN_FELT_OFF", DepositIntentField::LocalToken),
        (
            "LOCAL_DEPOSITOR_FELT_OFF",
            DepositIntentField::LocalDepositor,
        ),
        ("MAX_FEE_FELT_OFF", DepositIntentField::MaxFee),
        ("NONCE_FELT_OFF", DepositIntentField::Nonce),
        ("HOOK_DATA_LEN_FELT_OFF", DepositIntentField::HookDataLen),
        ("HOOK_DATA_FELT_OFF", DepositIntentField::HookData),
    ];
    for (masm_name, field) in offsets {
        assert_eq!(
            num(&nums, masm_name, "deposit_intent.masm") * 4,
            field.offset() as u64,
            "DC-1 offset relation for {masm_name} (MASM felt offset x 4 == Rust byte offset)"
        );
    }

    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_MAGIC_PACKED", "deposit_intent.masm"),
        u32::from_le_bytes(DepositIntentHeader::MAGIC.to_be_bytes()) as u64,
        "packed magic must be the u32-LE reinterpretation of the BE wire magic"
    );
    assert_eq!(
        num(
            &nums,
            "DEPOSIT_INTENT_VERSION_PACKED",
            "deposit_intent.masm"
        ),
        u32::from_le_bytes(DepositIntentHeader::VERSION.to_be_bytes()) as u64,
        "packed version must be the u32-LE reinterpretation of the BE wire version"
    );
    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_HEADER_BYTES", "deposit_intent.masm"),
        DepositIntent::HEADER_SIZE as u64,
        "header byte length must match across languages"
    );
    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_HEADER_BYTES", "deposit_intent.masm"),
        DepositIntent::HEADER_NUM_FELTS as u64 * 4,
        "header byte length must be 4x the felt count (4 bytes per felt)"
    );
    // DC-14 sub-field widths. The MASM side counts packed limbs because it writes felts; the Rust
    // side counts bytes because it writes bytes. Pinning the DERIVED relation — a value sits at
    // the end of its 32-byte field, so its pad is the field minus its own width — is what keeps
    // the two writers producing the same preimage.
    let limb_relations: [(&str, usize); 3] = [
        ("BYTES32_ACCOUNT_ID_LIMB_OFF", ACCOUNT_ID_BYTES),
        ("UINT256_ASSET_AMOUNT_LIMB_OFF", ASSET_AMOUNT_BYTES),
        // a full-width bytes32 has no pad, which is the degenerate case of the same relation
        ("MAGIC_FELT_OFF", BYTES32_LEN),
    ];
    for (masm_name, value_bytes) in limb_relations {
        assert_eq!(
            num(&nums, masm_name, "deposit_intent.masm") * 4,
            (BYTES32_LEN - value_bytes) as u64,
            "DC-14 right-alignment relation for {masm_name} (pad == 32 bytes - the value's width)"
        );
    }
    let width_relations: [(&str, usize); 1] = [("BYTES32_PACKED_LIMBS", BYTES32_LEN)];
    for (masm_name, value_bytes) in width_relations {
        assert_eq!(
            num(&mi_nums, masm_name, "mint_intent.masm") * 4,
            value_bytes as u64,
            "DC-14 packed-limb width for {masm_name} (limbs x 4 == the value's byte width)"
        );
    }
    assert_eq!(
        num(&mi_nums, "ACCOUNT_ID_FELTS", "mint_intent.masm"),
        MintIntent::ACCOUNT_ID_FELTS as u64,
        "DC-14 account-id felt-pair width parity"
    );

    // the stride `store_account_id` advances by between the two u64 halves it writes. An
    // `AssetAmount` is that same u64, which is why the two constants must agree.
    let (packed_mem_nums, _, _) = parse_masm_consts(PACKED_MEM_MASM);
    assert_eq!(
        num(&packed_mem_nums, "U64_PACKED_LIMBS", "packed_mem.masm") * 4,
        ASSET_AMOUNT_BYTES as u64,
        "a u64 spans ASSET_AMOUNT_BYTES bytes of the packed wire region"
    );

    // DC-14 carried-payload offsets. Both sides derive these from the widths above, so a width
    // edit that lands on only one side moves the offsets apart and fails here.
    let payload_offsets: [(&str, usize); 8] = [
        ("MINT_INTENT_NONCE_FELT_OFF", MintIntent::NONCE_FELT_OFF),
        (
            "MINT_INTENT_LOCAL_TOKEN_FELT_OFF",
            MintIntent::LOCAL_TOKEN_FELT_OFF,
        ),
        (
            "MINT_INTENT_LOCAL_DEPOSITOR_FELT_OFF",
            MintIntent::LOCAL_DEPOSITOR_FELT_OFF,
        ),
        (
            "MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF",
            MintIntent::REMOTE_RECIPIENT_FELT_OFF,
        ),
        (
            "MINT_INTENT_REMOTE_RECIPIENT_SUFFIX_FELT_OFF",
            MintIntent::REMOTE_RECIPIENT_SUFFIX_FELT_OFF,
        ),
        ("MINT_INTENT_MAX_FEE_FELT_OFF", MintIntent::MAX_FEE_FELT_OFF),
        (
            "MINT_INTENT_HOOK_DATA_LEN_FELT_OFF",
            MintIntent::HOOK_DATA_LEN_FELT_OFF,
        ),
        ("MINT_INTENT_FELTS", MintIntent::NUM_FELTS),
    ];
    for (masm_name, rust_value) in payload_offsets {
        assert_eq!(
            num(&mi_nums, masm_name, "mint_intent.masm"),
            rust_value as u64,
            "DC-14 carried-payload offset parity for {masm_name}"
        );
    }
    // the payload block is a whole number of words, so the hookData tail that follows it starts
    // word-aligned and the attestation section's width alone fixes where the payload begins
    assert_eq!(
        num(&mi_nums, "MINT_INTENT_FELTS", "mint_intent.masm") % 4,
        0,
        "the carried payload must be a whole number of words"
    );

    // extra row: the affine-pubkey felt count
    let (att_nums, _, _) = parse_masm_consts(ATTESTATION_VERIFY_MASM);
    assert_eq!(
        num(&att_nums, "PUBKEY_FELTS", "attestation_verify.masm"),
        PUBKEY_FELTS as u64,
        "affine-pubkey felt count parity (qx||qy -> 16 u32-LE felts; ATT commitment input)"
    );

    // The DOM_PAUSER / BLK_MANAGER role symbols no longer appear in any MASM constant. They used
    // to be hard-coded felts in the custom pause and blocklist wrappers, which is what this suite
    // pinned; the wrappers are gone and the symbols now live in the account's procedure-role map,
    // written from the SAME Rust constants by `XReserveAdminAuthority`. There is nothing left to
    // keep in step across languages, so the parity rows are gone with the wrappers. The role
    // identity is pinned instead where it is now expressed: the felt encodings in
    // `builder_api.rs` (`RoleSymbol::new(DOM_PAUSER_ROLE)` / `RoleSymbol::new(BLK_MANAGER_ROLE)`)
    // and the materialized map in `w2admin_production_admin_effects.rs`.

    let (burn_nums, _, _) = parse_masm_consts(BURN_POLICY_MASM);
    assert_eq!(
        num(
            &burn_nums,
            "XUSDC_BURN_WITHDRAWAL_ATTACHMENT_SCHEME",
            "burn_policy.masm"
        ),
        XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME as u64,
        "withdrawal attachment scheme parity (MASM policy == Rust factory)"
    );
    assert_eq!(
        num(
            &burn_nums,
            "XUSDC_BURN_WITHDRAWAL_ATTACHMENT_NUM_WORDS",
            "burn_policy.masm"
        ),
        XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS as u64,
        "withdrawal attachment word-count parity (MASM policy == Rust factory)"
    );

    // The merged mint-note transport must match across languages — the XUsdcMintNote factory
    // builds exactly what the attestation policy locates (find_attachment by scheme), sub-divides
    // at the attestation offset, and reduces at (scale 0). A one-sided edit — the exact mutation
    // check (e) — fails here.
    let (policy_nums, _, _) = parse_masm_consts(MINT_POLICY_MASM);
    assert_eq!(
        num(
            &policy_nums,
            "XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME",
            "mint_policy.masm"
        ),
        XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME as u64,
        "transport attachment scheme parity (MASM policy == Rust factory)"
    );
    assert_eq!(
        num(
            &policy_nums,
            "XUSDC_MINT_ATTESTATION_NUM_WORDS",
            "mint_policy.masm"
        ),
        XUSDC_MINT_ATTESTATION_NUM_WORDS as u64,
        "attestation section word-count parity (MASM policy == Rust factory)"
    );
    // derived relation, both sides: the intent sub-region starts past the attestation. The MASM
    // constant is an expression over that same constant, so pinning the Rust derivation against
    // the MASM operand is what keeps the two layouts one layout.
    assert_eq!(
        XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF as u64,
        num(
            &policy_nums,
            "XUSDC_MINT_ATTESTATION_NUM_WORDS",
            "mint_policy.masm"
        ),
        "the carried payload's word offset must be the attestation width on BOTH sides"
    );
    // DC-5 has no cross-language parity row left: the MASM side no longer HAS a scale, because the
    // writer zero-extends the note's AssetAmount instead of verifying a witness against a staged
    // uint256. The one thing left to pin is the value of the single Rust constant, and it is
    // asserted where it is defined (`amount.rs`, `deposit_scale_exp_is_zero`) — the constant is
    // module-private, so there is no second spelling that could drift from it.
    // rider A8 (ratified): the xUSDC scheme sits at >= 4 — clear of the protocol-reserved
    // "none" value 1 and the standard values 2 (NetworkAccountTarget, carried on this very
    // note) and 3 (Pswap). Executable so a scheme regression cannot slip in one-sided.
    assert!(
        num(
            &policy_nums,
            "XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME",
            "mint_policy.masm"
        ) >= 4,
        "the transport scheme must be >= 4 (rider A8: off the reserved/standard values)"
    );
    assert_ne!(
        NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
            .expect("the xusdc scheme is valid"),
        NetworkAccountTarget::ATTACHMENT_SCHEME,
        "the transport scheme must not collide with the standard NetworkAccountTarget scheme"
    );
}

// Error-string parity has no test left. `build.rs` generates the Rust `ERR_XRESERVE_*` constants
// from the MASM that declares them, and `support::SHELL_ERR_TABLE` names those generated
// constants, so the two sides cannot disagree — comparing them would compare the MASM with itself.
// The NAME coverage still has teeth: `masm_constants_bidirectional` below fails on a MASM error
// constant that no `SHELL_ERR_TABLE` row names.

/// Bidirectional sweep: every constant parsed from every MASM source must be
/// covered by a parity row or a documented exemption — a new MASM-only constant
/// (numeric, string, or `word("…")`) fails here until it gets a row.
#[test]
fn masm_constants_bidirectional() {
    // every MASM-only string constant must be a known error (the encoding table or the faucet
    // shell table); a new one fails here until it gets a row
    let known_err = |name: &str| support::SHELL_ERR_TABLE.iter().any(|(n, _)| *n == name);
    let sources: [(&str, &str, &[&str], Vec<(&str, &str)>); 7] = [
        (
            "mint_intent.masm",
            MINT_INTENT_MASM,
            MINT_INTENT_COVERED_NUMS,
            expected_mint_intent_word_consts(),
        ),
        (
            "deposit_intent.masm",
            DEPOSIT_INTENT_MASM,
            DEPOSIT_INTENT_COVERED_NUMS,
            expected_deposit_intent_word_consts(),
        ),
        // attestation_verify: NO slot consts of its own. It imports `XRESERVE_ATTESTERS_SLOT` (and
        // the enabled marker) from the setter module rather than redeclaring them, so the two sides
        // cannot drift by construction.
        (
            "attestation_verify.masm",
            ATTESTATION_VERIFY_MASM,
            ATTESTATION_COVERED_NUMS,
            Vec::new(),
        ),
        // the attestation mint policy: declares the transport + binding errors (known
        // shell errors via SHELL_ERR_TABLE) and the covered/parity-asserted numeric consts; its
        // slot consts stay IMPORTED (USED_NONCES from mint_intent) — no word("…")
        // consts of its own (the NONCE_USED_MARKER Word array literal is not parity-parsed).
        (
            "mint_policy.masm",
            MINT_POLICY_MASM,
            MINT_POLICY_COVERED_NUMS,
            Vec::new(),
        ),
        (
            "burn_policy.masm",
            BURN_POLICY_MASM,
            BURN_POLICY_COVERED_NUMS,
            Vec::new(),
        ),
        // set_attester: pins XRESERVE_ATTESTERS_SLOT to the shared name (no numeric consts;
        // the authority-gate traps reuse the stock ADMIN-role and pause errors, not declared here).
        (
            "attester_admin.masm",
            ATTESTER_ADMIN_MASM,
            &[],
            expected_attester_admin_word_consts(),
        ),
        // packed_mem: the layout-agnostic copy/store primitives. It declares the limb guard's
        // error (a known shell error) and one width; no slot consts.
        (
            "packed_mem.masm",
            PACKED_MEM_MASM,
            PACKED_MEM_COVERED_NUMS,
            Vec::new(),
        ),
    ];
    for (file, src, covered_nums, expected_words) in sources {
        let (nums, strs, words) = parse_masm_consts(src);
        for name in nums.keys() {
            assert!(
                covered_nums.contains(&name.as_str()),
                "unmapped MASM numeric constant {name} in {file}: add a parity row or a \
                 documented exemption"
            );
        }
        for name in strs.keys() {
            assert!(
                known_err(name),
                "unmapped MASM string constant {name} in {file}: add an error parity row \
                 or a documented exemption"
            );
        }
        for name in words.keys() {
            assert!(
                expected_words.iter().any(|(n, _)| n == name),
                "unmapped MASM word(\"…\") constant {name} in {file}: add a slot-label \
                 parity row"
            );
        }
        for (name, label) in &expected_words {
            let masm_label = words
                .get(*name)
                .unwrap_or_else(|| panic!("{file} must define const {name} = word(\"…\")"));
            assert_eq!(masm_label, label, "slot-label parity for {name} in {file}");
        }
    }
}

/// Parity for the installed authority mode: the production builder's `Authority` slot must carry
/// exactly `RbacControlled` = `[RBAC_CONTROLLED, 0, 0, 0]`, which is what makes the per-procedure
/// role map load-bearing — the pause and blocklist managers resolve to their assigned roles, and
/// every other gated procedure (`set_attester`, the stock `set_min_burn_amount` / `set_max_supply`,
/// the policy setters) falls back to the administrator role. Drifting the installed mode fails
/// here: under the administrator-controlled mode the role map would be ignored and pausing would land back
/// on the administrator, the one identity Circle's model keeps it away from.
#[test]
fn rbac_controlled_authority_parity() -> anyhow::Result<()> {
    use miden_standards::account::access::Authority;

    let components = support::production_component_set(0)?;
    let authority_slot = Authority::authority_slot();
    let word = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == authority_slot)
        .map(|s| s.value())
        .ok_or_else(|| anyhow::anyhow!("the composed set must carry the Authority slot"))?;
    // the authority_config word is [mode, is_frozen, 0, 0] with RbacControlled = 2 (authority.rs);
    // compare the full word so a smuggled tail felt — or a frozen flag — cannot hide.
    assert_eq!(
        word,
        miden_protocol::Word::from([2u32, 0, 0, 0]),
        "the installed Authority must be RbacControlled: the manager procedures carry roles and \
         every other gated procedure falls back to the administrator role"
    );
    Ok(())
}

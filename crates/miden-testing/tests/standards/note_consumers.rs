//! Gates every note script on a declared consumption rule.
//!
//! A note script either restricts consumption to accounts the note commits to, or is open to any
//! consumer by design. Nothing in a script's body distinguishes the second case from a check that
//! was simply forgotten, so every `@note_script` declares its rule on a `Consumers:` line and the
//! matching Rust note declares the same rule as a [`NoteConsumers`] value. This test ties the two
//! together, and fails for a note script that declares nothing at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use miden_agglayer::AgglayerNote;
use miden_standards::note::{NoteConsumers, StandardNote};

// EXPECTED NOTE SCRIPTS
// ================================================================================================

/// Every `@note_script` in `miden-standards`, paired with the note that declares its rule.
///
/// Paths are relative to `crates/miden-standards/asm`.
const STANDARDS_NOTE_SCRIPTS: &[(&str, StandardNote)] = &[
    ("standards/notes/allowlist_config.masm", StandardNote::ALLOWLIST_CONFIG),
    ("standards/notes/blocklist_config.masm", StandardNote::BLOCKLIST_CONFIG),
    ("standards/notes/burn.masm", StandardNote::BURN),
    (
        "standards/notes/constant_fee_policy_config.masm",
        StandardNote::CONSTANT_FEE_POLICY_CONFIG,
    ),
    (
        "standards/notes/faucet_metadata_config.masm",
        StandardNote::FAUCET_METADATA_CONFIG,
    ),
    ("standards/notes/faucet_policy_config.masm", StandardNote::FAUCET_POLICY_CONFIG),
    ("standards/notes/fee_sponsorship.masm", StandardNote::FEE_SPONSORSHIP),
    (
        "standards/notes/min_burn_amount_config.masm",
        StandardNote::MIN_BURN_AMOUNT_CONFIG,
    ),
    ("standards/notes/mint/mod.masm", StandardNote::MINT),
    (
        "standards/notes/network_account_config.masm",
        StandardNote::NETWORK_ACCOUNT_CONFIG,
    ),
    ("standards/notes/owner_config.masm", StandardNote::OWNER_CONFIG),
    ("standards/notes/p2id.masm", StandardNote::P2ID),
    ("standards/notes/p2ide.masm", StandardNote::P2IDE),
    ("standards/notes/pause_config.masm", StandardNote::PAUSE_CONFIG),
    ("standards/notes/pswap.masm", StandardNote::PSWAP),
    ("standards/notes/rbac_config.masm", StandardNote::RBAC_CONFIG),
    ("standards/notes/swap.masm", StandardNote::SWAP),
    ("standards/notes/tx_fee.masm", StandardNote::TX_FEE),
];

/// Every `@note_script` in `miden-agglayer`, paired with the note that declares its rule.
///
/// Paths are relative to `crates/miden-agglayer/asm`.
const AGGLAYER_NOTE_SCRIPTS: &[(&str, AgglayerNote)] = &[
    ("agglayer/notes/b2agg.masm", AgglayerNote::B2AGG),
    ("agglayer/notes/claim.masm", AgglayerNote::CLAIM),
    ("agglayer/notes/config_agg_bridge.masm", AgglayerNote::CONFIG_AGG_BRIDGE),
    ("agglayer/notes/deregister_agg_faucet.masm", AgglayerNote::DEREGISTER_AGG_FAUCET),
    ("agglayer/notes/remove_ger.masm", AgglayerNote::REMOVE_GER),
    ("agglayer/notes/update_ger.masm", AgglayerNote::UPDATE_GER),
];

/// Note scripts that restrict consumption without calling `miden::standards::note::consumer`,
/// together with the reason they cannot.
///
/// A new entry here is a deliberate, reviewed exception; it is not a place to park a script that
/// simply has not been converted yet.
const ENFORCEMENT_EXCEPTIONS: &[(&str, &str)] = &[(
    "standards/notes/p2ide.masm",
    "the choice between the target and the reclaimer is a branch rather than a single assertion: \
     the consuming account is compared against the target to pick the path, and the reclaim path \
     asserts it against the reclaimer (see `reclaim_note`)",
)];

/// The procedure prefix a note script uses to enforce a declared rule.
const ENFORCEMENT_PREFIX: &str = "exec.consumer::";

// TESTS
// ================================================================================================

/// Every note script on disk is accounted for by the tables above, so a new one cannot be added
/// without a note declaring who may consume it.
#[test]
fn every_note_script_is_declared() {
    for (asm_dir, declared) in [
        (
            standards_asm_dir(),
            declared_paths(&standards_asm_dir(), STANDARDS_NOTE_SCRIPTS),
        ),
        (agglayer_asm_dir(), declared_paths(&agglayer_asm_dir(), AGGLAYER_NOTE_SCRIPTS)),
    ] {
        let found = find_note_scripts(&asm_dir);

        let undeclared: Vec<_> = found.iter().filter(|path| !declared.contains(path)).collect();
        assert!(
            undeclared.is_empty(),
            "note scripts are not declared in the tables of this test, so nothing states who may \
             consume them: {undeclared:#?}",
        );

        let missing: Vec<_> = declared.iter().filter(|path| !found.contains(path)).collect();
        assert!(missing.is_empty(), "declared note scripts no longer exist: {missing:#?}");
    }
}

/// The rule a note script states matches the rule its note declares, and an unrestricted note gives
/// a reason on both sides.
#[test]
fn declared_consumers_match_the_note_scripts() {
    let mut cases: Vec<(PathBuf, &'static str, NoteConsumers)> = Vec::new();
    for (path, note) in STANDARDS_NOTE_SCRIPTS {
        cases.push((standards_asm_dir().join(path), note.name(), note.consumers()));
    }
    for (path, note) in AGGLAYER_NOTE_SCRIPTS {
        cases.push((agglayer_asm_dir().join(path), note.name(), note.consumers()));
    }

    for (path, name, consumers) in cases {
        let source = std::fs::read_to_string(&path).unwrap();
        let declaration = parse_declaration(&source).unwrap_or_else(|| {
            panic!(
                "the {name} note script has no `Consumers:` line in the doc comment of its \
                 `@note_script` procedure, so it does not state who may consume the note: {}",
                path.display()
            )
        });

        assert_eq!(
            declaration.class,
            consumers.name(),
            "the {name} note script states `{}` but the note declares `{}`",
            declaration.class,
            consumers.name(),
        );

        if let NoteConsumers::Unrestricted { rationale } = consumers {
            assert!(
                !rationale.trim().is_empty(),
                "the {name} note is open to any consumer without saying why",
            );
            assert!(
                declaration.rationale.is_some_and(|reason| !reason.trim().is_empty()),
                "the {name} note script is open to any consumer without saying why",
            );
        }
    }
}

/// Every note script that restricts consumption enforces it through the shared
/// `miden::standards::note::consumer` procedures, or is a listed exception.
#[test]
fn restricted_note_scripts_enforce_their_rule() {
    let mut cases: Vec<(PathBuf, &'static str, &'static str, NoteConsumers)> = Vec::new();
    for (path, note) in STANDARDS_NOTE_SCRIPTS {
        cases.push((standards_asm_dir().join(path), path, note.name(), note.consumers()));
    }
    for (path, note) in AGGLAYER_NOTE_SCRIPTS {
        cases.push((agglayer_asm_dir().join(path), path, note.name(), note.consumers()));
    }

    for (path, relative_path, name, consumers) in cases {
        let exception = ENFORCEMENT_EXCEPTIONS.iter().find(|(script, _)| *script == relative_path);
        let enforces = module_source(&path).contains(ENFORCEMENT_PREFIX);

        match (consumers.is_restricted(), exception) {
            (true, None) => assert!(
                enforces,
                "the {name} note script restricts consumption but never calls \
                 `{ENFORCEMENT_PREFIX}*`, so the restriction is not enforced: {}",
                path.display()
            ),
            (true, Some(_)) => assert!(
                !enforces,
                "the {name} note script is listed as unable to use `{ENFORCEMENT_PREFIX}*` but \
                 calls it; drop it from ENFORCEMENT_EXCEPTIONS: {}",
                path.display()
            ),
            (false, Some(_)) => panic!(
                "the {name} note is open to any consumer, so it does not belong in \
                 ENFORCEMENT_EXCEPTIONS"
            ),
            (false, None) => {},
        }
    }
}

// HELPERS
// ================================================================================================

/// A `Consumers:` declaration parsed from a note script.
struct Declaration {
    /// The rule's name, with any parenthetical naming the mechanism removed.
    class: String,
    /// The reason given after the rule's name, if any.
    rationale: Option<String>,
}

fn standards_asm_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../miden-standards/asm")
}

fn agglayer_asm_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../miden-agglayer/asm")
}

/// Returns the paths of the note scripts declared in `table`.
fn declared_paths<T>(asm_dir: &Path, table: &[(&str, T)]) -> Vec<PathBuf> {
    let paths: Vec<_> = table.iter().map(|(path, _)| asm_dir.join(path)).collect();
    let unique: BTreeMap<_, _> = paths.iter().map(|path| (path, ())).collect();
    assert_eq!(unique.len(), paths.len(), "a note script is declared twice");
    paths
}

/// Returns the paths of every MASM file under `asm_dir` that defines a note script.
fn find_note_scripts(asm_dir: &Path) -> Vec<PathBuf> {
    let mut scripts = Vec::new();
    let mut dirs = vec![asm_dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "masm")
                && defines_note_script(&path)
            {
                scripts.push(path);
            }
        }
    }
    scripts
}

/// Returns whether the MASM file at `path` defines a note script, i.e. carries the `@note_script`
/// attribute rather than merely mentioning it in a doc comment.
fn defines_note_script(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .any(|line| line.trim() == "@note_script")
}

/// Returns the source of the note script's module: the file itself, plus its siblings when the note
/// script is a `mod.masm` whose submodules make up the script.
fn module_source(path: &Path) -> String {
    let source = std::fs::read_to_string(path).unwrap();
    if path.file_name().is_none_or(|name| name != "mod.masm") {
        return source;
    }

    let mut sources = vec![source];
    for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
        let sibling = entry.unwrap().path();
        if sibling != path && sibling.extension().is_some_and(|ext| ext == "masm") {
            sources.push(std::fs::read_to_string(&sibling).unwrap());
        }
    }
    sources.join("\n")
}

/// Parses the `Consumers:` declaration from the doc comment of the file's note script procedure.
fn parse_declaration(source: &str) -> Option<Declaration> {
    let lines: Vec<_> = source.lines().collect();
    let script = lines.iter().position(|line| line.trim() == "@note_script")?;

    let mut doc_start = script;
    while doc_start > 0 && lines[doc_start - 1].starts_with("#!") {
        doc_start -= 1;
    }

    let doc = &lines[doc_start..script];
    let start = doc.iter().position(|line| line.starts_with("#! Consumers:"))?;
    let declaration = doc[start..]
        .iter()
        .take_while(|line| **line == doc[start] || line.starts_with("#!   "))
        .map(|line| line.trim_start_matches("#!").trim())
        .collect::<Vec<_>>()
        .join(" ");
    let declaration = declaration.strip_prefix("Consumers:")?.trim();

    let (class, rationale) = match declaration.split_once(" - ") {
        Some((class, rationale)) => (class, Some(rationale.trim().to_string())),
        None => (declaration, None),
    };
    let class = class.split(" (").next()?.trim().to_string();

    Some(Declaration { class, rationale })
}

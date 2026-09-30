//! The hygiene tripwire's comment extractors: the text a reader sees, and nothing a compiler
//! reads as code.
//!
//! MASM, TOML, and Rust each need their own scan, because each has its own string forms and a
//! banned token inside one of those is CODE — an assert message or a test probe asserted on byte
//! for byte. A `#[path]` module of `comment_hygiene_tripwire.rs`, split out to keep every file
//! inside the governing Rust line ceiling.

use std::fs;
use std::path::{Path, PathBuf};

/// Extracts `(line_number, comment_text)` from MASM source: everything after a `#` that sits
/// outside a double-quoted string literal.
///
/// MASM has only double-quoted strings and no multi-line literal, so string state resets per line.
pub fn masm_comments(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let mut in_string = false;
        let mut prev_escape = false;
        for (i, c) in line.char_indices() {
            match c {
                '\\' if in_string && !prev_escape => {
                    prev_escape = true;
                    continue;
                }
                '"' if !prev_escape => in_string = !in_string,
                '#' if !in_string => {
                    out.push((n + 1, line[i..].to_string()));
                    break;
                }
                _ => {}
            }
            prev_escape = false;
        }
    }
    out
}

/// Extracts `(line_number, comment_text)` from TOML source: everything after a `#` that sits
/// outside a string value.
///
/// TOML has four string forms and all four are code, so none of them may be read as a comment:
/// basic `"..."` (backslash escapes honored), literal `'...'` (no escapes at all — a backslash is
/// an ordinary character), and the multi-line `"""..."""` / `'''...'''` forms, which can carry a
/// `#` across many lines. String state therefore persists across lines rather than resetting at
/// each newline: a `#` inside a multi-line value is part of the value, not a comment.
pub fn toml_comments(src: &str) -> Vec<(usize, String)> {
    #[derive(PartialEq)]
    enum In {
        Code,
        Basic,
        Literal,
        MultiBasic,
        MultiLiteral,
    }
    let mut out = Vec::new();
    let mut state = In::Code;
    for (n, line) in src.lines().enumerate() {
        let b = line.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            match state {
                In::Code => {
                    if b[i..].starts_with(b"\"\"\"") {
                        state = In::MultiBasic;
                        i += 3;
                    } else if b[i..].starts_with(b"'''") {
                        state = In::MultiLiteral;
                        i += 3;
                    } else if b[i] == b'"' {
                        state = In::Basic;
                        i += 1;
                    } else if b[i] == b'\'' {
                        state = In::Literal;
                        i += 1;
                    } else if b[i] == b'#' {
                        out.push((n + 1, line[i..].to_string()));
                        break;
                    } else {
                        i += 1;
                    }
                }
                // a backslash escapes the next byte only in the two BASIC forms.
                In::Basic => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'"' {
                        state = In::Code;
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
                In::Literal => {
                    if b[i] == b'\'' {
                        state = In::Code;
                    }
                    i += 1;
                }
                In::MultiBasic => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i..].starts_with(b"\"\"\"") {
                        state = In::Code;
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                In::MultiLiteral => {
                    if b[i..].starts_with(b"'''") {
                        state = In::Code;
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        // a single-line string never continues onto the next line in TOML.
        if state == In::Basic || state == In::Literal {
            state = In::Code;
        }
    }
    out
}

/// Extracts `(line_number, comment_text)` from Rust source: `//`-family line comments and
/// `/* */` block comments (nesting honored), skipping the contents of string literals,
/// raw string literals, char literals, and lifetimes.
pub fn rust_comments(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(src.len(), |e| i + e);
                out.push((line, src[i..end].to_string()));
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let start_line = line;
                let mut depth = 1usize;
                let mut j = i + 2;
                while j < b.len() && depth > 0 {
                    if b[j] == b'\n' {
                        line += 1;
                        j += 1;
                    } else if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                out.push((start_line, src[i..j].to_string()));
                i = j;
            }
            b'r' if matches!(b.get(i + 1), Some(&b'"') | Some(&b'#')) => {
                // possible raw string literal r"..." / r#"..."# (also br"...").
                let mut hashes = 0usize;
                let mut j = i + 1;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    j += 1;
                    let mut closer = vec![b'"'];
                    closer.extend(std::iter::repeat_n(b'#', hashes));
                    while j < b.len() {
                        if b[j] == b'\n' {
                            line += 1;
                        }
                        if b[j..].starts_with(&closer) {
                            j += closer.len();
                            break;
                        }
                        j += 1;
                    }
                    i = j;
                } else {
                    i += 1; // a plain identifier starting with r
                }
            }
            b'"' => {
                // string literal: skip to the unescaped closing quote.
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        // an escape may be a line continuation (`\` then a newline), so the
                        // escaped byte still has to be counted or every later line number drifts.
                        b'\\' => {
                            if b.get(j + 1) == Some(&b'\n') {
                                line += 1;
                            }
                            j += 2;
                        }
                        b'\n' => {
                            line += 1;
                            j += 1;
                        }
                        b'"' => {
                            j += 1;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                i = j;
            }
            b'\'' => {
                // char literal ('a', '\n', '\u{1F600}') vs lifetime ('a in types).
                let rest = &b[i + 1..];
                let is_char_lit = match rest.first() {
                    Some(b'\\') => true,
                    Some(_) => rest.get(1) == Some(&b'\''),
                    None => false,
                };
                if is_char_lit {
                    let mut j = i + 1;
                    if b.get(j) == Some(&b'\\') {
                        j += 2; // the escape introducer and its head
                        while j < b.len() && b[j] != b'\'' {
                            j += 1;
                        }
                        j += 1;
                    } else {
                        j += 2;
                    }
                    i = j;
                } else {
                    i += 1; // lifetime: consume just the quote
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Collects every scannable file under `dir` (recursive) with the given extension filter.
pub fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            // never descend into build output.
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_files(&path, out);
        } else {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            if ext == "masm" || ext == "rs" || name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
}

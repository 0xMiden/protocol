---
name: masm-constants
description: Enforce constant definition and organization conventions for Miden Assembly (.masm) files. Use when editing, reviewing, or creating .masm files that define or use constants.
---

# MASM Constant Conventions

## Placement

Constants must be defined at the **top of the file**, before any procedure definitions, but after imports or type aliases.

## Organization

### Constants Section (first)

Group non-error constants by topic. Use blank lines between sections. Common topics:

- **Slot names** – use `word("path::to::slot")` for slot identifiers
- **Memory pointer offsets** – offsets into memory regions
- **Magic numbers / values** – domain-specific literals
- **Event identifiers** – for `emit` / `trace`

Order sections by dependency or by usage frequency. Put the most widely used first.

### Errors Section (after constants)

Errors (panic/assert error codes, e.g. `ERR_*`) go in a **dedicated "errors" section**, placed after the constants section. Define them with string values describing the error.

## Naming

### Memory Pointers

Memory pointer constants describe offsets into memory regions that are shared or global (e.g. layout of a memory region, input/output structure offsets). They are **not** scoped to a single procedure and do not use the procedure prefix.

```masm
# Good: descriptive, shared usage
const ASSET_OFF = 0
const AMOUNT_OFF = 1
const NOTE_DATA_LEN = 16

# Or grouped by memory region if applicable
const INPUT_PTR_OFF = 0
const INPUT_LEN_OFF = 1
```

### Memory Locals Offsets

Memory locals offsets are **procedure-scoped**: they describe offsets within a procedure's local memory. They must be **prefixed with the procedure name** they belong to:

```masm
# Good: procedure-prefixed
const validate_note_NOTE_IDX_LOC = 0
const validate_note_ASSET_LOC = 1
const process_input_INPUT_PTR_OFF = 0

# Bad: generic, ambiguous
const NOTE_IDX_LOC = 0
const ASSET_LOC = 1
const INPUT_PTR_OFF = 0
```

This keeps offsets scoped and avoids collisions when multiple procedures use local memory.

## Formatting

Put **spaces around the equals sign**.

**Errors** – string value describing the error:
```masm
const ERR_BRIDGE_NOT_MAINNET = "bridge not mainnet"
const ERR_UNAUTHORIZED = "unauthorized"
```

**Slots** – use `word()` with the slot path:
```masm
const BRIDGE_ID_SLOT = word("miden::agglayer::faucet")
const SLOT_ACCOUNT_ID = word("account::id")
```

**Offsets / numeric values** – plain numbers:
```masm
const validate_note_NOTE_IDX_LOC = 0
const validate_note_ASSET_LOC = 1
```

## Example Layout

```masm
# CONSTANTS
# =================================================================================================

# Slots
const BRIDGE_ID_SLOT = word("miden::agglayer::faucet")
const SLOT_ACCOUNT_ID = word("account::id")

# Memory pointers
const ASSET_OFF = 0
const AMOUNT_OFF = 1

# validate_note locals
const validate_note_NOTE_IDX_LOC = 0
const validate_note_ASSET_LOC = 1

# process_input locals
const process_input_INPUT_PTR_OFF = 0
const process_input_LEN_OFF = 1

# ERRORS
# =================================================================================================

const ERR_BRIDGE_NOT_MAINNET = "bridge not mainnet"
const ERR_UNAUTHORIZED = "unauthorized"
const ERR_NOTE_NOT_FOUND = "note not found"

# PROCEDURES
# =================================================================================================

pub proc validate_note
    ...
end
```

## Validation Checklist

- [ ] Errors in dedicated section, placed after constants
- [ ] All constants defined at top of file
- [ ] Non-error constants grouped by topic with blank lines between sections
- [ ] Memory pointers (shared/global) use descriptive names without procedure prefix
- [ ] Memory locals offsets prefixed with procedure name
- [ ] Spaces around `=` in all constant definitions
- [ ] Section comments used to label topic groups

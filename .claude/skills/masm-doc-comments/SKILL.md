---
name: masm-doc-comments
description: Enforce doc comment conventions for Miden Assembly (.masm) procedures. Use when editing, reviewing, or creating .masm procedures, especially when documenting inputs, outputs, panic conditions, or invocation types.
---

# MASM Procedure Doc Comments

## Overview

Every public MASM procedure should have a doc comment block using `#!` prefix with these sections in order:

1. **Description** - What the procedure does
2. **Inputs/Outputs** - Stack state before/after
3. **Where** - Explanation of each stack item (omit when the Description already names every item)
4. **Panics if** - Error conditions (when applicable)
5. **Invocation** - How the procedure is called (`exec`, `call`, or `dyncall`; omitted for syscall-invoked kernel procedures)

## Required Format

```masm
#! Brief description of what the procedure does.
#!
#! Additional context if needed.
#!
#! Inputs:  [item1, item2, WORD_ITEM]
#! Outputs: [result1, RESULT_WORD]
#!
#! Where:
#! - item1 is the description of item1.
#! - item2 is the description of item2.
#! - WORD_ITEM is a 4-element word representing X.
#! - result1 is the description of result1.
#! - RESULT_WORD is the resulting word.
#!
#! Panics if:
#! - condition that causes the procedure to fail.
#! - another error condition.
#!
#! Invocation: exec
pub proc my_procedure
```

## Stack Notation

### Naming Conventions

| Type | Style | Example |
|------|-------|---------|
| Single felt | lowercase with underscores | `note_index`, `amount`, `balance` |
| Word (4 felts) | UPPERCASE with underscores | `ASSET`, `RECIPIENT`, `SCRIPT_ROOT` |
| Multi-felt (2-3) | lowercase with `{parts}` suffix | `account_id_{suffix,prefix}` |
| All-zero Word | `EMPTY_WORD` | `[..., EMPTY_WORD, ...]` |

`EMPTY_WORD` is a naming convention used in stack trackers, `Where:` bullets, and prose comments to denote the all-zero Word `[0, 0, 0, 0]`.

In composite braces, list parts in **stack-top-first order, no spaces inside the braces**: `account_id_{suffix,prefix}` because the suffix sits on top of the stack and the prefix below it. The same rule applies to other split-128-bit IDs (`sender_{suffix,prefix}`, `faucet_id_{suffix,prefix}`, etc.).

### Stack Order

Items are listed left-to-right, with the **top of stack first**:

```masm
#! Inputs:  [top_item, second_item, THIRD_WORD]
```

### Empty Stack

Use empty brackets for no inputs or outputs:

```masm
#! Inputs:  []
#! Outputs: [result]
```

### Span notation `(N)` family

`(N)` after an item name denotes a span of N felts (not a Word). Spans stay lowercase; Words stay UPPERCASE and never take `(N)`. `pad(N)` (see masm-padding skill) is one member of this family; other spans appear in protocol code:

```masm
#! Inputs:  [first_element, foreign_procedure_inputs(15)]
#! Outputs: [foreign_procedure_outputs(16)]
```

### Padding (for `call` and `dyncall` procedures)

Procedures entered at the stack-depth-16 floor (`call` and `dyncall`) must show explicit padding so Inputs and Outputs each sum to 16 elements (see masm-padding skill):

```masm
#! Inputs:  [ASSET, pad(12)]
#! Outputs: [pad(16)]
#!
#! Invocation: call
```

## Where Section

Define every item from Inputs and Outputs:

```masm
#! Where:
#! - note_index is the index of the input note.
#! - sender_{suffix,prefix} are the suffix and prefix felts of the sender ID.
#! - ASSET_KEY is the vault key of the asset [0, 0, faucet_id_suffix, faucet_id_prefix].
#! - balance is the fungible asset balance in the vault.
```

**Rules:**
- Use "is" for single items, "are" for multi-part items
- Start descriptions lowercase (continues the sentence)
- End each line with a period
- Group related items (e.g., all inputs, then all outputs)

### When `Where:` may be omitted

Omit the `Where:` section entirely when the Description already names every Inputs/Outputs item and adding bullets would just repeat that information. Common case: trivial accessor procedures.

```masm
#! Returns the maximum supply.
#!
#! Inputs:  [pad(16)]
#! Outputs: [max_supply, pad(15)]
#!
#! Invocation: call
pub proc get_max_supply
```

No `Where:` is needed: the single named output `max_supply` is already identified by the Description. If you would otherwise write `#! - max_supply is the maximum supply.`, skip it.

Add `Where:` whenever any item needs description beyond what the Description line conveys — different name, additional constraint, composition (`ASSET = [faucet_id_prefix, faucet_id_suffix, 0, amount]`), or anything non-obvious.

## Panics Section

Bullets describe the **condition**, not the error identifier. Write `the nonce has already been incremented.`, not `ERR_ACCOUNT_NONCE_CAN_ONLY_BE_INCREMENTED_ONCE.`. The identifier is an implementation detail of the assert; the doc comment should read as English.

### Direct Panics

List conditions from `assert*` statements in the procedure:

```masm
#! Panics if:
#! - flag is false.
proc sample_procedure
    # => [flag]
    assert.err=ERR_FLAG_IS_FALSE
```

### Propagated Panics

When calling other procedures that may panic:

**Simple case (< 4 conditions):** List the specific conditions:

```masm
#! Description, inputs, etc.
#! Panics if:
#! - flag is false.
proc sample_procedure
    # => [flag]
    exec.another_procedure # this procedure may panic
end

proc another_procedure
    # => [flag]
    assert.err=ERR_FLAG_IS_FALSE
end
```

**Complex case (4+ conditions):** Reference the subprocedure:

```masm
#! Description, inputs, etc.
#! Panics if:
#! - another_procedure fails to verify.
proc sample_procedure
    # => [flag_1, flag_2, flag_3, flag_4]
    exec.another_procedure # this procedure may panic
end

#! Description, inputs, etc.
#! Panics if:
#! - flag_1 is false.
#! - flag_2 is false.
#! - flag_3 is false.
#! - flag_4 is false.
proc another_procedure
    # => [flag_1, flag_2, flag_3, flag_4]
    assert.err=ERR_FLAG_1_IS_FALSE
    assert.err=ERR_FLAG_2_IS_FALSE
    assert.err=ERR_FLAG_3_IS_FALSE
    assert.err=ERR_FLAG_4_IS_FALSE
end
```

### No Panics

Omit the "Panics if:" section entirely if the procedure cannot panic.

## Invocation Types

Specify how the procedure should be invoked. The value matches the MASM instruction that user-code callers use to enter the procedure:

| Value | Used by callers as | When to use |
|---|---|---|
| `exec` | `exec.<proc>` | Standard inline call. Shares the caller's stack; no padding requirement. |
| `call` | `call.<proc>` | Cross-context call (e.g. into another account). Enters at stack depth 16 — Inputs/Outputs must show `pad(N)` to total 16 (see masm-padding). |
| `dyncall` | `dyncall` from a script | Entry point of a note script or transaction script. Stack-depth-16 floor applies on entry. |

```masm
#! Invocation: exec
```

```masm
#! Invocation: call
```

```masm
#! Invocation: dyncall
```

For existing procedures, pick the value that matches how callers invoke them: `call` when invoked via `call.<procedure_name>`, `exec` for `exec.<procedure_name>`, `dyncall` for note-script and transaction-script entry points.

### Kernel procedures (syscall-invoked) are exempt

Kernel procedures under `crates/miden-protocol/asm/kernels/` are invoked by the VM via `syscall.<proc>` from user code. They do not carry an `Invocation:` line — the `syscall` invocation model is implied by the procedure's location in a kernel module. Omit the `Invocation:` line entirely for these procs.

## Validation Checklist

- [ ] Description starts with a capitalized present-tense verb and the first sentence ends with a period. Canonical verbs observed in protocol source: `Returns`, `Gets`, `Computes`, `Burns`, `Creates`, `Increments`, `Copies`, `Asserts`, `Verifies`, `Hashes`, `Adds`, `Removes`.
- [ ] Inputs and Outputs use correct stack notation
- [ ] Where section defines every stack item that needs description beyond the Description line, and is omitted entirely when the Description alone covers every item
- [ ] Words are UPPERCASE, felts are lowercase
- [ ] Panics section lists direct asserts and propagated errors
- [ ] Complex panic propagation uses "if <procedure> fails to verify" shorthand
- [ ] Invocation type specified: `exec`, `call`, or `dyncall`. Kernel (syscall-invoked) procedures are exempt — no `Invocation:` line.
- [ ] For `call` and `dyncall`: padding shown in Inputs/Outputs (see masm-padding skill)

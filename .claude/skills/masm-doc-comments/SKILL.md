---
name: masm-doc-comments
description: Enforce doc comment conventions for Miden Assembly (.masm) procedures. Use when editing, reviewing, or creating .masm procedures, especially when documenting inputs, outputs, panic conditions, or invocation types.
---

# MASM Procedure Doc Comments

## Overview

Every public MASM procedure should have a doc comment block using `#!` prefix with these sections in order:

1. **Description** - What the procedure does
2. **Inputs/Outputs** - Stack state before/after
3. **Where** - Explanation of each stack item
4. **Panics if** - Error conditions (when applicable)
5. **Invocation** - How the procedure is called (`exec` or `call`)

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
| Multi-felt (2-3) | lowercase with `{parts}` suffix | `account_id_{prefix,suffix}` |
| All-zero Word | `EMPTY_WORD` | `[..., EMPTY_WORD, ...]` |

`EMPTY_WORD` is a naming convention used in stack trackers, `Where:` bullets, and prose comments to denote the all-zero Word `[0, 0, 0, 0]`. It is not a defined constant; the point is to convey *meaning* (absence of data) rather than the literal numeric value.

Brace spacing (`{suffix,prefix}` vs `{suffix, prefix}`) and part order (`{suffix,prefix}` vs `{prefix,suffix}`) are inconsistent in source. Match the surrounding file; do not reformat existing braces.

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
#! Inputs:  [pad(16), foreign_procedure_inputs(15)]
#! Outputs: [foreign_procedure_outputs(16)]
```

For variable-length remainders, use a trailing `, ...`:

```masm
#! Inputs:  [note_idx, ...]
```

### Padding (for `call` procedures only)

Include explicit padding for `call` procedures (see masm-padding skill):

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
#! - sender_{prefix,suffix} are the prefix and suffix felts of the sender ID.
#! - ASSET is the asset word [faucet_id_prefix, faucet_id_suffix, 0, amount].
#! - balance is the fungible asset balance in the vault.
```

**Rules:**
- Use "is" for single items, "are" for multi-part items
- Start descriptions lowercase (continues the sentence)
- End each line with a period
- Group related items (e.g., all inputs, then all outputs)

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

Always specify how the procedure should be invoked:

```masm
#! Invocation: exec
```

or

```masm
#! Invocation: call
```

For existing procedures, a good rule of thumb is to use `call` when other procedures invoke this procedure via `call.<procedure_name>`, and `exec` if the procedure is invoked via `exec.<procedure_name>`.
There is also `dyncall` or `syscall` but they are not commonly used and should be handled by the programmer.

## Validation Checklist

- [ ] Description starts with a capitalized present-tense verb and the first sentence ends with a period. Canonical verbs observed in protocol source: `Returns`, `Gets`, `Computes`, `Burns`, `Creates`, `Increments`, `Copies`, `Asserts`, `Verifies`, `Hashes`, `Adds`, `Removes`.
- [ ] Inputs and Outputs use correct stack notation
- [ ] All stack items defined in Where section
- [ ] Words are UPPERCASE, felts are lowercase
- [ ] Panics section lists direct asserts and propagated errors
- [ ] Complex panic propagation uses "if <procedure> fails to verify" shorthand
- [ ] Invocation type specified (exec or call)
- [ ] For `call`: padding shown in Inputs/Outputs (see masm-padding skill)

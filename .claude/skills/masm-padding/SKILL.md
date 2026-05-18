---
name: masm-padding
description: Enforce stack padding conventions for Miden Assembly (.masm) procedures based on invocation type (call vs exec). Use when editing, reviewing, or creating .masm procedures, especially those with Invocation annotations.
---

# MASM Padding Conventions

## Overview

Padding requirements differ based on procedure invocation type:

| Invocation | Padding Required | Input/Output Elements |
|------------|------------------|----------------------|
| `call`     | Explicit padding in comments | Exactly 16 |
| `exec`     | No explicit padding | No requirement |

## Stack Depth Floor: 16

Miden VM enforces a minimum operand-stack depth of 16 elements (`MIN_STACK_DEPTH = 16` in the VM core). When an operation would naively shrink the stack below 16, the VM auto-fills the missing positions with zeros via the overflow-table mechanism. The actual depth stays exactly 16; only the visible content shrinks.

This invariant applies at the entry boundary of:

- `call` procedures,
- note scripts and transaction scripts (entered via `dyncall` at depth 16).

It does NOT apply to mid-chain `exec` procedures, which share the caller's stack and can drop the visible count below 16 by consuming caller elements (see Danger Zone).

### Tracking the floor in inline comments

When the naive math would put the stack below 16, the `# =>` tracker must reflect the actual auto-padded depth, not the naive count.

```masm
# entry at depth 16: [VALUE, pad(12)]
dropw
# => [pad(16)]   # correct: VALUE replaced with zeros, depth still 16
```

Not:

```masm
# => [pad(12)]   # wrong: depth is still 16, only the visible content shrank
```

This shows up most often at the start of note scripts that don't use their input arguments:

```masm
begin
    dropw
    # => [pad(16)]
    ...
end
```

## Call Procedures

Procedures invoked with `call` must have explicit padding in:
1. **Doc comments** (`#!`) for Inputs/Outputs
2. **Inline comments** (`#`) showing stack state

### Doc Comment Format

Use `pad(N)` notation where N + other elements = 16:

```masm
#! Inputs:  [ASSET, pad(12)]
#! Outputs: [pad(16)]
#!
#! Invocation: call
pub proc receive_asset
```

### Inline Comment Format

Track padding through the procedure:

```masm
exec.native_account::set_item
# => [OLD_VALUE, pad(12)]

dropw
# => [pad(16)] auto-padded to 16 elements    
```

## Exec Procedures

Procedures invoked with `exec` should NOT have explicit padding:

```masm
#! Inputs:  [PUB_KEY]
#! Outputs: []
#!
#! Invocation: exec
pub proc authenticate_transaction
```

### Why No Padding for Exec

`exec` procedures share the caller's stack directly. Explicit padding would be misleading because:
- The actual stack may have additional elements from the caller
- The procedure may consume caller's stack elements

### Danger Zone

If an `exec` procedure's stack falls below the specified stack elements, it will consume stack items from its caller, potentially leading to unexpected behavior. This is a bug and should be fixed by ensuring the procedure maintains sufficient stack depth and avoiding dropping more stack elements than available.

### Example of Dangerous Behavior

```masm
# => [num_approvers, threshold]
dropw # dropw drops 4 elements, which will result in "negative" stack consumption (consuming 2 elements from the caller's stack)
```


## Intermediate States

Inside a procedure, the stack may temporarily exceed 16 elements:

```masm
# => [num_approvers, threshold, MULTISIG_CONFIG, pad(12)]
#     ^--- 18 elements total, must be reduced before return
```

These extra elements must be explicitly dropped before the procedure returns (directly or via called procedures).

## Debugging Stack Depth

When unsure whether the stack matches the depth you expect, use the assembly's debug instructions to inspect it at runtime. These cost zero VM cycles, do not affect the program hash, and are stripped at compile time when the assembler is not in debug mode.

- `debug.stack` – print the full operand stack.
- `debug.stack.N` – print only the top N elements (1 ≤ N < 256).
- `sdepth` – push the current stack depth onto the stack as a felt; useful when you need depth as a runtime value, e.g. to assert it:

  ```masm
  sdepth push.16 eq assert.err="depth must be 16 here"
  ```

Run with the `--debug` flag to see output:

```bash
miden-vm run program.masm --debug
```

Without `--debug`, debug instructions are silently removed. Remove or comment out `debug.*` lines before committing production MASM.

## Validation Checklist

For all invocation types:
- [ ] Inline `# =>` trackers reflect the post-auto-pad depth (never below 16) at boundaries that enforce the floor (`call`, note scripts, tx scripts)
- [ ] No `debug.*` instruction is left in production MASM

For `call` procedures:
- [ ] Inputs doc comment shows exactly 16 elements with `pad(N)`
- [ ] Outputs doc comment shows exactly 16 elements with `pad(N)`
- [ ] Inline comments use `# =>` format with `pad(N)` notation
- [ ] All intermediate states track the full stack including padding

For `exec` procedures:
- [ ] No `pad(N)` in Inputs/Outputs doc comments
- [ ] No explicit padding in inline stack state comments
- [ ] Verify stack never drops below safe depth

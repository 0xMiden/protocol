---
sidebar_position: 7
---

# Blocks

## Public transaction logs

A block body preserves transaction headers grouped by batch and contains the complete public
transaction logs in the same batch and transaction order. Each public native-account transaction
has one entry, including empty collections. Private native-account transactions have no log entries.
Emission order and duplicate logs are preserved.

Each log collection must match its transaction header's log commitment. Missing, extra, reordered,
private-associated, or commitment-mismatched entries make the body invalid. Transaction IDs bind
the log commitments, and the block transaction commitment binds the ordered transaction IDs.

A block permits at most 32,768 public log content words (1 MiB of raw content) across all batches,
excluding metadata. Empty content consumes no word budget. The
[per-transaction log limits](transaction.md#limits) also apply.

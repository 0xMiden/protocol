---
sidebar_position: 6
---

# Batches

## Public transaction logs

A proven batch contains the complete logs of each public native-account transaction, including
empty collections, in transaction order. Private native-account transactions have no log entries,
even when a public foreign account emits logs for them. Emission order and duplicate logs are
preserved.

Each log collection must match its transaction header's log commitment. Missing, extra, reordered,
private-associated, or commitment-mismatched entries make the batch invalid. Transaction IDs bind
the log commitments, and the batch ID binds the ordered transaction IDs.

A batch permits at most 32,768 public log content words (1 MiB of raw content), excluding metadata.
Empty content consumes no word budget. The [per-transaction log limits](transaction.md#limits)
also apply.

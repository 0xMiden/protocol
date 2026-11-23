Added `ExecutedTransaction` and `TransactionMeasurements` protobuf messages.
[BREAKING] Changed `ExecutedTransaction::new` to return an error if the transaction data is inconsistent.
[BREAKING] Removed Winterfell serialization from `TransactionMeasurements`.
[BREAKING] Replaced the public fields of `TransactionMeasurements` with accessors and a fallible builder.
[BREAKING] Changed the cycle counts of `TransactionMeasurements`, `CycleInterval` and the note checker to `u32`.

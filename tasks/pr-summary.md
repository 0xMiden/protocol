## Summary

Reduces `NoteType` encoding from 2 bits to 1 bit and adds a 4-bit version field to the note metadata header, as a prerequisite for #2555 (multiple attachments per note). This frees up bits in the metadata header for future attachment metadata.

**Breaking change**: The note metadata encoding (both Rust serialization and MASM Word layout) has changed.

### New metadata layout

```text
Old: [sender_id_suffix (56 bits) | 6 zero bits | note_type (2 bits)]
New: [sender_id_suffix (56 bits) | reserved (3 bits) | note_type (1 bit) | version (4 bits)]
```

- `NoteType::Private` changed from `2` to `0` (new default)
- `NoteType::Public` remains `1`
- Version is hardcoded to `0` for forward compatibility
- Reserved bits are validated to be zero on decode

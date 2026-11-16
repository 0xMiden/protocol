The `on_before_note_sealed` asset callback now returns `[attachment_scheme, ATTACHMENT_COMMITMENT]`, an attachment that `output_note::seal` appends to the note unless the scheme is 0.

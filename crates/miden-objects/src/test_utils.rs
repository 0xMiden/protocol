use core::error::Error;

use miden_protocol::Word;

pub(crate) fn error_source<'a, T: Error + 'static>(
    error: &'a (dyn Error + 'static),
) -> Option<&'a T> {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }
        source = error.source();
    }
    None
}

pub(crate) fn dummy_word(value: u32) -> Word {
    Word::from([value, 0, 0, 0])
}

use core::error::Error;

use crate::ConversionError;

/// Extracts an infallible result without introducing a potential panic.
///
/// ```
/// use core::convert::Infallible;
///
/// use miden_protobuf::unwrap_infallible;
///
/// assert_eq!(unwrap_infallible(Ok::<_, Infallible>(42)), 42);
/// ```
///
/// Fallible results are rejected at compile time:
///
/// ```compile_fail,E0308
/// use miden_protobuf::unwrap_infallible;
///
/// unwrap_infallible("42".parse::<u32>());
/// ```
pub fn unwrap_infallible<T>(result: Result<T, core::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(impossible) => match impossible {},
    }
}

/// Decodes a wire message or oneof without constructing its verified domain counterpart.
///
/// Derived implementations produce schema-shaped records. Atomic messages can select an existing
/// deserialized type instead, using its `TryFrom` implementation. Such adapters should check the
/// representation only, leaving application invariants to [`Verify`] or [`VerifyWith`].
pub trait DecodeMessage: Sized {
    type Decoded: TryFrom<Self, Error = ConversionError>;

    fn decode_fields(self) -> Result<Self::Decoded, ConversionError> {
        self.try_into()
    }
}

/// The decoded representation of a **wire message or oneof** `P`, not its verified domain
/// counterpart.
pub type Decoded<P> = <P as DecodeMessage>::Decoded;

/// Checks domain invariants and constructs the verified type using ordinary Rust.
///
/// Verification errors belong to the domain. Unlike decoding errors, their field paths are not
/// generated: cross-field checks need not correspond to a single wire field.
/// Types that require external context can implement [`VerifyWith`] instead.
pub trait Verify: Sized {
    type Verified;
    type Error: Error + Send + Sync + 'static;

    fn verify(self) -> Result<Self::Verified, Self::Error>;
}

/// Checks domain invariants using caller-supplied context and constructs the verified type.
///
/// Context can be borrowed, such as a trusted parent header, or owned, such as a security level.
/// Use a named context struct when verification needs several inputs. Implementations must
/// document any trust requirements on the context.
///
/// This capability is independent of [`Verify`]: implementing it does not provide context-free
/// verification. As with [`Verify`], errors belong to the domain and do not receive generated
/// wire paths. Implementations are handwritten; decoding does not invoke verification.
pub trait VerifyWith<C>: Sized {
    type Verified;
    type Error: Error + Send + Sync + 'static;

    fn verify_with(self, context: C) -> Result<Self::Verified, Self::Error>;
}

/// Constructs a domain object from decoded fields while skipping selected verification checks.
///
/// This is an explicit, handwritten capability, independent of [`Verify`] and [`VerifyWith`].
/// Implement it only where the domain API supports unchecked construction. Construction can still
/// fail on remaining checks or conversions; use [`core::convert::Infallible`] when it cannot fail.
///
/// # Warning
///
/// Implementations must document precisely which checks are skipped, including nested checks,
/// and which invariants callers must ensure. The output is not guaranteed to be verified. This
/// operation must not bypass wire decoding checks or silently discard verification errors.
/// Skipping domain validation alone does not make this a Rust `unsafe` operation.
pub trait BuildUnchecked: Sized {
    type Output;
    type Error: Error + Send + Sync + 'static;

    fn build_unchecked(self) -> Result<Self::Output, Self::Error>;
}

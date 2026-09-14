use alloc::format;
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
/// Use [`DecodeMessageExt`] to combine field decoding with an explicit construction capability.
pub trait DecodeMessage: Sized {
    type Decoded: TryFrom<Self, Error = ConversionError>;

    fn decode_fields(self) -> Result<Self::Decoded, ConversionError> {
        self.try_into()
    }
}

/// The decoded representation of a **wire message or oneof** `P`, not its verified domain
/// counterpart.
pub type Decoded<P> = <P as DecodeMessage>::Decoded;

/// Combines field decoding with an explicitly selected domain construction capability.
///
/// Implemented for every [`DecodeMessage`], including oneofs and handwritten adapters. Each
/// method requires only its corresponding capability on the decoded representation. These methods
/// consume an already parsed wire message; they do not decode Protobuf bytes.
///
/// All methods return [`ConversionError`] with a stage prefix: `failed to decode`,
/// `failed to verify`, or `failed to build unchecked`. The original error, including any field
/// path, is preserved in the source chain. Stage labels are separate from wire paths. Call
/// [`DecodeMessage::decode_fields`] and the construction method separately when typed domain
/// errors are needed directly.
pub trait DecodeMessageExt: DecodeMessage {
    /// Decodes fields, then checks domain invariants using [`Verify::verify`].
    ///
    /// ```
    /// use miden_protobuf::{ConversionError, DecodeMessageExt, Verify};
    ///
    /// fn decode<P>(message: P) -> Result<<P::Decoded as Verify>::Verified, ConversionError>
    /// where
    ///     P: DecodeMessageExt,
    ///     P::Decoded: Verify,
    /// {
    ///     message.decode_and_verify()
    /// }
    /// ```
    fn decode_and_verify(self) -> Result<<Self::Decoded as Verify>::Verified, ConversionError>
    where
        Self::Decoded: Verify,
    {
        let decoded = self.decode_fields().map_err(|error| stage_error("decode", error))?;
        decoded.verify().map_err(|error| stage_error("verify", error))
    }

    /// Decodes fields, then verifies with borrowed or owned caller-supplied context.
    ///
    /// The context must satisfy the trust requirements of the decoded type's
    /// [`VerifyWith`] implementation.
    ///
    /// ```
    /// use miden_protobuf::{ConversionError, DecodeMessageExt, VerifyWith};
    ///
    /// fn decode<P, C>(
    ///     message: P,
    ///     context: C,
    /// ) -> Result<<P::Decoded as VerifyWith<C>>::Verified, ConversionError>
    /// where
    ///     P: DecodeMessageExt,
    ///     P::Decoded: VerifyWith<C>,
    /// {
    ///     message.decode_and_verify_with(context)
    /// }
    /// ```
    fn decode_and_verify_with<C>(
        self,
        context: C,
    ) -> Result<<Self::Decoded as VerifyWith<C>>::Verified, ConversionError>
    where
        Self::Decoded: VerifyWith<C>,
    {
        let decoded = self.decode_fields().map_err(|error| stage_error("decode", error))?;
        decoded.verify_with(context).map_err(|error| stage_error("verify", error))
    }

    /// Decodes fields, then constructs with [`BuildUnchecked::build_unchecked`].
    ///
    /// Structural decoding checks still run, and construction can still fail.
    ///
    /// # Warning
    ///
    /// The output is not guaranteed to be verified. Callers must ensure the invariants documented
    /// by the decoded type's [`BuildUnchecked`] implementation, including any nested checks it
    /// skips.
    ///
    /// ```
    /// use miden_protobuf::{BuildUnchecked, ConversionError, DecodeMessageExt};
    ///
    /// fn decode<P>(message: P) -> Result<<P::Decoded as BuildUnchecked>::Output, ConversionError>
    /// where
    ///     P: DecodeMessageExt,
    ///     P::Decoded: BuildUnchecked,
    /// {
    ///     message.decode_and_build_unchecked()
    /// }
    /// ```
    fn decode_and_build_unchecked(
        self,
    ) -> Result<<Self::Decoded as BuildUnchecked>::Output, ConversionError>
    where
        Self::Decoded: BuildUnchecked,
    {
        let decoded = self.decode_fields().map_err(|error| stage_error("decode", error))?;
        decoded.build_unchecked().map_err(|error| stage_error("build unchecked", error))
    }
}

impl<P: DecodeMessage> DecodeMessageExt for P {}

fn stage_error(stage: &'static str, error: impl Error + Send + Sync + 'static) -> ConversionError {
    ConversionError::with_source(format!("failed to {stage}: {error}"), error)
}

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

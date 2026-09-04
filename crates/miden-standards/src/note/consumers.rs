// NOTE CONSUMERS
// ================================================================================================

/// Declares which accounts a note allows to consume it.
///
/// Every note script states the same rule on the `Consumers:` line of the doc comment of its
/// `@note_script` procedure and, unless it is [`Unrestricted`](NoteConsumers::Unrestricted),
/// enforces it with the `miden::standards::note::consumer` procedures.
///
/// Declaring the rule makes it a property of the note rather than something that can only be
/// discovered by reading the script: a note that is open to any consumer says so and says why, so a
/// missing consumer check is a visible choice rather than an omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoteConsumers {
    /// Only the single account the note commits to may consume it.
    ///
    /// The account is committed to either by a
    /// [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) attachment or by the note
    /// storage, and the note script asserts it against the consuming account.
    TargetAccount,

    /// Only one of a fixed set of accounts the note commits to may consume it, and the note script
    /// decides which of them a given consumption belongs to.
    CommittedAccounts,

    /// Any account may consume the note.
    Unrestricted {
        /// Why the note is safe to leave open to any consumer.
        rationale: &'static str,
    },
}

impl NoteConsumers {
    /// Returns whether consumption is restricted to accounts the note commits to.
    pub const fn is_restricted(&self) -> bool {
        !matches!(self, Self::Unrestricted { .. })
    }

    /// Returns the name of the rule, which is the class named on the note script's `Consumers:`
    /// line.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::TargetAccount => "target account",
            Self::CommittedAccounts => "committed accounts",
            Self::Unrestricted { .. } => "unrestricted",
        }
    }
}

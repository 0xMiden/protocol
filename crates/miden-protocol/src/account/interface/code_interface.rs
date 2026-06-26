use alloc::collections::BTreeSet;

use crate::account::AccountId;
use crate::account::code::AccountCode;
use crate::account::code::procedure::AccountProcedureRoot;
use crate::errors::AccountCodeInterfaceError;

/// The set of procedures an account exposes.
///
/// This is the next-generation replacement for the enum-based interface in `miden-standards`. It
/// is intentionally minimal: it only carries the account's ID and the set of procedure roots that
/// make up its callable surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeInterface {
    account_id: AccountId,
    procedures: BTreeSet<AccountProcedureRoot>,
}

impl AccountCodeInterface {
    /// Constructs a new [`AccountCodeInterface`] from the given account ID and set of procedure
    /// roots.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of procedures is outside the
    /// `[AccountCode::MIN_NUM_PROCEDURES, AccountCode::MAX_NUM_PROCEDURES]` range.
    pub fn new(
        account_id: AccountId,
        procedures: BTreeSet<AccountProcedureRoot>,
    ) -> Result<Self, AccountCodeInterfaceError> {
        let count = procedures.len();
        if count < AccountCode::MIN_NUM_PROCEDURES {
            return Err(AccountCodeInterfaceError::TooFewProcedures { actual: count });
        }
        if count > AccountCode::MAX_NUM_PROCEDURES {
            return Err(AccountCodeInterfaceError::TooManyProcedures { actual: count });
        }
        Ok(Self { account_id, procedures })
    }

    /// Returns the ID of the account this interface belongs to.
    pub fn id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the set of procedure roots exposed by this interface.
    pub fn procedures(&self) -> &BTreeSet<AccountProcedureRoot> {
        &self.procedures
    }

    /// Returns `true` if every procedure root yielded by `procedures` is contained in this
    /// interface.
    pub fn contains(&self, procedures: impl IntoIterator<Item = AccountProcedureRoot>) -> bool {
        procedures
            .into_iter()
            .all(|procedure_root| self.procedures.contains(&procedure_root))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use rstest::rstest;

    use super::*;
    use crate::Word;
    use crate::account::{AccountBuilder, PartialAccount};
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;

    fn procedure(value: u32) -> AccountProcedureRoot {
        AccountProcedureRoot::from_raw(Word::from([value, value, value, value]))
    }

    fn build_code_interface(values: &[u32]) -> AccountCodeInterface {
        let procedures: BTreeSet<AccountProcedureRoot> =
            values.iter().copied().map(procedure).collect();
        AccountCodeInterface::new(dummy_account_id(), procedures).unwrap()
    }

    fn dummy_account_id() -> AccountId {
        AccountId::try_from(
            crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        )
        .unwrap()
    }

    #[rstest]
    #[case::empty(vec![])]
    #[case::subset(vec![1, 2])]
    #[case::exact(vec![1, 2, 3])]
    fn contains_returns_true(#[case] query: Vec<u32>) {
        let interface = build_code_interface(&[1, 2, 3]);
        let query: Vec<AccountProcedureRoot> = query.into_iter().map(procedure).collect();
        assert!(interface.contains(query));
    }

    #[rstest]
    #[case::missing_one(vec![1, 4])]
    #[case::all_missing(vec![10, 11])]
    fn contains_returns_false(#[case] query: Vec<u32>) {
        let interface = build_code_interface(&[1, 2, 3]);
        let query: Vec<AccountProcedureRoot> = query.into_iter().map(procedure).collect();
        assert!(!interface.contains(query));
    }

    #[test]
    fn new_rejects_too_few_procedures() {
        let procedures: BTreeSet<AccountProcedureRoot> = BTreeSet::new();
        let err = AccountCodeInterface::new(dummy_account_id(), procedures).unwrap_err();
        assert_matches::assert_matches!(
            err,
            AccountCodeInterfaceError::TooFewProcedures { actual: 0 }
        );

        let one_procedure: BTreeSet<AccountProcedureRoot> = [procedure(1)].into_iter().collect();
        let err = AccountCodeInterface::new(dummy_account_id(), one_procedure).unwrap_err();
        assert_matches::assert_matches!(
            err,
            AccountCodeInterfaceError::TooFewProcedures { actual: 1 }
        );
    }

    #[test]
    fn new_rejects_too_many_procedures() {
        let procedures: BTreeSet<AccountProcedureRoot> =
            (0..=AccountCode::MAX_NUM_PROCEDURES as u32).map(procedure).collect();
        let expected = AccountCode::MAX_NUM_PROCEDURES + 1;
        let err = AccountCodeInterface::new(dummy_account_id(), procedures).unwrap_err();
        assert_matches::assert_matches!(
            err,
            AccountCodeInterfaceError::TooManyProcedures { actual } if actual == expected
        );
    }

    #[test]
    fn new_accepts_min_and_max_procedures() {
        let min: BTreeSet<AccountProcedureRoot> =
            (0..AccountCode::MIN_NUM_PROCEDURES as u32).map(procedure).collect();
        AccountCodeInterface::new(dummy_account_id(), min).unwrap();

        let max: BTreeSet<AccountProcedureRoot> =
            (0..AccountCode::MAX_NUM_PROCEDURES as u32).map(procedure).collect();
        AccountCodeInterface::new(dummy_account_id(), max).unwrap();
    }

    #[test]
    fn account_code_interface_matches_code_procedures() -> anyhow::Result<()> {
        let account = AccountBuilder::new([7; 32])
            .with_auth_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build()?;

        let code_interface = account.code_interface();
        let expected: BTreeSet<AccountProcedureRoot> =
            account.code().procedures().iter().copied().collect();

        assert_eq!(code_interface.id(), account.id());
        assert_eq!(code_interface.procedures(), &expected);

        Ok(())
    }

    #[test]
    fn partial_account_code_interface_matches_code_procedures() -> anyhow::Result<()> {
        let account = AccountBuilder::new([8; 32])
            .with_auth_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build()?;
        let partial = PartialAccount::from(&account);

        let code_interface = partial.code_interface();
        let expected: BTreeSet<AccountProcedureRoot> =
            partial.code().procedures().iter().copied().collect();

        assert_eq!(code_interface.id(), partial.id());
        assert_eq!(code_interface.procedures(), &expected);

        Ok(())
    }
}

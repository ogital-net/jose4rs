use std::{fmt::Display, sync::LazyLock};

use crate::{error::JoseError, jwe::KeyManagementAlgorithm, jws::AlgorithmIdentifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    Permit,
    Block,
}

pub static BLOCK_NONE: LazyLock<AlgorithmConstraints<AlgorithmIdentifier>> =
    LazyLock::new(|| AlgorithmConstraints::block(Some(AlgorithmIdentifier::None)));

pub struct AlgorithmConstraints<A> {
    constraint_type: ConstraintType,
    algorithms: Box<[A]>,
}

pub trait Algorithm {}

impl Algorithm for AlgorithmIdentifier {}
impl Algorithm for KeyManagementAlgorithm {}

impl<A> AlgorithmConstraints<A>
where
    A: Clone + PartialEq + Display + Algorithm,
{
    pub fn new(constraint_type: ConstraintType, algs: impl AsRef<[A]>) -> Self {
        let algorithms = Box::from(algs.as_ref());
        Self {
            constraint_type,
            algorithms,
        }
    }

    fn block(alg: Option<A>) -> Self {
        let algorithms = match alg {
            Some(alg) => Box::from([alg]),
            None => Box::from([]),
        };

        Self {
            constraint_type: ConstraintType::Block,
            algorithms,
        }
    }

    pub(crate) fn check_constraint(&self, algorithm: A) -> Result<(), JoseError> {
        match self.constraint_type {
            ConstraintType::Permit => {
                if !self.algorithms.contains(&algorithm) {
                    return Err(JoseError::InvalidAlgorithm(format!(
                        "'{algorithm}' is not a permitted algorithm."
                    )));
                }
            }
            ConstraintType::Block => {
                if self.algorithms.contains(&algorithm) {
                    return Err(JoseError::InvalidAlgorithm(format!(
                        "'{algorithm}' is a blocked algorithm."
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::jws::AlgorithmIdentifier;

    use super::*;

    #[test]
    fn test_constraints() {
        let constraints = AlgorithmConstraints::new(
            ConstraintType::Permit,
            [
                AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256,
                AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512,
            ],
        );

        assert!(constraints
            .check_constraint(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384)
            .is_err());
        assert!(constraints
            .check_constraint(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
            .is_ok());
        assert!(constraints
            .check_constraint(AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512)
            .is_ok());

        let constraints = &BLOCK_NONE;
        assert!(constraints
            .check_constraint(AlgorithmIdentifier::None)
            .is_err());
    }
}

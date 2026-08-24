use std::{fmt::Display, sync::LazyLock};

use crate::{error::JoseError, jwe::KeyManagementAlgorithm, jws::AlgorithmIdentifier};

/// Whether an [`AlgorithmConstraints`] set permits or blocks its algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    /// Only the listed algorithms are allowed; everything else is rejected.
    Permit,
    /// The listed algorithms are rejected; everything else is allowed.
    Block,
}

/// An [`AlgorithmConstraints`] that blocks only the `none` algorithm.
///
/// This is the default for JWS: every signature algorithm is accepted except
/// the insecure `none` algorithm.
pub static BLOCK_NONE: LazyLock<AlgorithmConstraints<AlgorithmIdentifier>> =
    LazyLock::new(|| AlgorithmConstraints::block(Some(AlgorithmIdentifier::None)));

/// A set of algorithms to permit or block when verifying, decrypting, or
/// producing JOSE objects.
///
/// Constraints guard against algorithm-substitution attacks by letting the
/// caller restrict which algorithms a given operation will accept. See
/// [`ConstraintType`] for the two modes.
#[derive(Debug)]
pub struct AlgorithmConstraints<A> {
    constraint_type: ConstraintType,
    algorithms: Box<[A]>,
}

/// Marker trait for JOSE algorithm identifier enums.
///
/// Implemented by [`AlgorithmIdentifier`] (JWS signature algorithms) and
/// [`KeyManagementAlgorithm`] (JWE key management algorithms), allowing
/// [`AlgorithmConstraints`] to be generic over both.
pub trait Algorithm {}

impl Algorithm for AlgorithmIdentifier {}
impl Algorithm for KeyManagementAlgorithm {}

impl<A> AlgorithmConstraints<A>
where
    A: Clone + PartialEq + Display + Algorithm,
{
    /// Creates a constraint set of the given type over the given algorithms.
    pub fn new(constraint_type: ConstraintType, algs: impl AsRef<[A]>) -> Self {
        let algorithms = Box::from(algs.as_ref());
        Self {
            constraint_type,
            algorithms,
        }
    }

    /// Creates a [`ConstraintType::Block`] constraint over zero or one algorithm.
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
                        "'{algorithm}' is not a permitted algorithm"
                    )));
                }
            }
            ConstraintType::Block => {
                if self.algorithms.contains(&algorithm) {
                    return Err(JoseError::InvalidAlgorithm(format!(
                        "'{algorithm}' is a blocked algorithm"
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

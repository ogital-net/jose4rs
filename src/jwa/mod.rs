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
/// This trait is sealed; downstream crates cannot implement it.
///
/// ```compile_fail,E0277
/// use jose4rs::jwa::Algorithm;
///
/// struct CustomAlgorithm;
/// impl Algorithm for CustomAlgorithm {}
/// ```
pub trait Algorithm: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for AlgorithmIdentifier {}
impl Algorithm for AlgorithmIdentifier {}
impl sealed::Sealed for KeyManagementAlgorithm {}
impl Algorithm for KeyManagementAlgorithm {}

impl<A> AlgorithmConstraints<A>
where
    A: Copy + PartialEq + Display + Algorithm,
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

    /// Returns whether this policy allows `algorithm`.
    ///
    /// Use this to apply the same policy before key lookup and during a
    /// JOSE operation. An empty permit list rejects all algorithms; an empty
    /// block list rejects none.
    pub fn permits(&self, algorithm: A) -> bool {
        let listed = self.algorithms.contains(&algorithm);
        match self.constraint_type {
            ConstraintType::Permit => listed,
            ConstraintType::Block => !listed,
        }
    }

    pub(crate) fn check_constraint(&self, algorithm: A) -> Result<(), JoseError> {
        if self.permits(algorithm) {
            return Ok(());
        }
        let message = match self.constraint_type {
            ConstraintType::Permit => format!("'{algorithm}' is not a permitted algorithm"),
            ConstraintType::Block => format!("'{algorithm}' is a blocked algorithm"),
        };
        Err(JoseError::InvalidAlgorithm(message))
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

        assert!(
            constraints
                .check_constraint(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384)
                .is_err()
        );
        assert!(
            constraints
                .check_constraint(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
                .is_ok()
        );
        assert!(
            constraints
                .check_constraint(AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512)
                .is_ok()
        );

        let constraints = &BLOCK_NONE;
        assert!(
            constraints
                .check_constraint(AlgorithmIdentifier::None)
                .is_err()
        );
    }

    #[test]
    fn test_permits_matches_constraint_enforcement() {
        let alg = AlgorithmIdentifier::Ed25519;
        let other = AlgorithmIdentifier::EdDsa;
        for (mode, listed, unlisted) in [
            (ConstraintType::Permit, true, false),
            (ConstraintType::Block, false, true),
        ] {
            let constraints = AlgorithmConstraints::new(mode, [alg]);
            for (candidate, expected) in [(alg, listed), (other, unlisted)] {
                assert_eq!(constraints.permits(candidate), expected);
                assert_eq!(constraints.check_constraint(candidate).is_ok(), expected);
            }
            assert_eq!(AlgorithmConstraints::new(mode, []).permits(alg), unlisted);
        }
    }
}

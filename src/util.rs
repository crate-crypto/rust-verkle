use ark_ec::PairingEngine;
use ark_ff::{One, PrimeField};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::iter::successors;
pub(crate) fn powers_of<F: PrimeField>(scalar: &F, max_degree: usize) -> Vec<F> {
    powers_of_iter(*scalar, max_degree).collect::<Vec<_>>()
}
pub(crate) fn powers_of_iter<F: PrimeField>(
    scalar: F,
    max_degree: usize,
) -> impl Iterator<Item = F> {
    // XXX: As long as the scalar is not 1, this works.
    // scalar should be random, so this should be negligible
    assert!(scalar != F::one());
    let last_power = scalar.pow([max_degree as u64, 0, 0, 0]);
    let powers_of_10 = successors(Some(F::one()), move |n| {
        if n != &last_power {
            Some(*n * scalar)
        } else {
            None
        }
    });
    powers_of_10
}

/// This function is only used to generate the SRS.
/// The intention is just to compute the resulting points
/// of the operation `a*P, b*P, c*P ... (n-1)*P` into a `Vec`.
pub(crate) fn slow_multiscalar_mul_single_base<E: PairingEngine>(
    scalars: &[E::Fr],
    base: E::G1Projective,
) -> Vec<E::G1Projective> {
    use ark_ec::ProjectiveCurve;
    scalars
        .par_iter()
        .map(|s| base.mul(s.into_repr()))
        .collect()
}

#[cfg(test)]
mod test {
    use crate::util;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Field;

    /// Returns a vector of Frs of increasing powers of x from x^0 to x^d.
    fn slow_powers_of<F: PrimeField>(scalar: &F, max_degree: usize) -> Vec<F> {
        let mut powers = Vec::with_capacity(max_degree + 1);
        powers.push(F::one());
        for i in 1..=max_degree {
            powers.push(powers[i - 1] * scalar);
        }
        powers
    }
    #[test]
    fn powers_of_sucessor() {
        let scalar = ark_bls12_381::Fr::from(2 as u128);
        let powers = slow_powers_of(&scalar, 10);
        assert_eq!(powers.len(), 11);
        let powers2 = powers_of(&scalar, 10);
        assert_eq!(powers2.len(), 11);
        assert_eq!(powers, powers2)
    }

    #[test]
    fn test_powers_of() {
        let x = Fr::from(10u64);
        let degree = 100u64;

        let powers_of_x = util::powers_of::<Fr>(&x, degree as usize);

        for (i, x_i) in powers_of_x.iter().enumerate() {
            assert_eq!(*x_i, x.pow(&[i as u64, 0, 0, 0]))
        }

        let last_element = powers_of_x.last().unwrap();
        assert_eq!(*last_element, x.pow(&[degree, 0, 0, 0]))
    }
}

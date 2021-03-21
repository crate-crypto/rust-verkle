use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

/// Returns a vector of Frs of increasing powers of x from x^0 to x^d.
pub(crate) fn powers_of<F: PrimeField>(scalar: &F, max_degree: usize) -> Vec<F> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(F::one());
    for i in 1..=max_degree {
        powers.push(powers[i - 1] * scalar);
    }
    powers
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

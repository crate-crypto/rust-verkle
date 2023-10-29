use ark_ff::{Field, One};
use bandersnatch::Fr;
/// Computes the inner product between two scalar vectors
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    a.iter().zip(b.iter()).map(|(a, b)| *a * *b).sum()
}

pub fn powers_of(point: Fr, n: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(n);
    powers.push(Fr::one());

    for i in 1..n {
        powers.push(powers[i - 1] * point);
    }
    powers
}

#[test]
fn simple_vandemonde() {
    use ark_std::test_rng;
    use ark_std::UniformRand;
    let rand_fr = Fr::rand(&mut test_rng());
    let n = 100;
    let powers = powers_of(rand_fr, n);

    assert_eq!(powers[0], Fr::one());
    assert_eq!(powers[n - 1], rand_fr.pow(&[(n - 1) as u64]));

    for (i, power) in powers.into_iter().enumerate() {
        assert_eq!(power, rand_fr.pow(&[i as u64]))
    }
}

use super::CommitKeyLagrange;
use crate::kzg10::{errors::KZG10Error, opening_key::OpeningKey};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use rand_core::RngCore;
/// The Public Parameters can also be referred to as the Structured Reference String (SRS).
/// It is available to both the prover and verifier and allows the verifier to
/// efficiently verify and make claims about polynomials up to and including a configured degree.
#[derive(Debug)]
pub struct PublicParameters<E: PairingEngine> {
    /// Key used to generate proofs for composed circuits.
    pub commit_key: CommitKeyLagrange<E>,
    /// Key used to verify proofs for composed circuits.
    pub opening_key: OpeningKey<E>,
}

impl<E: PairingEngine> PublicParameters<E> {
    /// Do not use in production. Since the secret scalar will be known by whomever
    /// calls setup.
    /// Setup generates the public parameters using a random number generator.
    /// This method will in most cases be used for testing and exploration.
    /// In reality, a `Trusted party` or a `Multiparty Computation` will used to generate the SRS.
    /// Returns an error if the configured degree is less than one.
    pub fn setup<R: RngCore>(
        max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters<E>, KZG10Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(KZG10Error::DegreeIsZero.into());
        }

        // Generate the secret scalar beta
        let beta = E::Fr::rand(&mut rng);
        PublicParameters::setup_from_secret(max_degree, beta)
    }

    pub fn setup_from_secret(
        max_degree: usize,
        beta: E::Fr,
    ) -> Result<PublicParameters<E>, KZG10Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(KZG10Error::DegreeIsZero.into());
        }

        // Powers of G1 that will be used to commit to a specified polynomial
        let g = E::G1Projective::prime_subgroup_generator();

        // Compute beta*G2 element and stored cached elements for verifying multiple proofs.
        let h: E::G2Affine = E::G2Projective::prime_subgroup_generator().into();
        let beta_h: E::G2Affine = (h.mul(beta)).into();
        let prepared_h: E::G2Prepared = E::G2Prepared::from(h);
        let prepared_beta_h = E::G2Prepared::from(beta_h);

        let lagrange_srs = PublicParameters::<E>::compute_lagrange_srs(max_degree, beta, g);

        Ok(PublicParameters {
            commit_key: CommitKeyLagrange {
                lagrange_powers_of_g: lagrange_srs,
            },
            opening_key: OpeningKey::<E> {
                g: g.into(),
                h,
                beta_h,
                prepared_h,
                prepared_beta_h,
            },
        })
    }

    // This is _a_ quick way to _effectively_ compute the fft of the srs
    // Note that this method forces the committed polynomial to be of this exact degree.
    fn compute_lagrange_srs(
        max_degree: usize,
        beta: E::Fr,
        g: E::G1Projective,
    ) -> Vec<E::G1Affine> {
        use ark_ff::PrimeField;
        use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
        let domain: GeneralEvaluationDomain<E::Fr> =
            GeneralEvaluationDomain::new(max_degree).unwrap();

        // evaluate lagrange at the secret scalar
        let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(beta);

        // commit to each lagrange coefficient
        lagrange_coeffs
            .into_iter()
            .map(|l_s| g.mul(l_s.into_repr()).into())
            .collect()
    }

    // This will fft_g1
    // pub fn from_powers_of_g(powers_of_g : &[E::G1Affine]) -> Vec<E::G1Affine> {}

    pub fn dummy_setup(degree: usize) -> Result<PublicParameters<E>, KZG10Error> {
        use rand_core::OsRng;
        PublicParameters::setup(degree.next_power_of_two(), &mut OsRng)
    }

    pub fn commit_key(&self) -> &CommitKeyLagrange<E> {
        &self.commit_key
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::util;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
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

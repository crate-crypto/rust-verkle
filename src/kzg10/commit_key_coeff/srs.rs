use super::CommitKey;
use crate::kzg10::{errors::KZG10Error, OpeningKey};
use crate::util;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
/// The Public Parameters can also be referred to as the Structured Reference String (SRS).
/// It is available to both the prover and verifier and allows the verifier to
/// efficiently verify and make claims about polynomials up to and including a configured degree.
#[derive(Debug)]
pub struct PublicParameters<E: PairingEngine> {
    /// Key used to generate proofs for composed circuits.
    pub commit_key: CommitKey<E>,
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
    pub fn setup_from_secret(
        max_degree: usize,
        beta: E::Fr,
    ) -> Result<PublicParameters<E>, KZG10Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(KZG10Error::DegreeIsZero.into());
        }

        // Compute powers of beta up to and including beta^max_degree
        let powers_of_beta = util::powers_of(&beta, max_degree);

        // Powers of G1 that will be used to commit to a specified polynomial
        let g = E::G1Projective::prime_subgroup_generator();

        let powers_of_g: Vec<E::G1Projective> =
            util::slow_multiscalar_mul_single_base::<E>(&powers_of_beta, g);
        assert_eq!(powers_of_g.len(), max_degree + 1);

        // Normalise all projective points
        let normalised_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);

        // Compute beta*G2 element and stored cached elements for verifying multiple proofs.
        let h: E::G2Affine = E::G2Projective::prime_subgroup_generator().into();
        let beta_h: E::G2Affine = (h.mul(beta)).into();
        let prepared_h: E::G2Prepared = E::G2Prepared::from(h);
        let prepared_beta_h = E::G2Prepared::from(beta_h);

        Ok(PublicParameters {
            commit_key: CommitKey {
                powers_of_g: normalised_g,
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

    pub fn dummy_setup(degree: usize) -> Result<(CommitKey<E>, OpeningKey<E>), KZG10Error> {
        let srs = PublicParameters::setup_from_secret(
            degree.next_power_of_two(),
            E::Fr::from(8927347823478352432985u128),
        )
        .unwrap();
        Ok((srs.commit_key, srs.opening_key))
    }

    /// Max degree specifies the largest polynomial that this prover key can commit to.
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}

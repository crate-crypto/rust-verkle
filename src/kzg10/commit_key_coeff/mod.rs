use super::{errors::KZG10Error, Commitment, Committer, VerkleCommitter};
use crate::{transcript::TranscriptProtocol, util};
use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::{PrimeField, Zero};
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as Polynomial, GeneralEvaluationDomain};
use ark_poly::{EvaluationDomain, Polynomial as PolyTrait};

mod ruffini;
mod schemes;
pub mod srs;
/// CommitKey is used to commit to a polynomial which is bounded by the max_degree.
#[derive(Debug, Clone)]
pub struct CommitKey<E: PairingEngine> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
}

impl<E: PairingEngine> VerkleCommitter<E> for CommitKey<E> {
    fn commit_lagrange(&self, evaluations: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(evaluations.len()).unwrap();

        // Convert lagrange basis to coefficient basis
        // Then commit to the coefficient form
        let poly = Polynomial::from_coefficients_vec(domain.ifft(evaluations));
        return self.commit(&poly);
    }
}

impl<E: PairingEngine> Committer<E> for CommitKey<E> {
    fn commit_lagrange(&self, values: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        VerkleCommitter::commit_lagrange(self, values)
    }

    fn commit_coefficient(
        &self,
        polynomial: &Polynomial<E::Fr>,
    ) -> Result<Commitment<E>, KZG10Error> {
        // Check whether we can safely commit to this polynomial
        self.check_commit_degree_is_within_bounds(polynomial.degree())?;

        // Compute commitment
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &self.powers_of_g,
            &polynomial
                .coeffs
                .iter()
                .map(|c| c.into_repr())
                .collect::<Vec<_>>(),
        );
        Ok(Commitment::from_projective(commitment))
    }

    fn commit_lagrange_single(
        &self,
        value: E::Fr,
        index: usize,
    ) -> Result<Commitment<E>, KZG10Error> {
        todo!()
    }
}

impl<E: PairingEngine> CommitKey<E> {
    /// Returns the maximum degree polynomial that you can commit to.
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    pub(crate) fn check_commit_degree_is_within_bounds(
        &self,
        poly_degree: usize,
    ) -> Result<(), KZG10Error> {
        check_degree_is_within_bounds(self.max_degree(), poly_degree)
    }

    /// Commits to a polynomial returning the corresponding `Commitment`.
    ///
    /// Returns an error if the polynomial's degree is more than the max degree of the commit key.
    pub fn commit(&self, polynomial: &Polynomial<E::Fr>) -> Result<Commitment<E>, KZG10Error> {
        self.commit_coefficient(polynomial)
    }

    /// Computes a single witness for multiple polynomials at the same point, by taking
    /// a random linear combination of the individual witnesses.
    /// We apply the same optimisation mentioned in when computing each witness; removing f(z).
    pub(crate) fn compute_aggregate_witness(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        point: &E::Fr,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> Polynomial<E::Fr> {
        let challenge = transcript.challenge_scalar(b"aggregate_witness");

        let powers = util::powers_of::<E::Fr>(&challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial<E::Fr> = polynomials
            .iter()
            .zip(powers.iter())
            // XXX: upstream a mul by constant impl
            .map(|(poly, challenge)| poly * &Polynomial::from_coefficients_slice(&[*challenge]))
            // XXX: upstream a Sum impl
            .fold(Polynomial::zero(), |mut res, val| {
                res = &res + &val;
                res
            });
        ruffini::compute(&numerator, *point)
    }
}

/// Checks whether the polynomial we are committing to:
/// - Has zero degree
/// - Has a degree which is more than the max supported degree
///
///
/// Returns an error if any of the above conditions are true.
fn check_degree_is_within_bounds(max_degree: usize, poly_degree: usize) -> Result<(), KZG10Error> {
    if poly_degree == 0 {
        return Err(KZG10Error::PolynomialDegreeIsZero.into());
    }
    if poly_degree > max_degree {
        return Err(KZG10Error::PolynomialDegreeTooLarge.into());
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::kzg10::OpeningKey;

    use super::*;
    use crate::kzg10::commit_key_coeff::srs::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use rand_core::OsRng;

    use merlin::Transcript;

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(degree: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let secret = Fr::from(20u128);
        let srs = PublicParameters::setup_from_secret(degree.next_power_of_two(), secret).unwrap();
        (srs.commit_key, srs.opening_key)
    }
    #[test]
    fn test_basic_commit() {
        let degree = 25;
        let (proving_key, opening_key) = setup_test(degree);
        let point = <Fr as From<u64>>::from(10);

        let poly = Polynomial::rand(degree, &mut OsRng);
        let value = poly.evaluate(&point);

        let proof = proving_key
            .open_single(&poly, None, &value, &point)
            .unwrap();

        let ok = opening_key.check(point, proof);
        assert!(ok);
    }
    #[test]
    fn test_multi_point_compact() {
        let degree = 25;
        let (proving_key, opening_key) = setup_test(degree);
        let point_a = <Fr as From<u64>>::from(10);
        let point_b = <Fr as From<u64>>::from(20);

        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let value_a = poly_a.evaluate(&point_a);
        let commit_poly_a = proving_key.commit(&poly_a).unwrap();

        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let value_b = poly_b.evaluate(&point_b);
        let commit_poly_b = proving_key.commit(&poly_b).unwrap();

        let mut transcript = Transcript::new(b"dankrads_protocol");

        let proof = proving_key
            .open_multipoint(
                &[poly_a, poly_b],
                &[value_a, value_b],
                &[point_a, point_b],
                &mut transcript,
            )
            .unwrap();

        // Verifier
        let mut transcript = Transcript::new(b"dankrads_protocol");

        let ok = opening_key.check_multi_point(
            proof,
            &mut transcript,
            &[commit_poly_a, commit_poly_b],
            &[point_a, point_b],
            &[value_a, value_b],
        );
        assert!(ok);
    }

    #[test]
    fn test_batch_verification() {
        let degree = 25;
        let (proving_key, vk) = setup_test(degree);

        let point_a = <Fr as From<u64>>::from(10);
        let point_b = <Fr as From<u64>>::from(11);

        // Compute secret polynomial a
        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let value_a = poly_a.evaluate(&point_a);
        let proof_a = proving_key
            .open_single(&poly_a, None, &value_a, &point_a)
            .unwrap();
        assert!(vk.check(point_a, proof_a));

        // Compute secret polynomial b
        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let value_b = poly_b.evaluate(&point_b);
        let proof_b = proving_key
            .open_single(&poly_b, None, &value_b, &point_b)
            .unwrap();
        assert!(vk.check(point_b, proof_b));

        assert!(vk
            .batch_check(
                &[point_a, point_b],
                &[proof_a, proof_b],
                &mut Transcript::new(b""),
            )
            .is_ok());
    }
    #[test]
    fn test_aggregate_witness() {
        let max_degree = 27;
        let (proving_key, opening_key) = setup_test(max_degree);
        let point = <Fr as From<u64>>::from(10);

        // Committer's View
        let aggregated_proof = {
            // Compute secret polynomials and their evaluations
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point);

            let poly_b = Polynomial::rand(26 + 1, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point);

            proving_key
                .open_multiple(
                    &[poly_a, poly_b, poly_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point,
                    &mut Transcript::new(b"agg_flatten"),
                )
                .unwrap()
        };

        // Verifier's View
        let ok = {
            let flattened_proof = aggregated_proof.flatten(&mut Transcript::new(b"agg_flatten"));
            opening_key.check(point, flattened_proof)
        };

        assert!(ok);
    }

    #[test]
    fn test_batch_with_aggregation() {
        let max_degree = 28;
        let (proving_key, opening_key) = setup_test(max_degree);
        let point_a = <Fr as From<u64>>::from(10);
        let point_b = <Fr as From<u64>>::from(11);

        // Committer's View
        let (aggregated_proof, single_proof) = {
            // Compute secret polynomial and their evaluations
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point_a);

            let poly_b = Polynomial::rand(26, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point_a);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point_a);

            let poly_d = Polynomial::rand(28, &mut OsRng);
            let poly_d_eval = poly_d.evaluate(&point_b);

            let aggregated_proof = proving_key
                .open_multiple(
                    &[poly_a, poly_b, poly_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point_a,
                    &mut Transcript::new(b"agg_batch"),
                )
                .unwrap();

            let single_proof = proving_key
                .open_single(&poly_d, None, &poly_d_eval, &point_b)
                .unwrap();

            (aggregated_proof, single_proof)
        };

        // Verifier's View
        let ok = {
            let mut transcript = Transcript::new(b"agg_batch");
            let flattened_proof = aggregated_proof.flatten(&mut transcript);

            opening_key.batch_check(
                &[point_a, point_b],
                &[flattened_proof, single_proof],
                &mut transcript,
            )
        };

        assert!(ok.is_ok());
    }
}

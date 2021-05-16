use super::{lagrange::LagrangeBasis, CommitKeyLagrange};
use crate::{transcript::TranscriptProtocol, util};
use ark_ec::PairingEngine;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

impl<E: PairingEngine> CommitKeyLagrange<E> {
    pub(crate) fn compute_aggregate_witness_lagrange(
        &self,
        polynomials: &[Evaluations<E::Fr>],
        point: &E::Fr,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> LagrangeBasis<E> {
        let domain = polynomials.first().unwrap().domain();
        let domain_size = domain.size();

        let challenge = TranscriptProtocol::<E>::challenge_scalar(transcript, b"aggregate_witness");
        let powers = util::powers_of::<E::Fr>(&challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: LagrangeBasis<E> = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| LagrangeBasis::from(poly) * *challenge)
            .fold(LagrangeBasis::zero(domain_size), |mut res, val| {
                res = &res + &val;
                res
            });

        self.compute_lagrange_quotient(point, numerator)
    }

    pub(crate) fn compute_lagrange_quotient(
        &self,
        point: &E::Fr,
        poly: LagrangeBasis<E>,
    ) -> LagrangeBasis<E> {
        let domain = poly.0.domain();
        let domain_size = domain.size();

        let index = domain
            .elements()
            .into_iter()
            .position(|omega| omega == *point);

        let inv = Self::compute_inv(&poly.domain());

        match index {
            Some(index) => LagrangeBasis::divide_by_linear_vanishing(index, &poly, &inv),
            None => {
                let value = poly.evaluate_point_outside_domain(point);
                let mut q = vec![E::Fr::zero(); domain_size];
                for i in 0..domain_size {
                    q[i] = (poly.0.evals[i] - value) / (domain.element(i) - point)
                }
                let evaluations = Evaluations::from_vec_and_domain(q, domain);
                LagrangeBasis::from(evaluations)
            }
        }
    }

    pub(crate) fn compute_inv(domain: &GeneralEvaluationDomain<E::Fr>) -> Vec<E::Fr> {
        use ark_ff::One;
        let inv: Vec<_> = domain
            .elements()
            .into_iter()
            .enumerate()
            .map(|(index, x)| {
                if index == 0 {
                    return E::Fr::zero();
                }
                E::Fr::one() / (E::Fr::one() - x)
            })
            .collect();
        inv
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::kzg10::Committer;
    use crate::kzg10::MultiPointProver;
    use crate::kzg10::OpeningKey;
    use crate::kzg10::{
        commit_key_coeff::srs::PublicParameters,
        commit_key_lag::srs::PublicParameters as PublicParametersLag, CommitKey,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{
        univariate::DensePolynomial as Polynomial, GeneralEvaluationDomain,
        Polynomial as PolyTrait, UVPolynomial,
    };
    use merlin::Transcript;
    use rand_core::OsRng;

    // Creates a proving key and verifier key based on a specified degree
    fn setup_lagrange_srs(degree: usize) -> (CommitKeyLagrange<Bls12_381>, OpeningKey<Bls12_381>) {
        let secret = Fr::from(20u128);
        let srs =
            PublicParametersLag::setup_from_secret(degree.next_power_of_two(), secret).unwrap();
        (srs.commit_key, srs.opening_key)
    }
    fn setup_coeff_srs(degree: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let secret = Fr::from(20u128);
        let srs = PublicParameters::setup_from_secret(degree.next_power_of_two(), secret).unwrap();
        (srs.commit_key, srs.opening_key)
    }

    #[test]
    fn test_basic_commit_lagrange() {
        let degree = 31;
        let (lagrange_proving_key, opening_key) = setup_lagrange_srs(degree);
        let (coeff_proving_key, _) = setup_coeff_srs(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // coefficient form
        let poly = Polynomial::rand(degree, &mut OsRng);
        let value = poly.evaluate(&point);

        // Evaluation form
        let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly.coeffs), domain);

        assert_eq!(evaluations.evals[index], value);

        let proof_l = lagrange_proving_key
            .open_single_lagrange(&evaluations, None, &value, &point)
            .unwrap();
        let proof_c = coeff_proving_key
            .open_single(&poly, None, &value, &point)
            .unwrap();

        assert_eq!(
            proof_l.commitment_to_polynomial,
            proof_c.commitment_to_polynomial
        );
        assert_eq!(proof_l.commitment_to_witness, proof_c.commitment_to_witness);
        assert_eq!(proof_l.evaluated_point, proof_c.evaluated_point);
        assert_eq!(
            proof_l.commitment_to_polynomial,
            proof_c.commitment_to_polynomial
        );

        let ok = opening_key.check(point, proof_c);
        assert!(ok);
        let ok = opening_key.check(point, proof_l);
        assert!(ok);
    }
    #[test]
    fn test_divide_by_vanishing() {
        let degree = 25;
        let (proving_key, _) = setup_coeff_srs(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // coefficient form
        let poly = Polynomial::rand(degree, &mut OsRng);

        let expected_witness = proving_key.compute_single_witness(&poly, &point);

        // eval form
        let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly.coeffs), domain);
        let lagrange_poly = LagrangeBasis::<Bls12_381>::from(evaluations);
        let inv = CommitKeyLagrange::<Bls12_381>::compute_inv(&domain);
        let got_witness_lagrange =
            LagrangeBasis::divide_by_linear_vanishing(index, &lagrange_poly, &inv);
        let got_witness = got_witness_lagrange.interpolate();

        assert_eq!(got_witness, expected_witness);
    }

    #[test]
    fn test_multi_point_compact_lagrange() {
        let degree = 31;
        let (coeff_proving_key, _) = setup_coeff_srs(degree);
        let (lagrange_proving_key, opening_key) = setup_lagrange_srs(degree);

        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index_a = 5;
        let index_b = 6;
        let point_a = domain.element(index_a);
        let point_b = domain.element(index_b);

        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let evaluations_a = Evaluations::from_vec_and_domain(domain.fft(&poly_a), domain);

        let value_a = poly_a.evaluate(&point_a);
        let commit_poly_a = lagrange_proving_key
            .commit_lagrange(&evaluations_a.evals)
            .unwrap();
        let commit_poly_a_1 = coeff_proving_key.commit(&poly_a).unwrap();
        assert_eq!(commit_poly_a, commit_poly_a_1);

        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let evaluations_b = Evaluations::from_vec_and_domain(domain.fft(&poly_b), domain);

        let value_b = poly_b.evaluate(&point_b);
        let commit_poly_b = lagrange_proving_key
            .commit_lagrange(&evaluations_b.evals)
            .unwrap();
        let commit_poly_b_1 = coeff_proving_key.commit(&poly_b).unwrap();
        assert_eq!(commit_poly_b, commit_poly_b_1);

        let mut transcript = Transcript::new(b"dankrads_protocol");

        let proof_c = coeff_proving_key
            .open_multipoint(
                &[poly_a, poly_b],
                &[value_a, value_b],
                &[point_a, point_b],
                &mut transcript,
            )
            .unwrap();

        let mut transcript = Transcript::new(b"dankrads_protocol");
        let proof_l = lagrange_proving_key
            .open_multipoint_lagrange(
                &[evaluations_a, evaluations_b],
                None,
                &[value_a, value_b],
                &[point_a, point_b],
                &mut transcript,
            )
            .unwrap();

        assert_eq!(proof_l.sum_quotient, proof_c.sum_quotient);
        assert_eq!(proof_l.helper_evaluation, proof_c.helper_evaluation);
        assert_eq!(proof_l.aggregated_witness, proof_c.aggregated_witness);

        // Verifier
        let mut transcript = Transcript::new(b"dankrads_protocol");
        let ok = opening_key.check_multi_point(
            proof_c,
            &mut transcript,
            &[commit_poly_a, commit_poly_b],
            &[point_a, point_b],
            &[value_a, value_b],
        );
        assert!(ok);

        let mut transcript = Transcript::new(b"dankrads_protocol");
        let ok = opening_key.check_multi_point(
            proof_l,
            &mut transcript,
            &[commit_poly_a, commit_poly_b],
            &[point_a, point_b],
            &[value_a, value_b],
        );
        assert!(ok);
    }

    #[test]
    fn test_aggregate_witness_lagrange() {
        let degree = 31;
        let (lagrange_proving_key, opening_key) = setup_lagrange_srs(degree);
        let (coeff_proving_key, _) = setup_coeff_srs(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // Committer's View
        let aggregated_proof = {
            // Compute secret polynomials and their evaluations
            let poly_a = Polynomial::rand(degree, &mut OsRng);
            let evaluations_a = Evaluations::from_vec_and_domain(domain.fft(&poly_a), domain);
            let lagrange_poly = LagrangeBasis::<Bls12_381>::from(&evaluations_a);
            let poly_a_eval = lagrange_poly.0.evals[index];

            let poly_b = Polynomial::rand(degree, &mut OsRng);
            let evaluations_b =
                Evaluations::from_vec_and_domain(domain.fft(&poly_b.coeffs), domain);
            let lagrange_poly = LagrangeBasis::<Bls12_381>::from(&evaluations_b);
            let poly_b_eval = lagrange_poly.0.evals[index];

            let poly_c = Polynomial::rand(degree, &mut OsRng);
            let evaluations_c =
                Evaluations::from_vec_and_domain(domain.fft(&poly_c.coeffs), domain);
            let lagrange_poly = LagrangeBasis::<Bls12_381>::from(&evaluations_c);
            let poly_c_eval = lagrange_poly.0.evals[index];

            let l_proof = lagrange_proving_key
                .open_multiple_lagrange(
                    &[evaluations_a, evaluations_b, evaluations_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point,
                    &mut Transcript::new(b"agg_flatten"),
                )
                .unwrap();
            let c_proof = coeff_proving_key
                .open_multiple(
                    &[poly_a, poly_b, poly_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point,
                    &mut Transcript::new(b"agg_flatten"),
                )
                .unwrap();

            assert_eq!(&l_proof.evaluated_points, &c_proof.evaluated_points);
            assert_eq!(
                &l_proof.commitment_to_witness,
                &c_proof.commitment_to_witness
            );
            assert_eq!(
                &l_proof.commitments_to_polynomials,
                &c_proof.commitments_to_polynomials
            );

            l_proof
        };

        // Verifier's View
        let ok = {
            let flattened_proof = aggregated_proof.flatten(&mut Transcript::new(b"agg_flatten"));
            opening_key.check(point, flattened_proof)
        };

        assert!(ok);
    }
    #[test]
    fn test_compute_aggregate_witness_lagrange() {
        let degree = 31;
        let (lagrange_proving_key, opening_key) = setup_lagrange_srs(degree);
        let (coeff_proving_key, _) = setup_coeff_srs(degree);

        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // Compute secret polynomials and their evaluations
        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let evaluations_a = Evaluations::from_vec_and_domain(domain.fft(&poly_a.coeffs), domain);

        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let evaluations_b = Evaluations::from_vec_and_domain(domain.fft(&poly_b.coeffs), domain);

        let poly_c = Polynomial::rand(degree, &mut OsRng);
        let evaluations_c = Evaluations::from_vec_and_domain(domain.fft(&poly_c.coeffs), domain);

        let expected_quotient = coeff_proving_key.compute_aggregate_witness(
            &[poly_a, poly_b, poly_c],
            &point,
            &mut Transcript::new(b"agg_flatten"),
        );

        let got_quotient = lagrange_proving_key
            .compute_aggregate_witness_lagrange(
                &[evaluations_a, evaluations_b, evaluations_c],
                &point,
                &mut Transcript::new(b"agg_flatten"),
            )
            .interpolate();

        assert_eq!(expected_quotient, got_quotient)
    }
}

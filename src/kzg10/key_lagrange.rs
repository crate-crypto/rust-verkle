use super::{
    errors::KZG10Error, lagrange::LagrangeBasis, AggregateProof, AggregateProofMultiPoint,
    CommitKey, Commitment, Proof,
};
use crate::{transcript::TranscriptProtocol, util};
use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::{PrimeField, Zero};
use ark_poly::{EvaluationDomain, Evaluations};
use itertools::izip;
use merlin::Transcript;
use util::powers_of;

impl<E: PairingEngine> CommitKey<E> {
    pub fn commit_lagrange(&self, evaluations: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        // Check whether we can safely commit to this polynomial
        self.check_commit_degree_is_within_bounds(evaluations.len() - 1)?;

        // Compute commitment
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &self.lagrange_powers_of_g[0..evaluations.len()],
            &evaluations
                .iter()
                .map(|c| c.into_repr())
                .collect::<Vec<_>>(),
        );
        Ok(Commitment::from_projective(commitment))
    }

    pub(crate) fn compute_aggregate_witness_lagrange(
        &self,
        polynomials: &[Evaluations<E::Fr>],
        point: &E::Fr,
        transcript: &mut Transcript,
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

        match index {
            Some(index) => LagrangeBasis::divide_by_linear_vanishing(index, &poly),
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

    pub fn open_single_lagrange(
        &self,
        polynomial: &Evaluations<E::Fr>,
        poly_commitment: Option<Commitment<E>>,
        value: &E::Fr,
        point: &E::Fr,
    ) -> Result<Proof<E>, KZG10Error> {
        let lagrange_poly = LagrangeBasis::<E>::from(polynomial);
        let witness_poly =
            LagrangeBasis::divide_by_linear_vanishing_from_point(point, &lagrange_poly);

        let commitment_to_poly = match poly_commitment {
            Some(commitment) => commitment,
            None => self.commit_lagrange(&polynomial.evals)?,
        };

        Ok(Proof {
            commitment_to_witness: self.commit_lagrange(&witness_poly.values())?,
            evaluated_point: *value,
            commitment_to_polynomial: commitment_to_poly,
        })
    }

    pub fn open_multiple_lagrange(
        &self,
        polynomials: &[Evaluations<E::Fr>],
        evaluations: Vec<E::Fr>,
        point: &E::Fr,
        transcript: &mut Transcript,
    ) -> Result<AggregateProof<E>, KZG10Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(self.commit_lagrange(&poly.evals)?)
        }

        // Compute the aggregate witness for polynomials
        let witness_poly = self.compute_aggregate_witness_lagrange(polynomials, point, transcript);

        // Commit to witness polynomial
        let witness_commitment = self.commit_lagrange(&witness_poly.0.evals)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }

    pub fn open_multipoint_lagrange(
        &self,
        lagrange_polynomials: &[Evaluations<E::Fr>],
        evaluations: &[E::Fr],
        points: &[E::Fr], // These will be roots of unity
        transcript: &mut Transcript,
    ) -> Result<AggregateProofMultiPoint<E>, KZG10Error> {
        let domain_size = lagrange_polynomials.first().unwrap().domain().size();
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(lagrange_polynomials.len());
        for poly in lagrange_polynomials.iter() {
            let poly_commit = self.commit_lagrange(&poly.evals)?;

            TranscriptProtocol::<E>::append_point(transcript, b"f_x", &poly_commit.0);

            polynomial_commitments.push(poly_commit);
        }

        // compute the witness for each polynomial at their respective points
        let mut each_witness = Vec::new();

        for (poly, point, evaluation) in izip!(lagrange_polynomials, points, evaluations) {
            let lb = LagrangeBasis::<E>::from(poly).add_scalar(&-*evaluation); // XXX: Is this needed? It's not in single KZG
            let witness_poly =
                LagrangeBasis::<E>::divide_by_linear_vanishing_from_point(point, &lb);
            each_witness.push(witness_poly);
        }

        // Compute a new polynomial which sums together all of the witnesses for each polynomial
        // aggregate the witness polynomials to form the new polynomial that we want to run KZG10 on
        let challenge = TranscriptProtocol::<E>::challenge_scalar(transcript, b"r");
        let r_i = powers_of::<E::Fr>(&challenge, each_witness.len() - 1);

        let g_x: LagrangeBasis<E> = each_witness
            .iter()
            .zip(r_i.iter())
            .map(|(poly, challenge)| poly * challenge)
            .fold(LagrangeBasis::zero(domain_size), |mut res, val| {
                res = &res + &val;
                res
            });

        // Commit to to this poly_sum witness
        let d_comm = self.commit_lagrange(g_x.values())?;

        // Compute new point to evaluate g_x at
        let t = TranscriptProtocol::<E>::challenge_scalar(transcript, b"t");
        // compute the helper polynomial which will help the verifier compute g(t)
        //
        let mut denominator: Vec<_> = points.iter().map(|z_i| t - z_i).collect();
        ark_ff::batch_inversion(&mut denominator);
        let helper_coefficients: Vec<_> = r_i
            .into_iter()
            .zip(denominator)
            .map(|(r_i, den)| r_i * den)
            .collect();

        let h_x: LagrangeBasis<E> = helper_coefficients
            .iter()
            .zip(lagrange_polynomials.iter())
            .map(|(helper_scalars, poly)| &LagrangeBasis::from(poly) * helper_scalars)
            .fold(LagrangeBasis::zero(domain_size), |mut res, val| {
                res = &res + &val;
                res
            });

        // Evaluate both polynomials at the point `t`
        let h_t = h_x.evaluate_point_outside_domain(&t);
        let g_t = g_x.evaluate_point_outside_domain(&t);

        // We can now aggregate both proofs into an aggregate proof

        TranscriptProtocol::<E>::append_scalar(transcript, b"g_t", &g_t);
        TranscriptProtocol::<E>::append_scalar(transcript, b"h_t", &h_t);

        let sum_quotient = d_comm;
        let helper_evaluation = h_t;
        let aggregated_witness_poly =
            self.compute_aggregate_witness_lagrange(&[g_x.0, h_x.0], &t, transcript);
        let aggregated_witness = self.commit(&aggregated_witness_poly.interpolate())?;

        Ok(AggregateProofMultiPoint {
            sum_quotient,
            helper_evaluation,
            aggregated_witness,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::kzg10::OpeningKey;

    use super::super::srs::*;
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::{
        univariate::DensePolynomial as Polynomial, GeneralEvaluationDomain,
        Polynomial as PolyTrait, UVPolynomial,
    };
    use rand_core::OsRng;

    use merlin::Transcript;

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(degree: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let srs = PublicParameters::setup(degree.next_power_of_two(), &mut OsRng).unwrap();
        srs.trim(degree).unwrap()
    }

    #[test]
    fn test_basic_commit_lagrange() {
        let degree = 31;
        let (proving_key, opening_key) = setup_test(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // coefficient form
        let poly = Polynomial::rand(degree, &mut OsRng);
        let value = poly.evaluate(&point);

        // eval form
        let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly.coeffs), domain);

        assert_eq!(evaluations.evals[index], value);

        let proof_l = proving_key
            .open_single_lagrange(&evaluations, None, &value, &point)
            .unwrap();
        let proof_c = proving_key
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
        let (proving_key, _) = setup_test(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index = 5;
        let point = domain.element(index);

        // coefficient form
        let poly = Polynomial::rand(degree, &mut OsRng);

        let expected_witness = proving_key.compute_single_witness(&poly, &point);

        // eval form
        let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly.coeffs), domain);
        let lagrange_poly = LagrangeBasis::<Bls12_381>::from(evaluations);
        let got_witness_lagrange = LagrangeBasis::divide_by_linear_vanishing(index, &lagrange_poly);
        let got_witness = got_witness_lagrange.interpolate();

        assert_eq!(got_witness, expected_witness);
    }

    #[test]
    fn test_multi_point_compact_lagrange() {
        let degree = 31;
        let (proving_key, opening_key) = setup_test(degree);
        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();
        let index_a = 5;
        let index_b = 6;
        let point_a = domain.element(index_a);
        let point_b = domain.element(index_b);

        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let evaluations_a = Evaluations::from_vec_and_domain(domain.fft(&poly_a), domain);

        let value_a = poly_a.evaluate(&point_a);
        let commit_poly_a = proving_key.commit_lagrange(&evaluations_a.evals).unwrap();
        let commit_poly_a_1 = proving_key.commit(&poly_a).unwrap();
        assert_eq!(commit_poly_a, commit_poly_a_1);

        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let evaluations_b = Evaluations::from_vec_and_domain(domain.fft(&poly_b), domain);

        let value_b = poly_b.evaluate(&point_b);
        let commit_poly_b = proving_key.commit_lagrange(&evaluations_b.evals).unwrap();
        let commit_poly_b_1 = proving_key.commit(&poly_b).unwrap();
        assert_eq!(commit_poly_b, commit_poly_b_1);

        let mut transcript = Transcript::new(b"dankrads_protocol");

        let proof_c = proving_key
            .open_multipoint(
                &[poly_a, poly_b],
                &[value_a, value_b],
                &[point_a, point_b],
                &mut transcript,
            )
            .unwrap();

        let mut transcript = Transcript::new(b"dankrads_protocol");
        let proof_l = proving_key
            .open_multipoint_lagrange(
                &[evaluations_a, evaluations_b],
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
        let (proving_key, opening_key) = setup_test(degree);
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

            let l_proof = proving_key
                .open_multiple_lagrange(
                    &[evaluations_a, evaluations_b, evaluations_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point,
                    &mut Transcript::new(b"agg_flatten"),
                )
                .unwrap();
            let c_proof = proving_key
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
        let (proving_key, _) = setup_test(degree);

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

        let expected_quotient = proving_key.compute_aggregate_witness(
            &[poly_a, poly_b, poly_c],
            &point,
            &mut Transcript::new(b"agg_flatten"),
        );

        let got_quotient = proving_key
            .compute_aggregate_witness_lagrange(
                &[evaluations_a, evaluations_b, evaluations_c],
                &point,
                &mut Transcript::new(b"agg_flatten"),
            )
            .interpolate();

        assert_eq!(expected_quotient, got_quotient)
    }

    #[test]
    pub fn lagrange_commit_same_as_coefficient_commit() {
        use ark_ff::UniformRand;
        use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
        use rand_core::OsRng;
        let beta = Fr::rand(&mut OsRng);

        let pp = PublicParameters::<Bls12_381>::setup_from_secret(1024, beta).unwrap();

        let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(1024).unwrap();

        let poly_a = Polynomial::<Fr>::rand(1023, &mut OsRng);
        let evaluations = domain.fft(&poly_a);

        let expected_commitment = pp.commit_key.commit(&poly_a).unwrap();
        let got_commitment = pp.commit_key.commit_lagrange(&evaluations).unwrap();

        assert_eq!(&expected_commitment, &got_commitment);
    }
}

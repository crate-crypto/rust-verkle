use super::{
    errors::KZG10Error, ruffini, AggregateProof, AggregateProofMultiPoint, Commitment, Proof,
};
use crate::{transcript::TranscriptProtocol, util};
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial as Polynomial;
use ark_poly::Polynomial as PolyTrait;
use ark_poly::UVPolynomial;
use itertools::izip;
use merlin::Transcript;
use util::powers_of;

/// Opening Key is used to verify opening proofs made about a committed polynomial.
#[derive(Clone, Debug)]
pub struct OpeningKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: E::G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: E::G2Prepared,
}

/// CommitKey is used to commit to a polynomial which is bounded by the max_degree.
#[derive(Debug)]
pub struct CommitKey<E: PairingEngine> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    pub lagrange_powers_of_g: Vec<E::G1Affine>,
}

impl<E: PairingEngine> CommitKey<E> {
    /// Returns the maximum degree polynomial that you can commit to.
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    /// Truncates the commit key to a lower max degree.
    /// Returns an error if the truncated degree is zero or if the truncated degree
    /// is larger than the max degree of the commit key.
    pub fn truncate(&self, mut truncated_degree: usize) -> Result<CommitKey<E>, KZG10Error> {
        if truncated_degree == 1 {
            truncated_degree += 1;
        }
        // Check that the truncated degree is not zero
        if truncated_degree == 0 {
            return Err(KZG10Error::TruncatedDegreeIsZero.into());
        }

        // Check that max degree is less than truncated degree
        if truncated_degree > self.max_degree() {
            return Err(KZG10Error::TruncatedDegreeTooLarge.into());
        }

        let truncated_powers = Self {
            powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
            lagrange_powers_of_g: self.lagrange_powers_of_g[..=truncated_degree].to_vec(),
        };

        Ok(truncated_powers)
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

    /// For a given polynomial `p` and a point `z`, compute the witness
    /// for p(z) using Ruffini's method for simplicity.
    /// The Witness is the quotient of f(x) - f(z) / x-z.
    /// However we note that the quotient polynomial is invariant under the value f(z)
    /// ie. only the remainder changes. We can therefore compute the witness as f(x) / x - z
    /// and only use the remainder term f(z) during verification.
    pub fn compute_single_witness(
        &self,
        polynomial: &Polynomial<E::Fr>,
        point: &E::Fr,
    ) -> Polynomial<E::Fr> {
        // Computes `f(x) / x-z`, returning it as the witness poly
        ruffini::compute(polynomial, *point)
    }

    /// Computes a single witness for multiple polynomials at the same point, by taking
    /// a random linear combination of the individual witnesses.
    /// We apply the same optimisation mentioned in when computing each witness; removing f(z).
    pub(crate) fn compute_aggregate_witness(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        point: &E::Fr,
        transcript: &mut Transcript,
    ) -> Polynomial<E::Fr> {
        let challenge = TranscriptProtocol::<E>::challenge_scalar(transcript, b"aggregate_witness");

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

    /// Creates an opening proof that a polynomial `p` was correctly evaluated at p(z) and produced the value
    /// `v`. ie v = p(z).
    /// If the commitment is supplied, the algorithm will skip it
    /// Returns an error if the polynomials degree is too large.
    pub fn open_single(
        &self,
        polynomial: &Polynomial<E::Fr>,
        poly_commitment: Option<Commitment<E>>,
        value: &E::Fr,
        point: &E::Fr,
    ) -> Result<Proof<E>, KZG10Error> {
        let witness_poly = self.compute_single_witness(polynomial, point);

        let commitment_to_poly = match poly_commitment {
            Some(commitment) => commitment,
            None => self.commit(polynomial)?,
        };

        Ok(Proof {
            commitment_to_witness: self.commit(&witness_poly)?,
            evaluated_point: *value,
            commitment_to_polynomial: commitment_to_poly,
        })
    }

    pub fn open_single_from_commitment(
        &self,
        polynomial: &Polynomial<E::Fr>,
        value: &E::Fr,
        point: &E::Fr,
    ) -> Result<Proof<E>, KZG10Error> {
        let witness_poly = self.compute_single_witness(polynomial, point);
        Ok(Proof {
            commitment_to_witness: self.commit(&witness_poly)?,
            evaluated_point: *value,
            commitment_to_polynomial: self.commit(polynomial)?,
        })
    }

    /// Creates an opening proof that multiple polynomials were evaluated at the same point
    /// and that each evaluation produced the correct evaluation point.
    /// Returns an error if any of the polynomial's degrees are too large.
    pub fn open_multiple(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        evaluations: Vec<E::Fr>,
        point: &E::Fr,
        transcript: &mut Transcript,
    ) -> Result<AggregateProof<E>, KZG10Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(self.commit(poly)?)
        }

        // Compute the aggregate witness for polynomials
        let witness_poly = self.compute_aggregate_witness(polynomials, point, transcript);

        // Commit to witness polynomial
        let witness_commitment = self.commit(&witness_poly)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }

    /// Creates an opening proof that multiple polynomials were evaluated at the different points
    /// XXX: bikeshed names
    pub fn open_multipoint(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        evaluations: &[E::Fr],
        points: &[E::Fr],
        transcript: &mut Transcript,
    ) -> Result<AggregateProofMultiPoint<E>, KZG10Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            let poly_commit = self.commit(poly)?;

            TranscriptProtocol::<E>::append_point(transcript, b"f_x", &poly_commit.0);

            polynomial_commitments.push(poly_commit);
        }

        // compute the witness for each polynomial at their respective points
        let mut each_witness = Vec::new();

        for (poly, point, evaluation) in izip!(polynomials, points, evaluations) {
            let poly = poly - &Polynomial::from_coefficients_slice(&[*evaluation]); // XXX: Is this needed? It's not in single KZG
            let witness_poly = self.compute_single_witness(&poly, point);
            each_witness.push(witness_poly);
        }

        // Compute a new polynomial which sums together all of the witnesses for each polynomial
        // aggregate the witness polynomials to form the new polynomial that we want to run KZG10 on
        let challenge = TranscriptProtocol::<E>::challenge_scalar(transcript, b"r");
        let r_i = powers_of::<E::Fr>(&challenge, each_witness.len() - 1);

        let g_x: Polynomial<E::Fr> = each_witness
            .iter()
            .zip(r_i.iter())
            .map(|(poly, challenge)| poly * &Polynomial::from_coefficients_slice(&[*challenge]))
            .fold(Polynomial::zero(), |mut res, val| {
                res = &res + &val;
                res
            });

        // Commit to to this poly_sum witness
        let d_comm = self.commit(&g_x)?;

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

        let h_x: Polynomial<E::Fr> = helper_coefficients
            .iter()
            .zip(polynomials.iter())
            .map(|(helper_scalars, poly)| {
                poly * &Polynomial::from_coefficients_slice(&[*helper_scalars])
            })
            .fold(Polynomial::zero(), |mut res, val| {
                res = &res + &val;
                res
            });

        // Evaluate both polynomials at the point `t`
        let h_t = h_x.evaluate(&t);
        let g_t = g_x.evaluate(&t);

        // We can now aggregate both proofs into an aggregate proof

        TranscriptProtocol::<E>::append_scalar(transcript, b"g_t", &g_t);
        TranscriptProtocol::<E>::append_scalar(transcript, b"h_t", &h_t);

        let sum_quotient = d_comm;
        let helper_evaluation = h_t;
        let aggregated_witness_poly = self.compute_aggregate_witness(&[g_x, h_x], &t, transcript);
        let aggregated_witness = self.commit(&aggregated_witness_poly)?;

        Ok(AggregateProofMultiPoint {
            sum_quotient,
            helper_evaluation,
            aggregated_witness,
        })
    }
}

impl<E: PairingEngine> OpeningKey<E> {
    /// Checks that a polynomial `p` was evaluated at a point `z` and returned the value specified `v`.
    /// ie. v = p(z).
    pub fn check(&self, point: E::Fr, proof: Proof<E>) -> bool {
        let inner_a: E::G1Affine = (proof.commitment_to_polynomial.0.into_projective()
            - &(self.g.mul(proof.evaluated_point.into_repr())))
            .into();

        let inner_b: E::G2Affine =
            (self.beta_h.into_projective() - &(self.h.mul(point.into_repr()))).into();
        let prepared_inner_b = E::G2Prepared::from(-inner_b);

        let pairing = E::product_of_pairings(&[
            (inner_a.into(), self.prepared_h.clone()),
            (
                proof.commitment_to_witness.0.into(),
                prepared_inner_b.clone(),
            ),
        ]);

        pairing == E::Fqk::one()
    }

    /// Checks whether a batch of polynomials evaluated at different points, returned their specified value.
    pub fn batch_check(
        &self,
        points: &[E::Fr],
        proofs: &[Proof<E>],
        transcript: &mut Transcript,
    ) -> Result<(), KZG10Error> {
        let mut total_c = E::G1Projective::zero();
        let mut total_w = E::G1Projective::zero();

        let challenge = TranscriptProtocol::<E>::challenge_scalar(transcript, b"batch"); // XXX: Verifier can add their own randomness at this point
        let powers = util::powers_of(&challenge, proofs.len() - 1);
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::Fr::zero();

        for ((proof, challenge), point) in proofs.iter().zip(powers).zip(points) {
            let mut c = proof.commitment_to_polynomial.0.into_projective();
            let w = proof.commitment_to_witness.0;
            c += &w.mul(point.into_repr());
            g_multiplier += &(challenge * &proof.evaluated_point);

            total_c += &c.mul(challenge.into_repr());
            total_w += &w.mul(challenge.into_repr());
        }
        total_c -= &self.g.mul(g_multiplier.into_repr());

        let affine_total_w = E::G1Affine::from(-total_w);
        let affine_total_c = E::G1Affine::from(total_c);

        let pairing = E::product_of_pairings(&[
            (affine_total_w.into(), self.prepared_beta_h.clone()),
            (affine_total_c.into(), self.prepared_h.clone()),
        ]);

        if pairing != E::Fqk::one() {
            return Err(KZG10Error::PairingCheckFailure.into());
        };
        Ok(())
    }

    /// Takes the commitments to the polynomials
    /// and their evaluated points
    pub fn check_multi_point<T: TranscriptProtocol<E>>(
        &self,
        proof: AggregateProofMultiPoint<E>,
        transcript: &mut T,
        commitments: &[Commitment<E>],
        evaluation_points: &[E::Fr], // the `z` in y=p(z)
        evaluated_points: &[E::Fr],  // the `y` in y=p(z)
    ) -> bool {
        // Add all commitments to the transcript
        for comm in commitments.iter() {
            transcript.append_point(b"f_x", &comm.0);
        }

        // Compute challenges
        let r = TranscriptProtocol::<E>::challenge_scalar(transcript, b"r");
        let r_i = crate::util::powers_of_iter(r, commitments.len());
        let t = TranscriptProtocol::<E>::challenge_scalar(transcript, b"t");

        // compute g_2(t)
        let mut denominator: Vec<_> = evaluation_points.iter().map(|z_i| t - z_i).collect();
        ark_ff::batch_inversion(&mut denominator);
        let ri_di: Vec<_> = r_i.zip(denominator).map(|(r_i, d_i)| r_i * d_i).collect();
        let g_2_t: E::Fr = ri_di
            .iter()
            .zip(evaluated_points)
            .map(|(rd, y_i)| *rd * y_i)
            .sum();

        // Compute E
        let e_point: E::G1Projective = ri_di
            .into_iter()
            .zip(commitments)
            .map(|(rd, ci)| ci.0.mul(rd.into_repr()))
            .sum();
        let e_comm = Commitment::<E>::from_projective(e_point);

        // Compute y and w
        // y = h(t) -> prover provided
        // w = y - g_2(t)
        let y = proof.helper_evaluation;
        let w = y - g_2_t;

        // Add w and y to transcript
        TranscriptProtocol::<E>::append_scalar(transcript, b"g_t", &w);
        TranscriptProtocol::<E>::append_scalar(transcript, b"h_t", &y);

        // Compute aggregate proof. `q` is computed internally
        let mut agg_proof = AggregateProof::with_witness(proof.aggregated_witness);
        agg_proof.add_part((w, proof.sum_quotient));
        agg_proof.add_part((y, e_comm));
        let proof = agg_proof.flatten(transcript);

        self.check(t, proof)
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
    use super::super::srs::*;
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use rand_core::OsRng;

    use merlin::Transcript;

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(degree: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let srs = PublicParameters::setup(degree.next_power_of_two(), &mut OsRng).unwrap();
        srs.trim(degree).unwrap()
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

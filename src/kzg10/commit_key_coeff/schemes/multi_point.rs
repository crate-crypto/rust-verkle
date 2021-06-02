use crate::kzg10::commit_key_coeff::CommitKey;
use crate::{
    kzg10::{errors::KZG10Error, proof::AggregateProofMultiPoint, Commitment, MultiPointProver},
    transcript::TranscriptProtocol,
    util::powers_of,
};
use ark_ec::PairingEngine;
use ark_ff::Zero;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial as PolyTrait, UVPolynomial,
};
use itertools::izip;

impl<E: PairingEngine> CommitKey<E> {
    /// Creates an opening proof that multiple polynomials were evaluated at the different points
    /// XXX: bikeshed names
    pub fn open_multipoint(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        evaluations: &[E::Fr],
        points: &[E::Fr],
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> Result<AggregateProofMultiPoint<E>, KZG10Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            let poly_commit = self.commit(poly)?;

            TranscriptProtocol::<E>::append_point(transcript, b"f_x", &poly_commit.0);

            polynomial_commitments.push(poly_commit);
        }

        for point in points {
            transcript.append_scalar(b"value", point)
        }

        for point in evaluations {
            transcript.append_scalar(b"eval", point)
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
        let r = TranscriptProtocol::<E>::challenge_scalar(transcript, b"r");
        let r_i = powers_of::<E::Fr>(&r, each_witness.len() - 1);

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

        transcript.append_scalar(b"r", &r);
        transcript.append_point(b"D", &d_comm.0);

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

        let E = self.commit(&h_x)?;

        // Evaluate both polynomials at the point `t`
        let h_t = h_x.evaluate(&t);
        let g_t = g_x.evaluate(&t);

        transcript.append_point(b"E", &E.0);
        transcript.append_point(b"d_comm", &d_comm.0);
        transcript.append_scalar(b"h_t", &h_t);
        transcript.append_scalar(b"g_t", &g_t);

        // We can now aggregate both proofs into an aggregate proof

        let sum_quotient = d_comm;
        let helper_evaluation = h_t;
        let aggregated_witness_poly = self.compute_aggregate_witness(&[h_x, g_x], &t, transcript);
        let aggregated_witness = self.commit(&aggregated_witness_poly)?;

        Ok(AggregateProofMultiPoint {
            sum_quotient,
            helper_evaluation,
            aggregated_witness,
        })
    }
}

// Open multiple polynomials at multiple points
impl<E: PairingEngine, T: TranscriptProtocol<E>> MultiPointProver<E, T> for CommitKey<E> {
    fn open_multipoint_lagrange(
        &self,
        lagrange_polynomials: Vec<Vec<E::Fr>>,
        _poly_commitments: Option<&[Commitment<E>]>,
        evaluations: &[E::Fr],
        points: &[E::Fr], // These will be roots of unity
        transcript: &mut T,
    ) -> Result<AggregateProofMultiPoint<E>, KZG10Error> {
        let polynomial_degree = lagrange_polynomials.first().unwrap().len();
        let domain = GeneralEvaluationDomain::<E::Fr>::new(polynomial_degree).unwrap();

        // IFFT all of the evaluations
        let mut polynomials = Vec::new();
        for lag_poly in lagrange_polynomials.into_iter() {
            let coeffs = domain.ifft(&lag_poly);
            let poly = Polynomial::from_coefficients_vec(coeffs);
            polynomials.push(poly)
        }
        self.open_multipoint(&polynomials, evaluations, points, transcript)
    }
}

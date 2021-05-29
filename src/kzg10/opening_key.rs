use crate::{transcript::TranscriptProtocol, util};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use merlin::Transcript;

use super::{
    errors::KZG10Error, proof::AggregateProof, proof::AggregateProofMultiPoint, proof::Proof,
    Commitment,
};

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

        for point in evaluation_points {
            transcript.append_scalar(b"value", point)
        }

        for point in evaluated_points {
            transcript.append_scalar(b"eval", point)
        }

        // Compute challenges
        let r = TranscriptProtocol::<E>::challenge_scalar(transcript, b"r");
        let r_i = crate::util::powers_of_iter(r, commitments.len());

        transcript.append_scalar(b"r", &r);
        transcript.append_point(b"D", &proof.sum_quotient.0);

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
        transcript.append_point(b"E", &e_comm.0);
        transcript.append_point(b"d_comm", &proof.sum_quotient.0);
        transcript.append_scalar(b"h_t", &y);
        transcript.append_scalar(b"g_t", &w);

        // Compute aggregate proof. `q` is computed internally
        let mut agg_proof = AggregateProof::with_witness(proof.aggregated_witness);
        agg_proof.add_part((y, e_comm));
        agg_proof.add_part((w, proof.sum_quotient));
        let proof = agg_proof.flatten(transcript);

        self.check(t, proof)
    }
}

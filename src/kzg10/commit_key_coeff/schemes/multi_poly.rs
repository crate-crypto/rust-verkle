use crate::kzg10::commit_key_coeff::CommitKey;
use crate::{
    kzg10::{errors::KZG10Error, proof::AggregateProof},
    transcript::TranscriptProtocol,
};
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial as Polynomial;

// Creates a proof that multiple polynomials were evaluated at the same point
impl<E: PairingEngine> CommitKey<E> {
    /// Creates an opening proof that multiple polynomials were evaluated at the same point
    /// and that each evaluation produced the correct evaluation point.
    /// Returns an error if any of the polynomial's degrees are too large.
    pub fn open_multiple(
        &self,
        polynomials: &[Polynomial<E::Fr>],
        evaluations: Vec<E::Fr>,
        point: &E::Fr,
        transcript: &mut dyn TranscriptProtocol<E>,
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
}

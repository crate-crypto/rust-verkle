use ark_ec::PairingEngine;
use ark_poly::Evaluations;

use crate::{
    kzg10::{errors::KZG10Error, proof::AggregateProof, CommitKeyLagrange, LagrangeCommitter},
    transcript::TranscriptProtocol,
};
use ark_poly::EvaluationDomain;
use ark_poly::GeneralEvaluationDomain;
impl<E: PairingEngine> CommitKeyLagrange<E> {
    pub fn open_multiple_lagrange(
        &self,
        polynomials: &[Evaluations<E::Fr>],
        evaluations: Vec<E::Fr>,
        point: &E::Fr,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> Result<AggregateProof<E>, KZG10Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(self.commit_lagrange(&poly.evals)?)
        }

        let domain = polynomials.first().unwrap().domain();
        let domain_elements: Vec<_> = domain.elements().collect();
        // Compute the aggregate witness for polynomials
        let witness_poly = self.compute_aggregate_witness_lagrange(
            polynomials.into_iter().map(|x| x.evals.clone()).collect(),
            point,
            transcript,
            &domain_elements,
        );

        // Commit to witness polynomial
        let witness_commitment = self.commit_lagrange(&witness_poly.0)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }
}

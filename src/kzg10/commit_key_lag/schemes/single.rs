use ark_ec::PairingEngine;
use ark_poly::{Evaluations, GeneralEvaluationDomain};

use crate::kzg10::{
    commit_key_lag::lagrange::LagrangeBasis, errors::KZG10Error, proof::Proof, CommitKeyLagrange,
    Commitment, LagrangeCommitter,
};
use ark_poly::EvaluationDomain;

impl<E: PairingEngine> CommitKeyLagrange<E> {
    pub fn open_single_lagrange(
        &self,
        polynomial: &Evaluations<E::Fr>,
        poly_commitment: Option<Commitment<E>>,
        value: &E::Fr,
        point: &E::Fr,
    ) -> Result<Proof<E>, KZG10Error> {
        let domain_elements: Vec<_> = polynomial.domain().elements().collect();
        let inv = Self::compute_inv(&domain_elements);
        let witness_poly = LagrangeBasis::<E>::divide_by_linear_vanishing_from_point(
            point,
            &polynomial.evals,
            &inv,
            &domain_elements,
        );

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
}

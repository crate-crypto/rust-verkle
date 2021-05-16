use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};

use super::{errors::KZG10Error, Commitment, Committer, VerkleCommitter};
pub mod key_lagrange;
pub mod lagrange;
mod schemes;
pub mod srs;
#[derive(Debug, Clone)]
pub struct CommitKeyLagrange<E: PairingEngine> {
    /// Group elements of the form `{ \beta^i L_i }`, where `i` ranges from 0 to `degree`.
    /// Where L_i is the i'th lagrange polynomial
    pub lagrange_powers_of_g: Vec<E::G1Affine>,
}
impl<E: PairingEngine> VerkleCommitter<E> for CommitKeyLagrange<E> {
    fn commit_lagrange(&self, evaluations: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
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
}

impl<E: PairingEngine> Committer<E> for CommitKeyLagrange<E> {
    fn commit_lagrange(&self, values: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        VerkleCommitter::commit_lagrange(self, values)
    }

    fn commit_coefficient(
        &self,
        polynomial: &ark_poly::univariate::DensePolynomial<E::Fr>,
    ) -> Result<Commitment<E>, KZG10Error> {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(polynomial.degree()).unwrap();
        let evals = domain.fft(&polynomial);
        VerkleCommitter::commit_lagrange(self, &evals)
    }

    fn commit_lagrange_single(
        &self,
        value: E::Fr,
        index: usize,
    ) -> Result<Commitment<E>, KZG10Error> {
        todo!()
    }
}

pub mod commit_key_coeff;
pub mod commit_key_lag;
pub mod commitment;
pub mod errors;
pub mod opening_key;
pub mod precomp_lagrange;
pub mod proof;

use crate::transcript::TranscriptProtocol;
use ark_ec::PairingEngine;
use ark_poly::Evaluations;
// XXX: Remove this later on, we don't want to make the default API be coeff form
// or create a better namespace for it
pub use commit_key_coeff::srs::PublicParameters;
pub use commit_key_lag::CommitKeyLagrange;
pub use commitment::Commitment;
pub use opening_key::OpeningKey;

use self::errors::KZG10Error;

pub trait VerkleCommitter<E: PairingEngine> {
    fn commit_lagrange(&self, values: &[E::Fr]) -> Result<Commitment<E>, errors::KZG10Error>;
}
pub trait MultiPointProver<E: PairingEngine, T: TranscriptProtocol<E>> {
    fn open_multipoint_lagrange(
        &self,
        lagrange_polynomials: &[Evaluations<E::Fr>],
        poly_commitments: Option<&[Commitment<E>]>,
        evaluations: &[E::Fr],
        points: &[E::Fr], // These will be roots of unity
        transcript: &mut T,
    ) -> Result<proof::AggregateProofMultiPoint<E>, KZG10Error>;
}

pub trait Committer<E: PairingEngine> {
    fn commit_lagrange(&self, values: &[E::Fr]) -> Result<Commitment<E>, errors::KZG10Error>;
    fn commit_coefficient(
        &self,
        polynomial: &ark_poly::univariate::DensePolynomial<E::Fr>,
    ) -> Result<Commitment<E>, errors::KZG10Error>;
    fn commit_lagrange_single(
        &self,
        value: E::Fr,
        index: usize,
    ) -> Result<Commitment<E>, errors::KZG10Error>;
}

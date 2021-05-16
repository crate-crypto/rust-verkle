use crate::kzg10::commit_key_coeff::{ruffini, CommitKey};
use crate::kzg10::{errors::KZG10Error, proof::Proof, Commitment};
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial as Polynomial;

// Open a single polynomial at a single point.
// This is the original KZG

impl<E: PairingEngine> CommitKey<E> {
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
}

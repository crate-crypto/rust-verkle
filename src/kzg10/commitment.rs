use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_ff::Zero;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Holds a commitment to a polynomial in a form of a `G1Affine` Bls12_381 point.
pub struct Commitment<E: PairingEngine>(
    /// The commitment is a group element.
    pub E::G1Affine,
);

impl<E: PairingEngine> Commitment<E> {
    /// Builds a `Commitment` from a Bls12_381 `G1Projective` point.
    pub fn from_projective(g: E::G1Projective) -> Self {
        Self(g.into())
    }
    /// Builds a `Commitment` from a Bls12_381 `G1Affine` point.
    pub fn from_affine(g: E::G1Affine) -> Self {
        Self(g)
    }
    /// Builds an empty `Commitment` which is equivalent to the
    /// `G1Affine` identity point in Bls12_381.
    pub fn empty() -> Self {
        Commitment(E::G1Affine::zero())
    }
    // XXX: Remove empty once refactoring is completed
    pub fn identity() -> Self {
        Self::empty()
    }
    /// Returns the prime subgroup generator for `E`
    pub fn generator() -> E::G1Affine {
        use ark_ec::AffineCurve;
        E::G1Affine::prime_subgroup_generator()
    }

    pub fn mul_generator(x: E::Fr) -> Commitment<E> {
        use ark_ec::AffineCurve;
        let result = Commitment::<E>::generator().mul(x);
        Commitment::from_projective(result)
    }
}

impl<E: PairingEngine> Default for Commitment<E> {
    fn default() -> Self {
        Commitment::empty()
    }
}

use crate::point_encoding::serialize_g1;
impl Commitment<Bls12_381> {
    pub fn compress(&self) -> [u8; 48] {
        serialize_g1(&self.0)
    }
}

impl<E: PairingEngine> std::ops::Add for Commitment<E> {
    type Output = Commitment<E>;

    fn add(self, rhs: Self) -> Self::Output {
        Commitment(self.0 + rhs.0)
    }
}

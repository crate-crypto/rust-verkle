use crate::{hash::Hash, kzg10::Commitment};
use crate::{HashFunction, *};
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::AffineCurve;
use ark_ff::to_bytes;

/// VerkleCommitment is a convenience wrapper around a KZG10 commitment
/// It is not strictly needed as we can use Option with KZG10
#[derive(Debug, Copy, Clone)]
pub enum VerkleCommitment {
    NotComputed,
    Computed(kzg10::Commitment<Bls12_381>),
}
impl VerkleCommitment {
    pub fn identity() -> VerkleCommitment {
        VerkleCommitment::Computed(Commitment::empty())
    }

    pub fn is_computed(&self) -> bool {
        if let VerkleCommitment::Computed(_) = self {
            return true;
        }
        false
    }

    fn generator() -> G1Affine {
        G1Affine::prime_subgroup_generator()
    }

    // This function panics, if the commitment is empty
    pub fn as_repr(&self) -> &G1Affine {
        if let VerkleCommitment::Computed(comm) = self {
            return &comm.0;
        }
        unreachable!("point is not computed")
    }

    pub fn mul_generator(x: Fr) -> VerkleCommitment {
        let result = VerkleCommitment::generator().mul(x);
        VerkleCommitment::Computed(Commitment::from_projective(result))
    }

    /// Converts a Commitment to a Hash object
    pub fn to_hash(&self) -> Hash {
        let compressed_commitment = self.to_bytes();

        let mut hasher = HashFunction::new();
        hasher.update(compressed_commitment);

        let res: [u8; 32] = hasher.finalize().into();

        Hash::Computed(res)
    }

    // XXX: There should be a compress/as_bytes function somewhere in arkworks for
    // points, whose output could be tied to the lifetime of the G1Affine point
    //
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerkleCommitment::NotComputed => {
                panic!("cannot compress commitment, as it is not computed")
            }
            VerkleCommitment::Computed(point) => to_bytes!(point.0).unwrap(),
        }
    }
}

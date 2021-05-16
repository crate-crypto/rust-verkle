use crate::hash::{Hash, Hashable};
use crate::{HashFunction, *};
use ark_bls12_381::Bls12_381;

pub type VerkleCommitment = kzg10::Commitment<Bls12_381>;

impl Hashable for VerkleCommitment {
    fn to_hash(&self) -> Hash {
        let compressed_commitment = self.compress();

        let mut hasher = HashFunction::new();
        hasher.update(compressed_commitment);

        let res: [u8; 32] = hasher.finalize().into();

        Hash(res)
    }
}

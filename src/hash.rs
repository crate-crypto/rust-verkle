use crate::trie::node::leaf::LeafNode;
use crate::{HashFunction, *};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use std::convert::TryInto;

pub trait Hashable {
    fn to_hash(&self) -> Hash;
}

#[derive(Debug, Clone, Copy)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn zero() -> Hash {
        Hash([0u8; 32])
    }

    /// Converts a vector into an array
    /// This method will panic, the vector's length
    /// is not equal to the array's
    pub fn from_vec(v: Vec<u8>) -> Hash {
        Hash(v.try_into().unwrap())
    }

    /// Converts a vector into an array
    /// This method will panic, the vector's length
    /// is not equal to the array's
    pub fn from_leaf(leaf: &LeafNode) -> Hash {
        let mut hasher = HashFunction::new();

        hasher.update(leaf.as_bytes());

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Hash(res)
    }

    pub fn to_fr(&self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.0)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

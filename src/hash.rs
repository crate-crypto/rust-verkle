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
        Hash::from_bytes(&leaf.to_bytes())
    }

    pub fn from_value(val: &Value) -> Hash {
        Hash::from_bytes(val.as_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Hash {
        let mut hasher = HashFunction::new();

        hasher.update(bytes);

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Hash(res)
    }

    pub fn to_fr(&self) -> Fr {
        let mut hash = self.0.to_vec();
        hash[31] &= (2u8.pow(6) - 1);
        Fr::from_le_bytes_mod_order(&hash)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

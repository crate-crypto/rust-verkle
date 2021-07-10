use std::collections::BTreeMap;

use crate::{Hash, Key, Value, VerkleCommitment};

use super::errors::NodeError;

/// A Leaf node is a node which stores a value under a specific key.
///
/// It's main functionality is to get the value under it's key
///
#[derive(Debug, Copy, Clone)]
pub struct LeafNode {
    pub(crate) key: Key,
    pub(crate) value: Value,
    commitment: Option<VerkleCommitment>,
}

impl LeafNode {
    pub fn new(key: Key, value: Value) -> LeafNode {
        Self {
            key,
            value,
            commitment: None,
        }
    }
    pub fn get(&self, key: &Key) -> Result<&Value, NodeError> {
        if &self.key != key {
            Err(NodeError::LeafNodeKeyMismatch)
        } else {
            Ok(&self.value)
        }
    }

    pub fn hash(&self) -> Hash {
        Hash::from_leaf(self)
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        [self.key.as_bytes(), self.value.as_bytes()].concat()
    }
}
#[derive(Debug, Copy, Clone)]
pub struct LeafExtensionNode {
    // This key is never exposed directly,
    // we only ever use it as a stem
    key: Key,
    commitment: Option<VerkleCommitment>,
}

impl LeafExtensionNode {
    pub fn new(key: Key, value: Value) -> LeafExtensionNode {
        // We save the key and compute the stem on the fly
        // When we need it.
        //
        // - When hashing stem + value
        // -

        // Compute the index to store this value

        Self {
            key,
            commitment: None,
        }
    }

    // fn slot(key : Key)
    // pub fn get(&self, key: &Key) -> Result<&Value, NodeError> {
    //     // First check
    //     if &self.key != key {
    //         Err(NodeError::LeafNodeKeyMismatch)
    //     } else {
    //         Ok(&self.value)
    //     }
    // }

    pub fn hash(&self) -> Hash {
        todo!()
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    // pub fn as_bytes(&self) -> Vec<u8> {
    //     [self.key.as_bytes(), self.value.as_bytes()].concat()
    // }
}

#[cfg(test)]
mod interop {
    use super::*;
    #[test]
    fn key0val0() {
        let key0 = Key::one();
        let val0 = Value::zero();
        let leaf = LeafNode::new(key0, val0);
        let hash = leaf.hash().to_hex();
        assert_eq!(
            "58e8f2a1f78f0a591feb75aebecaaa81076e4290894b1c445cc32953604db089",
            hash
        )
    }
    #[test]
    fn hash_fr() {
        let key0 = Key::one();
        let val0 = Value::one();
        let leaf = LeafNode::new(key0, val0);
        use num_bigint::BigUint;
        use num_traits::Num;
        // let hash = dbg!(leaf.hash().to_hex());
        let mut bytes = leaf.hash().0;
        bytes.reverse();
        let hex_str = dbg!(hex::encode(bytes));
        let hash = dbg!(leaf.hash().to_fr().to_string());
        let b = BigUint::from_str_radix(&hex_str, 16).unwrap();
        dbg!(b.to_str_radix(10));
    }
    #[test]
    fn hash_fr2() {
        let key_be = Key::from_arr([
            2, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);
        let val = Value::one();
        let leaf = LeafNode::new(key_be, val);
        use num_bigint::BigUint;
        use num_traits::Num;

        let mut bytes = leaf.hash().0;
        bytes.reverse();
        let hex_str = dbg!(hex::encode(bytes));
        let hash = dbg!(leaf.hash().to_fr().to_string());
        let b = BigUint::from_str_radix(&hex_str, 16).unwrap();
        dbg!(b.to_str_radix(10));
    }
}

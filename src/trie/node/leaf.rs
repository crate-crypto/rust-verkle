use crate::{Hash, Key, Value};

use super::errors::NodeError;

/// A Leaf node is a node which stores a value under a specific key.
///
/// It's main functionality is to get the value under it's key
///
#[derive(Debug, Copy, Clone)]
pub struct LeafNode {
    pub key: Key,
    pub value: Value,
}

impl LeafNode {
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
}

#[cfg(test)]
mod interop {
    use super::*;
    #[test]
    fn key0val0() {
        let key0 = Key::one();
        let val0 = Value::zero();
        let leaf = LeafNode {
            key: key0,
            value: val0,
        };
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
        let leaf = LeafNode {
            key: key0,
            value: val0,
        };
        use num_bigint::BigUint;
        use num_traits::Num;
        // let hash = dbg!(leaf.hash().to_hex());
        let mut bytes = match leaf.hash() {
            Hash::NotComputed => panic!(""),
            Hash::Computed(bytes) => bytes,
        };
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
        let leaf = LeafNode {
            key: key_be,
            value: val,
        };
        use num_bigint::BigUint;
        use num_traits::Num;
        // let hash = dbg!(leaf.hash().to_hex());
        let mut bytes = match leaf.hash() {
            Hash::NotComputed => panic!(""),
            Hash::Computed(bytes) => bytes,
        };
        bytes.reverse();
        let hex_str = dbg!(hex::encode(bytes));
        let hash = dbg!(leaf.hash().to_fr().to_string());
        let b = BigUint::from_str_radix(&hex_str, 16).unwrap();
        dbg!(b.to_str_radix(10));
    }
}

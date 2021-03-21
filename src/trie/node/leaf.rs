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
    pub fn get(&self, key: &Key) -> Result<Value, NodeError> {
        if &self.key != key {
            Err(NodeError::LeafNodeKeyMismatch)
        } else {
            Ok(self.value)
        }
    }

    pub fn hash(&self) -> Hash {
        Hash::from_leaf(self)
    }
}

use crate::{Hash, VerkleCommitment};

/// Empty nodes are nodes signify the absence of a value
/// at a particular Key.
#[derive(Debug, Copy, Clone)]
pub struct EmptyNode;

impl EmptyNode {
    pub const fn hash(&self) -> Hash {
        Hash::zero()
    }
    pub fn commitment(&self) -> VerkleCommitment {
        VerkleCommitment::identity()
    }
}

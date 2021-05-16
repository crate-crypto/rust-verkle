use crate::{Hash, VerkleCommitment};

use super::{empty::EmptyNode, leaf::LeafNode};
// XXX: This api will be changed as computing the commitment to a leafnode
// is possible through this.

/// Hashed nodes (I believe) are used for pre-computations.
/// It is not strictly necessary to have Hashed nodes in the implementation
/// However, the Golang implementation has it so the API for it
/// has been eagerly created.
///
/// Note that the API does not allow one to create a hashed node from
/// scratch, you must start with a leaf or empty node to be able
/// to create a hashed node
#[derive(Debug, Copy, Clone)]
pub struct HashedNode {
    hash: Hash,
    commitment: Option<VerkleCommitment>,
}

/// To create a HashedNode from an EmptyNode
/// We compute the hash as the zeroHash
impl From<EmptyNode> for HashedNode {
    fn from(e: EmptyNode) -> Self {
        HashedNode {
            hash: e.hash(),
            commitment: None,
        }
    }
}

/// To create a HashedNode from a LeafNode
/// We compute the hash as H(key, value)
impl From<LeafNode> for HashedNode {
    fn from(e: LeafNode) -> Self {
        HashedNode {
            hash: e.hash(),
            commitment: None,
        }
    }
}

impl HashedNode {
    // Compute the commitment to the Hash: [x]_1
    //
    // This is done in two steps:
    // 1) Map the hash to the finite field in question.
    // 2) Multiply this finite field element by
    // a generator.
    //
    // The map is done by reducing the
    // bytes modulo the field order.
    fn compute_commitment(&mut self) -> VerkleCommitment {
        // Since the HashedNode cannot be constructed without a hash
        // calling hash_to_fr is safe.
        let x = self.hash.to_fr();
        let commitment = VerkleCommitment::mul_generator(x);
        self.commitment = Some(commitment);
        commitment
    }

    /// Return the underlying hash
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Compute the commitment to the hash or compute it
    /// if it is not already computed.
    pub fn commitment(&mut self) -> VerkleCommitment {
        match self.commitment {
            Some(comm) => comm,
            None => self.compute_commitment(),
        }
    }
}

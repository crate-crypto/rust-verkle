use super::Node;
use crate::{
    trie::verkle::indexer::{ChildMap, DataIndex, NodeSlotMap},
    Hash, VerkleCommitment,
};

#[derive(Debug, Copy, Clone)]
pub struct InternalNode {
    pub hash: Option<Hash>,
    pub commitment: Option<VerkleCommitment>,
}

pub struct TerminationPath {
    // The path bits from the root to the key.
    // XXX: this can be rederived from the width, key and number of nodes
    pub path_bits: Vec<usize>,
    // The indices of the nodes in the DataIndexer
    pub node_indices: Vec<DataIndex>,
}

impl InternalNode {
    pub fn new() -> InternalNode {
        InternalNode {
            hash: None,
            commitment: None,
        }
    }

    /// Returns an array of u8s representing the child type
    /// This is used only for testing and can be put
    /// as a test method
    pub fn children_types(
        data_index: DataIndex,
        num_children: usize,
        sm: &NodeSlotMap,
        child_map: &ChildMap,
    ) -> Vec<u8> {
        let mut vec = Vec::new();

        for child_index in 0..num_children {
            match child_map.child(data_index, child_index) {
                Some(data_index) => {
                    let node_data = sm.get(data_index);
                    vec.push(node_data.node_type());
                }
                None => {
                    vec.push(Node::Empty.node_type());
                }
            }
        }
        vec
    }
}

use crate::{
    trie::node::{errors::NodeError, Node},
    Key, Value,
};

use super::VerkleTrie;

impl<'a> VerkleTrie<'a> {
    pub fn _get(&self, key: &Key) -> Result<Value, NodeError> {
        let path_indices = key.path_indices(self.width);
        let mut current_node_index = self.root_index;
        for index in path_indices {
            let child_data_index = self
                .child_map
                .child(current_node_index, index)
                .ok_or(NodeError::LeafKeyNotFound)?;

            let child = self.data_indexer.get(child_data_index);

            match child {
                Node::Internal(_) => current_node_index = child_data_index,
                Node::Hashed(_) => unreachable!("Should not have a hashed node here"),
                // Node::LeafExt(leaf) => return leaf.get(&key).map(ToOwned::to_owned),
                Node::LeafExt(leaf) => todo!(),
                Node::Empty => unreachable!("soon to be deprecated, empty is implicit"),
                Node::Value(_) => todo!(),
            }
        }
        Err(NodeError::LeafKeyNotFound)
    }
}

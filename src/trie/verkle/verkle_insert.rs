use crate::{Key, Value, VerkleCommitment};

use super::indexer::{ChildDataIndex, ChildMap, DataIndex, NodeSlotMap, ParentDataIndex};
use crate::trie::{
    node::{internal::InternalNode, leaf::LeafNode, Node},
    verkle::VerkleTrie,
};

impl<'a> VerkleTrie<'a> {
    pub fn _insert(&mut self, key: Key, value: Value) {
        let instructions = VerkleTrie::find_insert_position(
            self.root_index,
            self.width,
            &self.child_map,
            &mut self.data_indexer,
            key,
            value,
        );
        self.process_instructions(instructions);
    }
}

impl<'a> VerkleTrie<'a> {
    fn process_instructions(&mut self, instructions: Vec<Ins>) {
        for instruction in instructions {
            match instruction {
                Ins::UpdateLeaf(node_index, leaf_node) => {
                    let node = self.data_indexer.get_mut(node_index);
                    *node = Node::Leaf(leaf_node);
                }
                Ins::UpdateInternalChild { pointer, data } => {
                    let internal_node = self.data_indexer.get_mut(pointer).as_mut_internal();
                    internal_node.commitment = VerkleCommitment::NotComputed;
                    self.child_map
                        .add_child(pointer, data.path_index, data.data_index);
                }
                Ins::ResetComm { pointer } => {
                    let internal_node = self.data_indexer.get_mut(pointer).as_mut_internal();
                    internal_node.commitment = VerkleCommitment::NotComputed;
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct ChildData {
    path_index: usize,
    data_index: ChildDataIndex,
}

#[derive(Debug)]
pub enum Ins {
    // Instruction to update a leaf
    // To update a leaf, we need the position of the leaf in the arena
    // and what data we should update the leaf with
    UpdateLeaf(DataIndex, LeafNode),
    // Instruction to update an internal node
    UpdateInternalChild { pointer: DataIndex, data: ChildData },
    // Set the internal node's commitment to nil.
    // so that it is recomputed
    // We will include an UpdateComm instruction later on
    ResetComm { pointer: DataIndex },
}

impl<'a> VerkleTrie<'a> {
    // Returns all the information needed to insert this key
    fn find_insert_position(
        root_index: ParentDataIndex,
        width: usize,
        child_map: &ChildMap,
        data_indexer: &mut NodeSlotMap,
        key: Key,
        value: Value,
    ) -> Vec<Ins> {
        let leaf_node = LeafNode { key, value };

        let mut path_indices = key.path_indices(width);
        let mut paths_passed = 0; // XXX: When we use for loops, this can be replaced with enumerate

        let mut instructions = Vec::new();

        let mut current_node_index = root_index;

        loop {
            paths_passed += 1;

            // Reset all of the cached commitments.
            // XXX: Without this, it would cause a bug, if we
            // used insert_single
            let ins = Ins::ResetComm {
                pointer: current_node_index,
            };
            instructions.push(ins);

            // orlp( can loop on iterator)
            let index = path_indices.next().unwrap();

            // Find child data index
            let child_data_index = child_map.child(current_node_index, index);
            // If child is empty, exit with leaf insert instruction or return data index
            let child_data_index = match child_data_index {
                Some(child_data_index) => child_data_index,
                None => {
                    // This means that the child is empty.
                    // We just need to update the internal node at this position
                    // with a leaf node.

                    let inst = Ins::UpdateInternalChild {
                        pointer: current_node_index,
                        data: ChildData {
                            path_index: index,
                            data_index: data_indexer.index(Node::Leaf(leaf_node)),
                        },
                    };
                    instructions.push(inst);
                    return instructions;
                }
            };

            // Fetch the child data from the indexer
            let child = data_indexer.get(child_data_index);

            // Since it is not empty, it must be a leaf or an internal node
            if let Node::Hashed(_) = child {
                panic!("hashed node not allowed")
                // return Err(NodeError::HashedNodeInsert);
            }
            // Check for internal node case
            if let Node::Internal(_) = child {
                // XXX; we will add an update commitment instruction
                current_node_index = child_data_index;
                continue;
            }

            let leaf = *child.as_leaf();
            // Check if the leaf node is equal to the key
            // in which case, we update the leaf
            if leaf.key == key {
                let instr = Ins::UpdateLeaf(child_data_index, leaf_node);
                instructions.push(instr);
                break;
            }

            // The keys are not the same, this means that they share `n` path indices
            // we need to create `n-1` internal nodes and link them together
            // XXX: We can pass in an offset here to skip `n` path bits
            let (shared_path, p_diff_a, p_diff_b) = Key::path_difference(&leaf.key, &key, width);

            // path_difference returns all shared_paths.
            // Even shared paths before the current internal node.
            // Lets remove all of those paths
            // let pos_of_first_path = shared_path.iter().position(|&pth| pth == index).unwrap();
            // let relative_shared_path = &shared_path[(pos_of_first_path + 1)..];
            let relative_shared_path = &shared_path[paths_passed..];

            // p_diff_a and p_diff_b tell us the first path index that these paths disagree
            // since the keys are not equal, these should have values
            let p_diff_a = p_diff_a.unwrap();
            let p_diff_b = p_diff_b.unwrap();

            // This is the node that will replace the leaf node
            // replace the leaf node with
            let new_inner_node = InternalNode::new();
            // add node to arena
            let node_index = data_indexer.index(Node::Internal(new_inner_node));
            // Add instruction to update the leaf with this branch node
            let inst = Ins::UpdateInternalChild {
                pointer: current_node_index,
                data: ChildData {
                    path_index: index,
                    data_index: node_index,
                },
            };
            instructions.push(inst);
            current_node_index = node_index;
            for path in relative_shared_path {
                // create a new branch node and add it to the arena
                let new_inner_node = InternalNode::new();
                let node_index = data_indexer.index(Node::Internal(new_inner_node));

                // update the previous branch node to link to this branch node
                // via the path
                let inst = Ins::UpdateInternalChild {
                    pointer: current_node_index,
                    data: ChildData {
                        path_index: *path,
                        data_index: node_index,
                    },
                };
                instructions.push(inst);
                current_node_index = node_index;
            }

            // The last instruction is to point the last node at the two leaves
            let index_leaf_a = child_data_index;
            let index_leaf_b = data_indexer.index(Node::Leaf(leaf_node));
            let inst = Ins::UpdateInternalChild {
                pointer: current_node_index,
                data: ChildData {
                    path_index: p_diff_a,
                    data_index: index_leaf_a,
                },
            };
            instructions.push(inst);
            let inst = Ins::UpdateInternalChild {
                pointer: current_node_index,
                data: ChildData {
                    path_index: p_diff_b,
                    data_index: index_leaf_b,
                },
            };
            instructions.push(inst);
            return instructions;
        }

        return instructions;
    }
}

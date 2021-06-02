use std::hint::unreachable_unchecked;

use crate::{hash::Hashable, Key, Value};
use ark_bls12_381::Fr;
use ark_ff::Zero;

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
        // Split the instructions.
        // We want to process the commitment update instructions separately
        let (update_comm_instrs, other_instrs): (Vec<_>, Vec<_>) =
            instructions.into_iter().partition(|e| {
                std::mem::discriminant(e)
                    == std::mem::discriminant(&Ins::UpdateComm {
                        pointer: DataIndex::default(),
                        old_value: Fr::zero(),
                        lagrange_index: 0,
                    })
            });

        for instruction in other_instrs {
            match instruction {
                Ins::UpdateLeaf(node_index, leaf_node) => {
                    let node = self.data_indexer.get_mut(node_index);
                    *node = Node::Leaf(leaf_node);
                }
                Ins::UpdateInternalChild { pointer, data } => {
                    let internal_node = self.data_indexer.get_mut(pointer).as_mut_internal();
                    self.child_map
                        .add_child(pointer, data.path_index, data.data_index);
                }

                Ins::UpdateComm {
                    pointer,
                    old_value,
                    lagrange_index,
                } => unreachable!(),
            }
        }

        // Now update all of the commitments
        for instr in update_comm_instrs.into_iter().rev() {
            match instr {
                Ins::UpdateComm {
                    pointer,
                    old_value,
                    lagrange_index,
                } => {
                    let child_data_index = self.child_map.child(pointer, lagrange_index).unwrap();
                    let child = self.data_indexer.get(child_data_index);
                    let new_value = match child {
                        Node::Internal(internal_node) => {
                            internal_node.commitment.unwrap().to_hash().to_fr()
                        }
                        Node::Hashed(_) => unreachable!("we don't store these after insertion"),
                        Node::Leaf(leaf) => leaf.hash().to_fr(),
                        Node::Empty => unreachable!("you cannot update to a empty node"),
                    };
                    let delta = new_value - old_value;
                    let updated_comm = self
                        .ck
                        .commit_lagrange_single(delta, lagrange_index)
                        .unwrap();

                    let internal_node = self.data_indexer.get_mut(pointer).as_mut_internal();
                    let old_comm = internal_node.commitment.unwrap_or_default();
                    internal_node.commitment = Some(updated_comm + old_comm);
                }
                _ => unreachable!(),
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
    UpdateInternalChild {
        pointer: DataIndex,
        data: ChildData,
    },
    UpdateComm {
        // This is the parent node that we are updating. It will always be a branch node
        pointer: DataIndex,
        // This is the value of the child node, before the update was ran
        old_value: Fr,
        // This is the child index, which we will use to figure out which lagrange coefficient to use
        lagrange_index: usize,
        // The child_data_index can be derived from the pointer and the child index
    },
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

        for index in path_indices {
            paths_passed += 1;

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

                    // Add the update commitment instruction
                    let inst = Ins::UpdateComm {
                        pointer: current_node_index,
                        old_value: Fr::zero(),
                        lagrange_index: index,
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
            if let Node::Internal(internal) = child {
                let old_value = internal.commitment.unwrap_or_default().to_hash().to_fr();

                let inst = Ins::UpdateComm {
                    pointer: current_node_index,
                    old_value,
                    lagrange_index: index,
                };
                instructions.push(inst);

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

                let inst = Ins::UpdateComm {
                    pointer: current_node_index,
                    old_value: leaf.hash().to_fr(),
                    lagrange_index: index,
                };
                instructions.push(inst);

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

            let inst = Ins::UpdateComm {
                pointer: current_node_index,
                old_value: leaf.hash().to_fr(),
                lagrange_index: index,
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

                let inst = Ins::UpdateComm {
                    pointer: current_node_index,
                    old_value: Fr::zero(),
                    lagrange_index: *path,
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

            let inst = Ins::UpdateComm {
                pointer: current_node_index,
                old_value: Fr::zero(),
                lagrange_index: p_diff_a,
            };
            instructions.push(inst);
            let inst = Ins::UpdateComm {
                pointer: current_node_index,
                old_value: Fr::zero(),
                lagrange_index: p_diff_b,
            };
            instructions.push(inst);

            return instructions;
        }

        return instructions;
    }
}

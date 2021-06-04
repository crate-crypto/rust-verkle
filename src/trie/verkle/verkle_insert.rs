use std::{
    collections::{HashMap, HashSet},
    hint::unreachable_unchecked,
};

use crate::{hash::Hashable, Key, Value};
use ark_bls12_381::Fr;
use ark_ff::Zero;

use super::indexer::{ChildDataIndex, ChildMap, DataIndex, NodeSlotMap, ParentDataIndex};
use crate::trie::{
    node::{internal::InternalNode, leaf::LeafNode, Node},
    verkle::VerkleTrie,
};

impl<'a> VerkleTrie<'a> {
    pub fn _insert(&mut self, key: Key, value: Value) -> Vec<UpdateComm> {
        let (instructions, update_comm_instrs) = VerkleTrie::find_insert_position(
            self.root_index,
            self.width,
            &self.child_map,
            &mut self.data_indexer,
            key,
            value,
        );
        self.process_instructions(instructions);

        update_comm_instrs
    }

    // Deduplicates the update commitment:
    // - If an update commitment has the same pointer and lagrange index,
    // then we keep the first one and remove the subsequent ones
    pub fn dedup_comm(&mut self, old_comms: Vec<UpdateComm>) -> Vec<UpdateComm> {
        let mut dedup_comms = Vec::with_capacity(old_comms.len());

        // Set to keep track of unique
        let mut unique_ = HashSet::with_capacity(old_comms.len());

        for update_comm in old_comms {
            if unique_.contains(&update_comm) {
                continue;
            } else {
                dedup_comms.push(update_comm);
                unique_.insert(update_comm);
            }
        }

        dedup_comms
    }

    pub fn update_comm(&mut self, ins: Vec<UpdateComm>) {
        // First group all of the commitments by the same pointer/branch node
        // so that we update that nodes commitment at once

        use itertools::Itertools;
        let mut grouped_updates: Vec<(DataIndex, Vec<UpdateComm>)> = ins
            .into_iter()
            .into_group_map_by(|x| x.pointer)
            .into_iter()
            .collect();

        // Now sort by depth, with the lowest depth first.
        // We will iterate from the highest depth by just reversing it in the for loop
        grouped_updates.sort_by(|x, y| x.1[0].depth.cmp(&y.1[0].depth));

        for (pointer, comms) in grouped_updates.into_iter().rev() {
            // Compute all of the delta's for each child
            let deltas: Vec<_> = comms
                .into_iter()
                .map(|update_comm| {
                    let old_value = update_comm.old_value;
                    let lagrange_index = update_comm.lagrange_index;

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
                    (lagrange_index, delta)
                })
                .collect_vec();

            let updated_comm = self.ck.commit_lagrange_sparse(&deltas).unwrap();

            let internal_node = self.data_indexer.get_mut(pointer).as_mut_internal();
            let old_comm = internal_node.commitment.unwrap_or_default();
            internal_node.commitment = Some(updated_comm + old_comm);
        }
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
                    self.child_map
                        .add_child(pointer, data.path_index, data.data_index);
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
}

#[derive(Debug, Copy, Clone)]
pub struct UpdateComm {
    // This is the parent node that we are updating. It will always be a branch node
    pointer: DataIndex,
    // This is the value of the child node, before the update was ran
    old_value: Fr,
    // This is the child index, which we will use to figure out which lagrange coefficient to use
    lagrange_index: usize,
    // The child_data_index can be derived from the pointer and the child index
    depth: usize,
}

impl PartialEq for UpdateComm {
    fn eq(&self, other: &Self) -> bool {
        self.pointer.eq(&other.pointer) & self.lagrange_index.eq(&other.lagrange_index)
    }
}
impl Eq for UpdateComm {}

impl std::hash::Hash for UpdateComm {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pointer.hash(state);
        self.lagrange_index.hash(state);
    }
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
    ) -> (Vec<Ins>, Vec<UpdateComm>) {
        let leaf_node = LeafNode { key, value };

        let mut path_indices = key.path_indices(width);
        let mut paths_passed = 0; // XXX: When we use for loops, this can be replaced with enumerate

        let mut instructions = Vec::new();
        let mut comm_update_instructions = Vec::new();

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
                    let inst = UpdateComm {
                        pointer: current_node_index,
                        old_value: Fr::zero(),
                        lagrange_index: index,
                        depth: paths_passed,
                    };
                    comm_update_instructions.push(inst);

                    return (instructions, comm_update_instructions);
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

                let inst = UpdateComm {
                    pointer: current_node_index,
                    old_value,
                    lagrange_index: index,
                    depth: paths_passed,
                };
                comm_update_instructions.push(inst);

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

                let inst = UpdateComm {
                    pointer: current_node_index,
                    old_value: leaf.hash().to_fr(),
                    lagrange_index: index,
                    depth: paths_passed,
                };
                comm_update_instructions.push(inst);

                break;
            }

            // The keys are not the same, this means that they share `n` path indices
            // we need to create `n-1` internal nodes and link them together
            // XXX: We can pass in an offset here to skip `n` path bits
            let (shared_path, p_diff_a, p_diff_b) = Key::path_difference(&leaf.key, &key, width);

            // path_difference returns all shared_paths.
            // Even shared paths before the current internal node.
            // Lets remove all of those paths
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

            let inst = UpdateComm {
                pointer: current_node_index,
                old_value: leaf.hash().to_fr(),
                lagrange_index: index,
                depth: paths_passed,
            };
            comm_update_instructions.push(inst);

            current_node_index = node_index;
            for (offset, path) in relative_shared_path.iter().enumerate() {
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

                let inst = UpdateComm {
                    pointer: current_node_index,
                    old_value: Fr::zero(),
                    lagrange_index: *path,
                    depth: paths_passed + offset + 1, // XXX: plus one because enumerate starts at 0
                };
                comm_update_instructions.push(inst);
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

            let inst = UpdateComm {
                pointer: current_node_index,
                old_value: Fr::zero(),
                lagrange_index: p_diff_a,
                depth: paths_passed + relative_shared_path.len() + 1,
            };
            comm_update_instructions.push(inst);
            let inst = UpdateComm {
                pointer: current_node_index,
                old_value: Fr::zero(),
                lagrange_index: p_diff_b,
                depth: paths_passed + relative_shared_path.len() + 1,
            };
            comm_update_instructions.push(inst);

            return (instructions, comm_update_instructions);
        }

        return (instructions, comm_update_instructions);
    }
}

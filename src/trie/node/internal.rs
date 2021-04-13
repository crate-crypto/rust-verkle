use super::{children::Children, errors::NodeError, leaf::LeafNode, Node};
use crate::{
    kzg10::CommitKey,
    trie::indexer::{DataIndex, NodeSlotMap},
    verkle::VerklePath,
    Hash, Key, Value, VerkleCommitment,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_poly::{Evaluations, GeneralEvaluationDomain};
use std::usize;

#[derive(Debug, Clone)]
pub struct InternalNode {
    pub children: Children,
    // XXX: rename to key_depth
    pub depth: usize,
    pub width: usize,
    hash: Hash,
    commitment: VerkleCommitment,
}

pub struct TerminationPath {
    // The path bits from the root to the key.
    // XXX: this can be rederived from the width, key and number of nodes
    pub path_bits: Vec<usize>,
    // The indices of the nodes in the DataIndexer
    pub node_indices: Vec<DataIndex>,
}

impl InternalNode {
    /// Returns an array of u8s representing the child type
    /// This is used only for testing and can be put
    /// as a test method
    pub fn children_types(&self, sm: &NodeSlotMap) -> Vec<u8> {
        let mut vec = Vec::new();
        for data_index in self.children.iter() {
            match data_index {
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
    pub fn child<'a>(
        &self,
        path_index: usize,
        sm: &'a NodeSlotMap,
    ) -> Option<(&'a Node, &DataIndex)> {
        let node_index = self.children.get_child(path_index);
        let node_index = match node_index {
            None => return None,
            Some(data_index) => data_index,
        };
        Some((sm.get(node_index), node_index))
    }
}

impl InternalNode {
    pub fn new(depth: usize, width: usize) -> InternalNode {
        let children = Children::new(1 << width);
        InternalNode {
            children,
            depth,
            width,
            hash: Hash::NotComputed,
            commitment: VerkleCommitment::NotComputed,
        }
    }

    pub fn insert2(
        root_index: DataIndex,
        key: Key,
        value: Value,
        sm: &mut NodeSlotMap,
    ) -> Result<(), NodeError> {
        // Regardless, we need to insert a leaf node.
        // We just need to figure out where it is being inserted
        let leaf_node = LeafNode { key, value };

        let mut current_node = sm.get(&root_index).as_internal();
        let mut depth = current_node.depth;
        let width = current_node.width;

        // First figure out where in the tree this will be placed
        let mut path_indices = key.path_indices(width).into_iter();

        let mut current_node_index = root_index;
        #[derive(Debug)]
        struct ChildData {
            path_index: usize,
            data_index: DataIndex,
        }

        // An internal node's child can be in 2 states:
        // - empty
        // - internal
        // If it's empty, then we need to add a leaf node here
        // to do this, we need the node location in the database,
        // the path index and the key and value. This is the purpose of
        // the UpdateLeaf command
        //
        // If it is internal, then since we cannot delete a node
        // we can only traverse this internal node and update it's commitment
        // Lets forget about commitment update
        #[derive(Debug)]
        enum Ins {
            // Instruction to update a leaf
            // To update a leaf, we need the position of the leaf in the arena
            // and what data we should update the leaf with
            UpdateLeaf(DataIndex, LeafNode),
            // Instruction to update an internal node
            UpdateInternalChild { pointer: DataIndex, data: ChildData },
        }
        struct UpdateComm {
            current_node: DataIndex,
            value_change: Fr,
        }
        let mut instructions = vec![];

        loop {
            let index = path_indices.next().unwrap();

            // Find child
            let (child, child_node_index) = match current_node.child(index, sm) {
                Some((child, child_node_index)) => (child, *child_node_index),
                None => {
                    // empty node
                    let leaf_node_index = sm.index(Node::Leaf(leaf_node));
                    let inst = Ins::UpdateInternalChild {
                        pointer: current_node_index,
                        data: ChildData {
                            path_index: index,
                            data_index: leaf_node_index,
                        },
                    };
                    instructions.push(inst);
                    break;
                }
            };
            depth += width;

            // We expect either a leaf node or an internal node
            //
            if let Node::Hashed(_) = child {
                return Err(NodeError::HashedNodeInsert);
            }
            // Check for internal node case
            if let Node::Internal(internal) = child {
                // XXX; we will add an update commitment instruction
                current_node = internal;
                current_node_index = child_node_index;
                continue;
            }

            let leaf = child.as_leaf();
            // Check if the leaf node is equal to the key
            // in which case, we update the leaf
            if leaf.key == key {
                let instr = Ins::UpdateLeaf(child_node_index, leaf_node);
                instructions.push(instr);
                break;
            }

            // The keys are not the same, this means that they share `n` path indices
            // we need to create `n-1` internal nodes and link them together
            let (shared_path, p_diff_a, p_diff_b) = Key::path_difference(&leaf.key, &key, width);

            // path_difference returns all shared_paths.
            // Even shared paths before the current internal node.
            // Lets remove all of those paths
            let pos_of_first_path = shared_path.iter().position(|&pth| pth == index).unwrap();
            let relative_shared_path = &shared_path[(pos_of_first_path + 1)..];

            // p_diff_a and p_diff_b tell us the first path index that these paths disagree
            // since the keys are not equal, these should have values
            let p_diff_a = p_diff_a.unwrap();
            let p_diff_b = p_diff_b.unwrap();

            // This is the node that will replace the leaf node
            // replace the leaf node with
            let new_inner_node = InternalNode::new(depth, width);
            // add node to arena
            let node_index = sm.index(Node::Internal(new_inner_node));
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
                depth = depth + width;
                // create a new branch node and add it to the arena
                let new_inner_node = InternalNode::new(depth, width);
                let node_index = sm.index(Node::Internal(new_inner_node));

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
            let index_leaf_a = child_node_index;
            let index_leaf_b = sm.index(Node::Leaf(leaf_node));
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
            break;
        }

        // Process the instructions
        for instruction in instructions {
            match instruction {
                Ins::UpdateLeaf(node_index, leaf_node) => {
                    let node = sm.get_mut(node_index);
                    *node = Node::Leaf(leaf_node);
                }
                Ins::UpdateInternalChild { pointer, data } => {
                    let internal_node = sm.get_mut(pointer).as_mut_internal();
                    internal_node.commitment = VerkleCommitment::NotComputed;
                    internal_node
                        .children
                        .replace_child(data.path_index, data.data_index);
                }
            }
        }

        Ok(())
    }

    pub fn get<'a>(&self, key: &Key, sm: &'a NodeSlotMap) -> Result<&'a Value, NodeError> {
        // XXX: change this function to not use recursion
        let n_child = offset2key(key.as_bytes(), self.width, self.depth);

        let node_child_index = self.children.get_child(n_child).expect("expected a child");
        let child = sm.get(&node_child_index);
        match child {
            Node::Internal(internal) => internal.get(key, sm),
            Node::Leaf(leaf) => leaf.get(key),
            Node::Empty | Node::Hashed(_) => return Err(NodeError::InvalidChildRead),
        }
    }

    pub fn find_child_from_path_bit<'a>(
        &self,
        sm: &'a NodeSlotMap,
        path_bit: usize,
    ) -> Option<(&'a Node, &DataIndex)> {
        self.child(path_bit, sm)
    }

    // Collect all of the nodes along the path to the key
    pub fn find_termination_path(
        &self,
        sm: &NodeSlotMap,
        key: &Key,
        // XXX: Can we remove the nodes vector as we have node_indices?
    ) -> Result<TerminationPath, NodeError> {
        let mut path_bits = Vec::with_capacity(3);
        let mut node_indices = Vec::with_capacity(3);

        let mut curr_node = self;
        for path_bit in key.path_indices(self.width) {
            let (node, node_index) = match curr_node.find_child_from_path_bit(sm, path_bit) {
                Some((node, node_index)) => (node, node_index),
                None => return Err(NodeError::UnexpectedEmptyNode),
            };
            path_bits.push(path_bit);
            node_indices.push(*node_index);

            match node {
                Node::Internal(internal) => {
                    curr_node = internal;
                }
                Node::Leaf(leaf) => {
                    // A key has been found, however it may not be the key we are looking for
                    if &leaf.key != key {
                        return Err(NodeError::WrongLeafNode {
                            leaf_found: leaf.key,
                        });
                    }
                    return Ok(TerminationPath {
                        path_bits,
                        node_indices,
                    });
                }
                Node::Hashed(_) => return Err(NodeError::UnexpectedHashNode),
                Node::Empty => return Err(NodeError::UnexpectedEmptyNode),
            }
        }

        return Err(NodeError::BranchNodePath);
    }

    pub fn compute_polynomial_evaluations(
        data_index: DataIndex,
        width: usize,
        sm: &mut NodeSlotMap,
        ck: &CommitKey<Bls12_381>,
    ) -> Evaluations<Fr> {
        let evaluations = InternalNode::compute_evaluations(data_index, sm, ck);

        let num_children = 1 << width;
        let d = GeneralEvaluationDomain::<Fr>::new(num_children).unwrap();
        Evaluations::from_vec_and_domain(evaluations.to_vec(), d)
    }

    // Compute evaluations for an internal node, by iterating it's children and getting their
    // evaluations
    //
    // XXX: This should not be done in a recursive manner
    // We need to pass in an array which gives the commitments to the internal nodes on this level
    // or find a way to cache commitments when the path has not changed
    pub fn compute_evaluations(
        data_index: DataIndex,
        sm: &mut NodeSlotMap,
        ck: &CommitKey<Bls12_381>,
    ) -> Vec<Fr> {
        let children = sm.get(&data_index).as_internal().children.clone();
        let mut polynomial_eval = vec![Fr::zero(); children.len()];

        // XXX: make this parallel. May require switching to an iterator with Map
        for (i, child_data_index) in children.iter().enumerate() {
            let child_data_index = match child_data_index {
                None => continue,
                Some(index) => index,
            };

            let child = sm.get(&child_data_index);

            match child {
                Node::Internal(_) => {
                    let eval = InternalNode::commitment(*child_data_index, sm, ck)
                        .to_hash()
                        .to_fr();
                    polynomial_eval[i] = eval;
                }
                Node::Hashed(hashed_node) => {
                    // Note that we do not commit to the hash here, we simply convert it to fr
                    let eval = hashed_node.hash().to_fr();
                    polynomial_eval[i] = eval;
                }
                Node::Leaf(leaf_node) => {
                    let eval = leaf_node.hash().to_fr();
                    polynomial_eval[i] = eval;
                }
                Node::Empty => {
                    // do nothing
                }
            }
        }
        polynomial_eval
    }

    // Computes the evaluations for each node in the path
    // pub fn compute_evaluations_from_term_path(
    //     term_path: &TerminationPath,
    //     sm: &mut NodeSlotMap,
    //     ck: &CommitKey<Bls12_381>,
    // ) -> Vec<Fr> {
    // }

    pub fn commitment(
        // the data index for this internal node
        data_index: DataIndex,
        sm: &mut NodeSlotMap,
        ck: &CommitKey<Bls12_381>,
    ) -> VerkleCommitment {
        // First get the internal node to check if it's commitment is cached
        let node = sm.get(&data_index).as_internal();
        let width = node.width;

        if let VerkleCommitment::Computed(_) = node.commitment {
            return node.commitment;
        }
        let poly = InternalNode::compute_polynomial_evaluations(data_index, width, sm, ck);
        let kzg10_commitment = ck.commit_lagrange(&poly.evals).unwrap();

        let node = sm.get_mut(data_index).as_mut_internal();
        node.commitment = VerkleCommitment::Computed(kzg10_commitment);
        node.commitment
    }

    pub fn commitment_from_poly(
        data_index: DataIndex,
        sm: &mut NodeSlotMap,
        // If the polynomial for the branch node is already computed,
        // we can commit to it and save the commitment.
        // This must be the corresponding polynomial for the branch node
        // or the proof will fail.
        precomputed_polynomial: &Evaluations<Fr>,
        ck: &CommitKey<Bls12_381>,
    ) -> VerkleCommitment {
        let kzg10_commitment = ck.commit_lagrange(&precomputed_polynomial.evals).unwrap();

        let node = sm.get_mut(data_index).as_mut_internal();
        node.commitment = VerkleCommitment::Computed(kzg10_commitment);
        node.commitment
    }

    pub fn find_commitment_path(
        data_index: DataIndex,
        sm: &mut NodeSlotMap,
        key: &Key,
        ck: &CommitKey<Bls12_381>,
    ) -> Result<VerklePath, NodeError> {
        let node = sm.get(&data_index).as_internal();
        let width = node.width;

        let termination_path = node.find_termination_path(sm, key)?;

        let path_bit = termination_path.path_bits;
        let mut node_indices = termination_path.node_indices;

        // If there are no errors, then it means:
        // - There is at least one node, which is the leaf
        // - The other nodes are branches
        //
        let last_node_index = node_indices.pop().unwrap();

        // Lets first commit to all of the branch nodes.
        // And store the polynomials in coefficient form(for now).
        //
        // We need the polynomial even after committing because we need
        // to compute the Kate witness.
        //
        // XXX: It is possible to move most of that machinery here,
        // but it's a lot cleaner to have KZG10 as a separate module
        // altogether.
        let mut commitments = Vec::with_capacity(node_indices.len());
        let mut polynomials = Vec::with_capacity(node_indices.len());

        let root_branch_poly =
            InternalNode::compute_polynomial_evaluations(data_index, width, sm, ck);
        let root_commitment =
            InternalNode::commitment_from_poly(data_index, sm, &root_branch_poly, ck);

        let node = sm.get_mut(data_index).as_mut_internal();
        node.commitment = root_commitment;

        polynomials.push(root_branch_poly);
        commitments.push(root_commitment);

        for branch_node_index in node_indices.iter() {
            let branch_poly =
                InternalNode::compute_polynomial_evaluations(*branch_node_index, width, sm, ck);
            let branch_commitment =
                InternalNode::commitment_from_poly(*branch_node_index, sm, &branch_poly, ck);

            polynomials.push(branch_poly);
            commitments.push(branch_commitment)
        }

        // Now collect all of the evaluation points for the commitments
        // The evaluation point for the first commitment, is the hash/root of the
        // second node.
        //
        // XXX: The below code can merged into the previous for loop
        // since each commitment is also the evaluation point for the previous node
        // It is not just so that I can comment it and git commit this version, which
        // is more readable.
        let mut evaluation_points = Vec::with_capacity(commitments.len());
        // Skip the first commitment(root node)
        for commitment in commitments.iter().skip(1) {
            evaluation_points.push(commitment.to_hash().to_fr())
        }
        // Add the last node which should be a leaf as an evaluation point by hashing
        let leaf_hash = sm.get(&last_node_index).as_leaf().hash();
        evaluation_points.push(leaf_hash.to_fr());

        // Convert the path_bits to Field elements to be evaluated at
        // We raise them to the power of omega, where omega is a 2^width root of unity
        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(1 << width).unwrap();
        let path_indices_as_fr: Vec<_> = path_bit
            .into_iter()
            .map(|path_index| domain.element(path_index))
            .collect();

        Ok(VerklePath {
            omega_path_indices: path_indices_as_fr,
            node_roots: evaluation_points,
            commitments,
            polynomials,
        })
    }
}

// impl InternalNode {

// }

pub fn offset2key(key: &[u8], width: usize, offset: usize) -> usize {
    bit_extraction(key, width, offset)
}

/// Bit extraction interprets the bytes as bits
/// It then Takes `WIDTH` number of bits
/// starting from the offset position
pub fn bit_extraction(bytes: &[u8], width: usize, offset: usize) -> usize {
    use bitvec::prelude::*;

    let bits = bytes.view_bits::<Msb0>();
    // If the offset + width exceeds the number of bits,
    // the function will return none. Check if this is the case, and
    // truncate to the last position, if so.
    let last_position = match offset + width >= bits.len() {
        true => bits.len(),
        false => offset + width,
    };
    bits.get(offset..last_position).unwrap().load_be::<usize>()
}

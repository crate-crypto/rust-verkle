use super::{errors::NodeError, leaf::LeafNode, Node};
use crate::{
    kzg10::CommitKey,
    trie::{NodeIndex, NodeSlotMap},
    verkle::VerklePath,
    Hash, Key, Value, VerkleCommitment,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_poly::{Evaluations, GeneralEvaluationDomain};
use std::{convert::TryInto, usize};

pub const WIDTH: usize = 10;
// The number of children a branch node can have
pub const NUM_CHILDREN: usize = 1 << WIDTH;

/// An internal node is a pointer node which can point to
/// 2^WIDTH amount of children nodes
///  Currently WIDTH is 10, so an internal node can hold 1024 children nodes
///
#[derive(Debug, Copy, Clone)]
pub struct InternalNode {
    pub children: [NodeIndex; NUM_CHILDREN],
    // XXX: rename to key_depth
    pub depth: usize,
    hash: Hash,
    commitment: VerkleCommitment,
}

impl InternalNode {
    /// Returns an array of u8s representing the child type
    /// This is used only for testing and can be put
    /// as a test method
    pub fn children_types(&self, sm: &NodeSlotMap) -> Vec<u8> {
        let mut vec = Vec::new();
        for child_node_idx in &self.children {
            let child = &sm[*child_node_idx];

            vec.push(child.node_type());
        }
        vec
    }
}

impl InternalNode {
    pub fn new(depth: usize, sm: &mut NodeSlotMap) -> InternalNode {
        let children: Vec<_> = (0..NUM_CHILDREN)
            .map(|_| sm.insert(Node::default()))
            .collect();
        let children: [NodeIndex; NUM_CHILDREN] = children.try_into().unwrap();

        InternalNode {
            children,
            depth,
            hash: Hash::NotComputed,
            commitment: VerkleCommitment::NotComputed,
        }
    }
    /// Lets go through all of the cases that can occur for insertion here:
    ///
    /// Given a key and value
    // XXX: This overflows the stack for the longest path.
    // The only way to make it work is to allocate 9MB of stack size instead of 8MB.
    // This could possibly be caused by the Box, which allocates arrays on the stack first
    // An alternative is to use an Arena
    pub fn insert(
        &mut self,
        key: Key,
        value: Value,
        sm: &mut NodeSlotMap,
    ) -> Result<(), NodeError> {
        InternalNode::update_internal_node(self, sm, key, value)
    }

    // Given a Node, key and value
    // Return the node that should replace this child
    pub fn update_internal_node(
        internal_node: &mut InternalNode,
        sm: &mut NodeSlotMap,
        key: Key,
        value: Value,
    ) -> Result<(), NodeError> {
        // Nullify the commitment
        internal_node.commitment = VerkleCommitment::NotComputed;

        let n_child = offset2key(key.as_bytes(), internal_node.depth);

        let child_node_index = internal_node.children[n_child];
        let child = sm.get(child_node_index).unwrap().clone();

        let mut new_branch_to_insert: Option<Node> = None;
        if let Node::Leaf(leaf_node) = &child {
            let new_node = InternalNode::update_leaf_node(
                sm,
                internal_node.depth,
                n_child,
                leaf_node,
                key,
                value,
            );
            new_branch_to_insert = Some(new_node);
        }

        if let Node::Empty(_) = child {
            new_branch_to_insert = Some(Node::Leaf(LeafNode { key, value }));
        }

        if let Node::Hashed(_) = child {
            return Err(NodeError::HashedNodeInsert);
        }

        if let Node::Internal(mut internal) = child {
            InternalNode::update_internal_node(&mut internal, sm, key, value)?;
            new_branch_to_insert = Some(Node::Internal(internal));
        }

        // Point internal node to the new child node
        // XXX: Seems get_mut then replace overflows the stack for some reason
        internal_node.children[n_child] = sm.insert(new_branch_to_insert.unwrap());

        Ok(())
    }

    fn update_leaf_node(
        sm: &mut NodeSlotMap,
        depth: usize,
        // The path index that this leaf node shares with the key.
        // It is not possible to update a leaf node from
        // anywhere other than through an internal node
        first_path: usize,
        leaf_node: &LeafNode,
        key: Key,
        value: Value,
    ) -> Node {
        // First check if the keys are exactly the same
        // If so, this is just an update
        if &leaf_node.key == &key {
            return Node::Leaf(LeafNode { key, value });
        }

        // The keys differ. Find out by how many path indices
        // The first shared path between the keys will be the path from the internal node
        // that we started with and this leaf node.
        // We skip it as we want to find out the shared path between this leaf and the key
        // relative to the leaf
        let (shared_path, p_diff_a, p_diff_b) = Key::path_difference(&leaf_node.key, &key);
        let total_shared_paths = shared_path.len();
        // path_difference returns all shared_paths.
        // Even shared paths before the current internal node.
        // Lets remove all of those paths
        let pos_of_first_path = shared_path
            .iter()
            .position(|&pth| pth == first_path)
            .unwrap();
        let shared_path = &shared_path[(pos_of_first_path + 1)..];

        // p_diff_a and p_diff_b tell us the first path index that these paths disagree
        // since the keys are not equal, these should have values
        let p_diff_a = p_diff_a.unwrap();
        let p_diff_b = p_diff_b.unwrap();

        // So remember, this child leaf node is now going to turn into a branch node
        // And this leaf node plus the inserted key will share a branch node
        let child_leaf_node = leaf_node.clone();
        let inserted_key_leaf_node = LeafNode { key, value };

        // Lets put these leaf nodes into a branch node.
        // Their position in this branch node depends on the first
        // difference in their key
        //
        // The depth of this branch node depends on how many
        // path indices these two leaves share, altogether.
        let mut last_depth = depth + (total_shared_paths * WIDTH);
        let mut last_branch = InternalNode::new(last_depth, sm);

        // XXX: We should already have this in the tree, so this is a waste
        last_branch.children[p_diff_a] = sm.insert(Node::Leaf(child_leaf_node));
        last_branch.children[p_diff_b] = sm.insert(Node::Leaf(inserted_key_leaf_node));

        // If the shared_path is empty, then there are no more branch nodes between this new branch node
        // that we have just created and so we can simply replace the leaf node with this new branch node
        // XXX: This if statement is not needed. Leave it in, for clarity
        if shared_path.is_empty() {
            return Node::Internal(last_branch);
        }

        // If the shared path is not empty, then there are branch nodes between
        // the branch with the leaves and this current level where the leaf node is
        // We will build up each branch node until we are at the current level
        // which is `internal_node.depth + width`

        for s_path in shared_path.into_iter().rev() {
            // First create a node one level higher than the current node
            let new_depth = last_depth - WIDTH;
            let mut new_branch = InternalNode::new(new_depth, sm);

            // Connect this new branch to the previous branch via the shared path
            new_branch.children[*s_path] = sm.insert(Node::Internal(last_branch));

            last_depth = new_depth;
            last_branch = new_branch;
        }

        // Once the for loop has completed, our last_branch should have the same
        // depth as this leaf node
        assert_eq!(last_depth, depth + WIDTH);
        return Node::Internal(last_branch);
    }

    pub fn get(&self, key: &Key, sm: &NodeSlotMap) -> Result<Value, NodeError> {
        let n_child = offset2key(key.as_bytes(), self.depth);

        let node_child_index = self.children.get(n_child).expect("expected a child");
        let child = sm[*node_child_index].clone();
        match child {
            Node::Internal(internal) => internal.get(key, sm),
            Node::Leaf(leaf) => leaf.get(key),
            Node::Empty(_) | Node::Hashed(_) => return Err(NodeError::InvalidChildRead),
        }
    }

    pub fn find_commitment_path(
        &mut self,
        sm: &mut NodeSlotMap,
        key: &Key,
        ck: &CommitKey<Bls12_381>,
    ) -> Result<VerklePath, NodeError> {
        let (mut key_path, path_bit, mut node_indices) = self.find_termination_path(sm, key)?;
        // If there are no errors, then it means:
        // - There is at least one node, which is the leaf
        // - The other nodes are branches
        //
        let last_node = key_path.pop().unwrap();

        // Lets first commit to all of the branch nodes.
        // And store the polynomials in coefficient form(for now).
        //
        // We need the polynomial even after committing because we need
        // to compute the Kate witness.
        //
        // XXX: It is possible to move most of that machinery here,
        // but it's a lot cleaner to have KZG10 as a separate module
        // altogether.
        let mut commitments = Vec::with_capacity(key_path.len());
        let mut polynomials = Vec::with_capacity(key_path.len());

        let root_branch_poly = self.compute_polynomial_evaluations(sm, ck);
        let root_commitment = self.commitment_from_poly(&root_branch_poly, ck);
        self.commitment = root_commitment;

        polynomials.push(root_branch_poly);
        commitments.push(root_commitment);

        // Convert the nodes in the key path to branch nodes
        // This panics if any of the nodes are not branch nodes.
        // If this happens, then the algorithm is unsound anyways.
        let mut branch_nodes: Vec<_> = key_path.into_iter().map(|node| node.internal()).collect();

        for branch in branch_nodes.iter_mut() {
            let branch_poly = branch.compute_polynomial_evaluations(sm, ck);
            let branch_commitment = branch.commitment_from_poly(&branch_poly, ck);

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
        let leaf_hash = last_node.as_leaf().hash();
        evaluation_points.push(leaf_hash.to_fr());

        // Convert the path_bits to Field elements to be evaluated at
        // We raise them to the power of omega, where omega is a 2^width root of unity
        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(NUM_CHILDREN).unwrap();
        let path_indices_as_fr: Vec<_> = path_bit
            .into_iter()
            .map(|path_index| domain.element(path_index))
            .collect();

        // Lastly, lets cache the commitments for the branch nodes in the key path
        //
        // XXX: This is done by replacing the node in the slot map
        // This should be cheap as Nodes are just a group of integers
        // however there should be a more efficient way.
        //
        // Pop off the last index, this will be the index for the
        // leaf node
        node_indices.pop();

        for (index, branch_node) in node_indices.into_iter().zip(branch_nodes) {
            sm[index] = Node::Internal(branch_node)
        }

        Ok(VerklePath {
            omega_path_indices: path_indices_as_fr,
            node_roots: evaluation_points,
            commitments,
            polynomials,
        })
    }

    // Collect all of the nodes along the path to the key
    pub fn find_termination_path(
        &self,
        sm: &NodeSlotMap,
        key: &Key,
    ) -> Result<(Vec<Node>, Vec<usize>, Vec<NodeIndex>), NodeError> {
        let mut nodes = Vec::with_capacity(3);
        let mut path_bits = Vec::with_capacity(3);
        let mut node_indices = Vec::with_capacity(3);

        let mut curr_node = self.clone();
        for path_bit in key.path_indices() {
            let (node, node_index) = curr_node.find_child_from_path_bit(sm, path_bit);
            nodes.push(node);
            path_bits.push(path_bit);
            node_indices.push(node_index);

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
                    return Ok((nodes, path_bits, node_indices));
                }
                Node::Hashed(_) => return Err(NodeError::UnexpectedHashNode),
                Node::Empty(_) => return Err(NodeError::UnexpectedEmptyNode),
            }
        }

        return Err(NodeError::BranchNodePath);
    }

    pub fn find_child_from_path_bit(&self, sm: &NodeSlotMap, path_bit: usize) -> (Node, NodeIndex) {
        let node_idx = self.children[path_bit];
        (sm[node_idx], node_idx)
    }

    pub fn commitment(&mut self, sm: &NodeSlotMap, ck: &CommitKey<Bls12_381>) -> VerkleCommitment {
        if let VerkleCommitment::Computed(_) = self.commitment {
            return self.commitment;
        }
        let poly = self.compute_polynomial_evaluations(sm, ck);
        let kzg10_commitment = ck.commit_lagrange(&poly.evals).unwrap();
        self.commitment = VerkleCommitment::Computed(kzg10_commitment);
        self.commitment
    }

    pub fn commitment_from_poly(
        &mut self,
        // If the polynomial for the branch node is already computed,
        // we can commit to it and save the commitment.
        // This must be the corresponding polynomial for the branch node
        // or the proof will fail.
        precomputed_polynomial: &Evaluations<Fr>,
        ck: &CommitKey<Bls12_381>,
    ) -> VerkleCommitment {
        let kzg10_commitment = ck.commit_lagrange(&precomputed_polynomial.evals).unwrap();
        self.commitment = VerkleCommitment::Computed(kzg10_commitment);
        self.commitment
    }

    pub fn hash(&mut self, sm: &NodeSlotMap, ck: &CommitKey<Bls12_381>) -> Hash {
        self.commitment(sm, ck).to_hash()
    }

    // XXX: This should not be done in a recursive manner
    // We need to pass in an array which gives the commitments to the internal nodes on this level
    // or find a way to cache commitments when the path has not changed
    pub fn compute_evaluations(
        &self,
        sm: &NodeSlotMap,
        ck: &CommitKey<Bls12_381>,
    ) -> ([Fr; NUM_CHILDREN]) {
        let mut polynomial_eval = [Fr::zero(); NUM_CHILDREN];

        // XXX: Change this to be iterator?
        for (i, node_child_index) in self.children.iter().enumerate() {
            let child = sm[*node_child_index].clone();
            match child {
                Node::Internal(mut internal) => {
                    let eval = internal.commitment(sm, ck).to_hash().to_fr();
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
                Node::Empty(_) => {
                    // do nothing
                }
            }
        }
        polynomial_eval
    }

    pub fn compute_polynomial_evaluations(
        &self,
        sm: &NodeSlotMap,
        ck: &CommitKey<Bls12_381>,
    ) -> Evaluations<Fr> {
        let evaluations = self.compute_evaluations(sm, ck);

        // Do IFFT since we need these in coefficient form
        // for the inefficient version
        // Then commit to the polynomial using the SRS
        let d = GeneralEvaluationDomain::<Fr>::new(NUM_CHILDREN).unwrap();
        Evaluations::from_vec_and_domain(evaluations.to_vec(), d)
    }
}

pub fn offset2key(key: &[u8], offset: usize) -> usize {
    bit_extraction(key, 10, offset)
}

/// Bit extraction interprets the bytes as bits
/// It then Takes `WIDTH` number of bits
/// starting from the offset position
pub fn bit_extraction(bytes: &[u8], width: usize, offset: usize) -> usize {
    // offset tells us how many bits to skip.
    // If offset is 2, then we skip 2 bits.
    // If offset is 3, then we skip 3 bits.
    //
    // Notice however, than in both cases of 2 and 3
    // The starting position is still the first byte
    // It is only when we get to an offset of 8,
    // do we skip the first byte altogether and
    // start off in the second byte.
    //
    // For this reason, we must divide the offset by 8
    // to figure out which byte we start from.
    let _n_first_byte = offset / 8;

    // Now imagine that the offset is 0 and the width is 10.
    // We need to figure out how many bits from the second
    // byte need to be extracted.
    //
    // So if the width is 10, then we need to take 8 bits from
    // the first byte and 2 bits from the next byte.
    //
    // If the width if 10 and the offset is 2.
    // we can only take 6 bits from the first, since we skipped 2 bits
    // and in the next byte, we need to take 4 bits.
    //
    // Generalising:
    //
    // If the width is `n` and the offset is `k`
    // we can only take 8-(k % 8) bits from the first byte
    // This also takes care of the edge case, when `k` is a multiple of 8
    // if the offset is 8, we want to take 8 bits from the first byte!
    //
    // Now to figure out how many bits to take from the second array
    // Note that we have taken (8-k%8) bits from the first byte
    // We now only need to collect n - (8 - k % 8) bits from the last
    // byte
    // Computing where the last byte will be in the byte array would
    // be offset + width / 8
    let _last_byte = (offset + width) / 8;

    // But instead of doing that, lets just use bitvec and get a bitview of the
    // bytes
    use bitvec::prelude::*;

    let bits = bytes.view_bits::<Msb0>();
    // If the offset + width exceeds the number of bits,
    // the function will return none. Check if this is the case, and
    // truncate to the last position, if so.
    let last_position = match offset + width >= bits.len() {
        true => bits.len(),
        false => offset + width,
    };
    let k = bits.get(offset..last_position).unwrap().load_be::<usize>();
    k
}

#[test]
fn this_test_differs_in_golang() {
    let k = vec![0, 117, 0, 1];
    let width = 10;
    let offset = 15;
    bit_extraction(&k, width, offset);
}

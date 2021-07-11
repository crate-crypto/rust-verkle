use crate::hash::Hashable;
use crate::{kzg10::LagrangeCommitter, Key, VerkleCommitment, VerklePath};
use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{EvaluationDomain, Evaluations};

use super::indexer::{ChildMap, DataIndex, NodeSlotMap};
use crate::trie::{
    node::{errors::NodeError, internal::TerminationPath, Node},
    verkle::VerkleTrie,
};

impl<'a> VerkleTrie<'a> {
    pub fn _create_verkle_path(&mut self, key: &Key) -> Result<VerklePath, NodeError> {
        find_commitment_path(
            self.root_index,
            &mut self.data_indexer,
            &self.child_map,
            self.width,
            key,
            self.ck,
        )
    }
}

pub fn commitment_from_poly(
    data_index: DataIndex,
    sm: &mut NodeSlotMap,
    // If the polynomial for the branch node is already computed,
    // we can commit to it and save the commitment.
    // This must be the corresponding polynomial for the branch node
    // or the proof will fail.
    precomputed_polynomial: &Evaluations<Fr>,
    ck: &dyn LagrangeCommitter<Bls12_381>,
) -> VerkleCommitment {
    let kzg10_commitment = ck.commit_lagrange(&precomputed_polynomial.evals).unwrap();

    let node = sm.get_mut(data_index).as_mut_internal();
    node.commitment = Some(kzg10_commitment);
    kzg10_commitment
}

//XXX: This has not been modified for the new structure
pub fn find_commitment_path(
    data_index: DataIndex,
    sm: &mut NodeSlotMap,
    child_map: &ChildMap,
    width: usize,
    key: &Key,
    ck: &dyn LagrangeCommitter<Bls12_381>,
) -> Result<VerklePath, NodeError> {
    let termination_path = find_termination_path(data_index, sm, child_map, width, key)?;

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
        super::compute_polynomial_evaluations(data_index, width, sm, child_map, ck);
    let root_commitment = commitment_from_poly(data_index, sm, &root_branch_poly, ck);

    let node = sm.get_mut(data_index).as_mut_internal();
    node.commitment = Some(root_commitment);

    polynomials.push(root_branch_poly);
    commitments.push(root_commitment);

    for branch_node_index in node_indices.iter() {
        let branch_poly =
            super::compute_polynomial_evaluations(*branch_node_index, width, sm, child_map, ck);
        let branch_commitment = commitment_from_poly(*branch_node_index, sm, &branch_poly, ck);

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
    let leaf_hash = sm.get(last_node_index).as_leaf_ext().hash(width);
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

pub fn find_termination_path(
    root_index: DataIndex,
    data_indexer: &NodeSlotMap,
    child_map: &ChildMap,
    width: usize,
    key: &Key,
    // XXX: Can we remove the nodes vector as we have node_indices?
) -> Result<TerminationPath, NodeError> {
    let mut path_bits = Vec::with_capacity(3);
    let mut node_indices = Vec::with_capacity(3);

    let mut curr_node = root_index;
    for path_bit in key.path_indices(width) {
        let node_index = child_map
            .child(curr_node, path_bit)
            .ok_or(NodeError::UnexpectedEmptyNode)?;

        path_bits.push(path_bit);
        node_indices.push(node_index);

        match data_indexer.get(node_index) {
            Node::Internal(_) => {
                curr_node = node_index;
            }
            Node::LeafExt(leaf) => {
                // A key has been found, however it may not be the key we are looking for
                todo!()
                // if leaf.key() != key {
                //     return Err(NodeError::WrongLeafNode {
                //         leaf_found: leaf.key().clone(),
                //     });
                // }
                // return Ok(TerminationPath {
                //     path_bits,
                //     node_indices,
                // });
            }
            Node::Hashed(_) => return Err(NodeError::UnexpectedHashNode),
            Node::Empty => return Err(NodeError::UnexpectedEmptyNode),
            Node::Value(_) => todo!(),
        }
    }

    return Err(NodeError::BranchNodePath);
}

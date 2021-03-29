use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::Evaluations;
use merlin::Transcript;

use crate::{
    kzg10::{self, CommitKey, OpeningKey},
    VerkleCommitment,
};
// This module is used to create and verify proofs, given a Verkle path or a Verkle proof respectively
//
/// The VerklePath is used to indirectly prove that a specific value exists
/// at a specific key.
///
/// When finding the path to a leaf node
// At each level in the trie, there will either be a
/// an inner/branch node or the leaf node.
///
/// In order to prove that a value is present at a particular key
/// we need three things:
///
/// Lets imagine we are at the termination node and we have a `Key`.
///
/// The termination node, is the leaf node which contains the value corresponding to the Key.
///
/// If the Trie implementation is correct, there should be a path from the termination node
/// to the root node.
///
/// Let's denote the termination node as N_t and the root node as N_0.
/// To explain, I will go from N_t to N_0, however the algorithm itself
/// goes from N_0 to N_t
///
/// 1) We are at the termination node, there is necessarily a path from a branch node
/// to this termination node.
/// This path has a 10 bit index, which allows the branch node to point to N_t.
/// ie, given a path index and N_{t-1} we can arrive at N_t
///
/// This path index is included in the Verkle path.
///
/// 2) We are still at N_t, we take the Hash of this node and also save it as H_t
///
/// 3) We now look at N_{t-1} which is necessarily a branch node, and we compute the
/// commitment for N_{t-1}
///
/// In the above case,  N_t was a leaf node and the node before it was a branch node
/// Lets see how things are when N_{t-1} is a branch node and N_{t-2} is also a branch node
///
/// 1) The path index is stored again. There is necessarily a path from this N_{t-1} to N_{t-2}
///
/// 2) We are at N_{t-1} which is a branch node, we need to take the hash of this
/// The hash of a branch node is the hash of it's children's Hash
/// Example, since N_{t-1} only has one child, the termination node, it's hash is computed as H(H_t)
///
/// 3) We now look at N_{t-2} and compute the commitment for it.
///
/// Notice that the commitment for a branch node is over _all_ of it's children
/// While the Hash is computed for the child at the path index.
///
/// Notice that LeafNodes cannot be committed to in the algorithm, only branch nodes!
///
/// Also concatenating all of the path indices together, gives the `Key`
///
pub struct VerklePath {
    pub omega_path_indices: Vec<Fr>,
    pub node_roots: Vec<Fr>,
    /// For a branch node to make a commitment, it first creates an array 2^{width} Field elements
    /// all initialised to be zero. Let's call this array A, and A[i] indicates the ith element in the array
    ///
    /// We iterate each of its 1024 children, there are three cases:
    //
    // The child is empty:
    //
    // In this case, we leave the corresponding entry in the array as zero
    // For example, if we were looking at the first child and it was empty:
    // We would leave A[0] as zero.
    //
    // The child is a leaf:
    //
    // In this case, we hash the leaf and convert it to a field element by reducing modulo the field order.
    // We then replace the corresponding entry in the array with this value.
    // For example, if the fifth entry in the array was a leaf, we would compute k = HashToFr(leaf)
    // Then do A[4] = k (I use 4 because the array index starts at 0)
    //
    // The child is a branch node:
    //
    // First I note that we cannot have an unlimited amount of branch nodes. We eventually need
    // to get to a leaf or an empty node. This is necessarily true as soon as we set the width and key size.
    // If we have a branch node, then we need to compute the commitment of that branch node,
    // which recursively calls this algorithm again.
    //
    // BUT this algorithm produces a Commitment and not a FieldElement.So once we get the commitment from
    // the child branch, we compress and encode it in byte format, then call HashToFr on the byte representation.
    //
    // One thing to note: In the golang impl HashToFr takes the output of a Hash and reduces it,
    // While the explanation here assumes the data is hashed inside of HashToFr.
    pub commitments: Vec<VerkleCommitment>,
    pub polynomials: Vec<Evaluations<Fr>>,
}

impl VerklePath {
    pub fn create_proof(&self, ck: &CommitKey<Bls12_381>) -> VerkleProof {
        let mut transcript = Transcript::new(b"verkle_proof");

        assert!(
            self.polynomials.len() > 0,
            "to create a verkle proof, you must have at least one polynomial"
        );

        // XXX: open_multipoint should take an optional vector of commitments
        // Currently, the polynomials are being committed to inside of KZG10 also.

        let proof = ck
            .open_multipoint_lagrange(
                &self.polynomials,
                &self.node_roots,
                &self.omega_path_indices,
                &mut transcript,
            )
            .unwrap();
        VerkleProof { proof }
    }
}
// At the moment, no aggregation is being done
// So there is a proof per branch node
pub struct VerkleProof {
    proof: kzg10::AggregateProofMultiPoint<ark_bls12_381::Bls12_381>,
}

impl VerkleProof {
    pub fn verify(
        &self,
        vk: &OpeningKey<Bls12_381>,
        commitments: &[VerkleCommitment],
        path_indices: &[Fr],
        children_hashes: &[Fr],
    ) -> bool {
        let mut transcript = Transcript::new(b"verkle_proof");

        let commitments: Vec<kzg10::Commitment<ark_bls12_381::Bls12_381>> = commitments
            .into_iter()
            .map(|c| kzg10::Commitment::from_affine(*c.as_repr()))
            .collect();

        vk.check_multi_point(
            self.proof,
            &mut transcript,
            &commitments,
            path_indices,
            children_hashes,
        )
    }
}

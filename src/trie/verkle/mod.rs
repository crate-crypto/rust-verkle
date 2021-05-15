/// This is the default implementation of the VerkleTrie trait
///
use self::indexer::{ChildMap, DataIndex, NodeSlotMap};
use crate::{kzg10::VerkleCommitter, trie::node::errors::NodeError};

use crate::trie::node::internal::InternalNode;
use crate::trie::VerkleTrait;
use crate::{kzg10::CommitKey, trie::node::Node, verkle::VerklePath, Key, Value, VerkleCommitment};
use ark_bls12_381::Bls12_381;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};

pub(crate) mod indexer;
mod verkle_find_path;
mod verkle_get;
mod verkle_insert;

#[derive(Clone)]
pub struct VerkleTrie<'a> {
    pub(crate) root_index: DataIndex,
    pub(crate) data_indexer: NodeSlotMap,
    pub(crate) child_map: ChildMap,
    pub(crate) width: usize,
    pub(crate) ck: &'a dyn VerkleCommitter<Bls12_381>,
}

impl<'a> VerkleTrie<'_> {
    pub fn new(width: usize, ck: &'a CommitKey<Bls12_381>) -> VerkleTrie<'a> {
        // Initialise the slot map to store the node data
        let mut data_indexer = NodeSlotMap::new();

        // Create the root node
        let root = InternalNode::new();
        // Store the root node in the slot map
        let root_index = data_indexer.index(Node::Internal(root));

        // Initialise the ChildMap for storing node relations
        let child_map = ChildMap::new();

        VerkleTrie {
            root_index,
            data_indexer,
            child_map,
            width,
            ck,
        }
    }

    pub fn commit_key(&self) -> &dyn VerkleCommitter<Bls12_381> {
        self.ck
    }
}

impl<'a> VerkleTrait for VerkleTrie<'a> {
    fn get(&self, key: &Key) -> Result<Value, NodeError> {
        self._get(key)
    }

    fn insert(&mut self, key_values: impl Iterator<Item = (Key, Value)>) -> VerkleCommitment {
        for kv in key_values {
            self._insert(kv.0, kv.1);
        }
        self.compute_root()
    }

    fn insert_single(&mut self, key: Key, value: Value) -> VerkleCommitment {
        self.insert(std::iter::once((key, value)))
    }

    fn compute_root(&mut self) -> VerkleCommitment {
        commitment(
            self.root_index,
            self.width,
            &mut self.data_indexer,
            &self.child_map,
            self.ck,
        )
    }

    fn create_verkle_path(&mut self, key: &Key) -> Result<VerklePath, NodeError> {
        self._create_verkle_path(key)
    }
}

use ark_bls12_381::Fr;
use ark_ff::Zero;

pub fn compute_evaluations(
    data_index: DataIndex,
    width: usize,
    child_map: &ChildMap,
    sm: &mut NodeSlotMap,
    ck: &dyn VerkleCommitter<Bls12_381>,
) -> Vec<Fr> {
    let children = child_map.children(data_index);
    let mut polynomial_eval = vec![Fr::zero(); 1 << width];

    // XXX: make this parallel. May require switching to an iterator with Map
    for (i, child_data_index) in children.into_iter() {
        let child = sm.get(child_data_index);

        match child {
            Node::Internal(_) => {
                // XXX: We can make this take a reference to sm and then update all
                // of the commitments after this for loop. Then this can be parallel
                let eval = commitment(child_data_index, width, sm, child_map, ck)
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

pub fn commitment(
    // the data index for this internal node
    data_index: DataIndex,
    width: usize,
    sm: &mut NodeSlotMap,
    child_map: &ChildMap,
    ck: &dyn VerkleCommitter<Bls12_381>,
) -> VerkleCommitment {
    // First get the internal node to check if it's commitment is cached
    let node = *sm.get(data_index).as_internal();

    if let VerkleCommitment::Computed(_) = node.commitment {
        return node.commitment;
    }
    let poly = compute_polynomial_evaluations(data_index, width, sm, child_map, ck);
    let kzg10_commitment = ck.commit_lagrange(&poly.evals).unwrap();
    let node = sm.get_mut(data_index).as_mut_internal();
    node.commitment = VerkleCommitment::Computed(kzg10_commitment);
    node.commitment
}

// XXX: We can remove this and just use compute_evaluations
// We will not return Vec<Fr> but a new type that wraps it
pub fn compute_polynomial_evaluations(
    data_index: DataIndex,
    width: usize,
    sm: &mut NodeSlotMap,
    child_map: &ChildMap,
    ck: &dyn VerkleCommitter<Bls12_381>,
) -> Evaluations<Fr> {
    let evaluations = compute_evaluations(data_index, width, child_map, sm, ck);

    let num_children = 1 << width;
    let d = GeneralEvaluationDomain::<Fr>::new(num_children).unwrap();
    Evaluations::from_vec_and_domain(evaluations.to_vec(), d)
}

use crate::{kzg10::CommitKey, trie::node::Node, verkle::VerklePath, Key, Value, VerkleCommitment};
use ark_bls12_381::Bls12_381;
use node::internal::InternalNode;

use self::node::errors::NodeError;

pub mod indexer;
pub mod node;
use indexer::DataIndex;
use indexer::NodeSlotMap;

pub struct VerkleTrie {
    root_index: DataIndex,
    data_indexer: NodeSlotMap,
}

impl VerkleTrie {
    pub fn new(width: usize) -> VerkleTrie {
        let mut data_indexer = NodeSlotMap::new();
        let root = InternalNode::new(0, width);
        let root_index = data_indexer.index(Node::Internal(root));
        VerkleTrie {
            root_index,
            data_indexer,
        }
    }
    pub fn insert(&mut self, key: Key, value: Value) {
        InternalNode::insert2(self.root_index, key, value, &mut self.data_indexer).unwrap();
    }
    pub fn get(&mut self, key: &Key) -> Result<&Value, NodeError> {
        let root = self.data_indexer.get(&self.root_index).as_internal();
        root.get(key, &self.data_indexer)
    }

    pub fn compute_root_commitment(
        &mut self,
        commit_key: &CommitKey<Bls12_381>,
    ) -> VerkleCommitment {
        InternalNode::commitment(self.root_index, &mut self.data_indexer, commit_key)
    }

    // Creates a verkle path for the given key
    pub fn create_path(
        &mut self,
        key: &Key,
        commit_key: &CommitKey<Bls12_381>,
    ) -> Result<VerklePath, NodeError> {
        InternalNode::find_commitment_path(
            self.root_index,
            &mut self.data_indexer,
            &key,
            commit_key,
        )
    }

    #[cfg(test)]
    fn find_node_with_path(
        &mut self,
        key: &Key,
    ) -> Result<node::internal::TerminationPath, NodeError> {
        let root = self.data_indexer.get(&self.root_index).as_internal();
        root.find_termination_path(&self.data_indexer, key)
    }

    #[cfg(test)]
    fn root_node(&self) -> InternalNode {
        self.data_indexer.get(&self.root_index).clone().internal()
    }
    #[cfg(test)]
    fn root_children_types(&self) -> Vec<u8> {
        let root = self.data_indexer.get(&self.root_index).as_internal();
        self.children_types(root)
    }
    #[cfg(test)]
    fn children_types(&self, internal: &InternalNode) -> Vec<u8> {
        internal.children_types(&self.data_indexer)
    }

    #[cfg(test)]
    fn root_children(&self, index: usize) -> Node {
        let root = self.data_indexer.get(&self.root_index).as_internal();
        self.get_child(root, index)
    }

    #[cfg(test)]
    fn get_child(&self, internal_node: &InternalNode, index: usize) -> Node {
        let first_child_node_idx = internal_node.children.get_child(index).unwrap();
        self.data_indexer.get(&first_child_node_idx).clone()
    }
}

#[cfg(test)]
mod test {
    use crate::trie::node::{EMPTY_NODE_TYPE, INTERNAL_NODE_TYPE, LEAF_NODE_TYPE};

    use super::VerkleTrie;
    use crate::kzg10::{CommitKey, OpeningKey, PublicParameters};
    use crate::trie::node::{internal::InternalNode, Node};
    use crate::{Key, Value};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::EvaluationDomain;
    use rand::Rng;
    use rand_core::OsRng;

    #[test]
    fn basic_same_insert() {
        let mut tree = VerkleTrie::new(10);
        for _ in 0..100 {
            tree.insert(Key::zero(), Value::zero());
        }
    }

    #[test]
    fn basic_insert_key() {
        let mut tree = VerkleTrie::new(8);

        let value = Value::from_arr([1u8; 32]);
        tree.insert(Key::zero(), value);

        let child_node = tree.root_children(0);
        let leaf_node = child_node.as_leaf();

        assert_eq!(leaf_node.key, Key::zero());
        assert_eq!(leaf_node.value, value);
    }
    #[test]
    fn basic_get() {
        let mut tree = VerkleTrie::new(10);

        tree.insert(Key::zero(), Value::zero());
        let val = tree.get(&Key::zero()).unwrap();
        assert_eq!(val, &Value::zero());

        assert!(tree.get(&Key::one()).is_err());

        tree.insert(Key::one(), Value::one());
        let val = tree.get(&Key::one()).unwrap();
        assert_eq!(val, &Value::one());
    }
    #[test]
    fn longest_path_insert() {
        let mut tree = VerkleTrie::new(10);
        let zero = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let first_value = Value::from_arr([1u8; 32]);

        let one = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let second_value = Value::from_arr([2u8; 32]);

        tree.insert(zero, first_value);
        tree.insert(one, second_value);
    }

    #[test]
    fn check_longest_path_insert() {
        let width = 10;
        let mut tree = VerkleTrie::new(width);
        let zero = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let first_value = Value::from_arr([1u8; 32]);

        let one = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let second_value = Value::from_arr([2u8; 32]);

        tree.insert(zero, first_value);
        tree.insert(one, second_value);

        // All children should be empty except for the first one which should be
        // an internal node. This repeats until the last children
        // Since we are offsetting by 10 bits, and the key is 256 bits.
        // We should have 26 children altogether.

        let mut vec = vec![EMPTY_NODE_TYPE; 1 << width];
        vec[0] = INTERNAL_NODE_TYPE;
        let mut depth = 0;

        assert_eq!(tree.root_children_types()[0], INTERNAL_NODE_TYPE);

        // Now extract the internal node at position 0
        // First child
        let mut internal = tree.root_children(0).internal();

        // All of the other nodes are exactly the same, except for the last child
        // Repeat the same check we did for first node 24 times.
        for i in 1..=24 {
            depth = depth + 10;
            assert_eq!(internal.depth, depth, "i is {}", i);
            assert_eq!(internal.children_types(&tree.data_indexer), vec);

            // extract the first child as the new internal
            internal = tree.get_child(&internal, 0).internal();
        }

        // The last child should have two leaves
        let mut vec = vec![EMPTY_NODE_TYPE; 1 << width];
        vec[0] = LEAF_NODE_TYPE;
        vec[1] = LEAF_NODE_TYPE;

        let first_child = tree.get_child(&internal, 0);
        let second_child = tree.get_child(&internal, 1);

        let leaf_node = first_child.as_leaf();
        assert_eq!(leaf_node.key, Key::zero());
        assert_eq!(leaf_node.value, first_value);

        let leaf_node = second_child.as_leaf();
        assert_eq!(leaf_node.key, Key::one());
        assert_eq!(leaf_node.value, second_value);

        assert_eq!(tree.children_types(&internal), vec);
    }

    #[test]
    fn check_width_8_termination_path() {
        let mut tree = VerkleTrie::new(8);
        let a = Key::from_arr([
            1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let b = Key::from_arr([
            1, 2, 3, 4, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        tree.insert(a, Value::zero());
        tree.insert(b, Value::zero());

        let mut term_path = tree.find_node_with_path(&b).unwrap();

        assert_eq!(term_path.path_bits.len(), 6);
        assert_eq!(term_path.path_bits, vec![1, 2, 3, 4, 5, 7]);

        assert_eq!(term_path.node_indices.len(), 6);

        // The last node will be the leaf node containing the value
        let leaf_data_index = term_path.node_indices.pop().unwrap();
        let path_to_last_node = term_path.path_bits.pop().unwrap();

        // The other nodes should be internal nodes
        let mut current_internal_node = tree.root_node();
        for (path_index, node_index) in term_path
            .path_bits
            .iter()
            .zip(term_path.node_indices.iter())
        {
            let child_data_index = current_internal_node
                .children
                .get_child(*path_index)
                .unwrap();
            assert_eq!(&child_data_index, node_index);
            current_internal_node = tree.data_indexer.get(&child_data_index).clone().internal();
        }

        let last_node_data_index = current_internal_node
            .children
            .get_child(path_to_last_node)
            .unwrap();
        assert_eq!(last_node_data_index, leaf_data_index);

        let leaf_node = tree.data_indexer.get(&last_node_data_index).as_leaf();

        assert_eq!(leaf_node.key, b);
        assert_eq!(leaf_node.value, Value::zero());
    }

    #[test]
    fn insert_first_last_child() {
        let mut tree = VerkleTrie::new(10);

        let first_value = Value::from_arr([1u8; 32]);
        let last_value = Value::from_arr([2u8; 32]);

        tree.insert(Key::zero(), first_value);
        tree.insert(Key::max(), last_value);

        let first_child_node = tree.root_children(0);
        let leaf_node = first_child_node.as_leaf();
        assert_eq!(leaf_node.key, Key::zero());
        assert_eq!(leaf_node.value, first_value);

        let num_children = tree.root_node().children.len();
        let last_child_node = tree.root_children(num_children - 1);
        let leaf_node = last_child_node.as_leaf();
        assert_eq!(leaf_node.key, Key::max());
        assert_eq!(leaf_node.value, last_value);
    }

    #[test]
    fn dankrads_example_with_32_bits_automatic() {
        // This is the same example as above, however we use an algorithm to collect the verkle path
        // for the first key instead of manually checking and testing
        let width = 10;
        let (ck, vk) = setup_test(1 << width);

        let mut tree = VerkleTrie::new(width);

        // This first key is the leaf I am trying to create a proof for
        let first_key = Key::from_arr([
            80, 0, 0, 0, //
            0, 1, 1, 1, //
            1, 0, 1, 0, //
            1, 1, 1, 1, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);
        let first_value = Value::from_arr([
            1, 2, 1, 3, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);

        // This key shares 20 bits with the first key
        let second_key = Key::from_arr([
            80, 0, 8, 1, //
            0, 1, 1, 1, //
            0, 0, 0, 1, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);

        let (shared_path, _, _) = Key::path_difference(&first_key, &second_key, width);
        assert_eq!(shared_path.len(), 2);
        let second_value = Value::from_arr([
            4, 4, 4, 4, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);

        // this key shares 10 bits with the first
        let third_key = Key::from_arr([
            80, 32, 48, 1, //
            0, 0, 0, 1, //
            1, 1, 1, 1, //
            0, 0, 1, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);
        let third_value = Value::from_arr([
            1, 3, 5, 4, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);
        // this key shares 10 bits with the first

        let fourth_key = Key::from_arr([
            80, 48, 0, 1, //
            1, 1, 0, 1, //
            0, 1, 1, 1, //
            0, 1, 1, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);
        let fourth_value = Value::from_arr([
            6, 6, 6, 6, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
            0, 0, 0, 0, //
        ]);

        tree.insert(fourth_key, fourth_value);
        tree.insert(first_key, first_value);
        tree.insert(second_key, second_value);
        tree.insert(third_key, third_value);
        let verkle_path = InternalNode::find_commitment_path(
            tree.root_index,
            &mut tree.data_indexer,
            &first_key,
            &ck,
        )
        .unwrap();

        // Check consistency with manual checks
        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(1 << width).unwrap();

        assert_eq!(verkle_path.omega_path_indices.len(), 3);
        let expected_indices = vec![domain.element(320), domain.element(0), domain.element(0)];
        assert_eq!(expected_indices, verkle_path.omega_path_indices);
        let verkle_proof = verkle_path.create_proof(&ck);

        assert!(verkle_proof.verify(
            &vk,
            &verkle_path.commitments,
            &expected_indices,
            &verkle_path.node_roots,
        ));
    }

    // use crate::kzg10::{CommitKey, OpeningKey, PublicParameters};
    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(num_children: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let degree = num_children - 1;
        let srs = PublicParameters::setup(degree, &mut OsRng).unwrap();
        srs.trim(degree).unwrap()
    }
}

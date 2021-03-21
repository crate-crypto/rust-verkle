use crate::{kzg10::CommitKey, trie::node::Node, verkle::VerklePath, Key, Value};
use ark_bls12_381::Bls12_381;
use node::internal::InternalNode;
use slotmap::{new_key_type, SlotMap};

use self::node::errors::NodeError;

pub mod node;

// NodeIndex is used to refer to Nodes in the arena allocator.
// A better name might be DataIndex.
new_key_type! {pub struct NodeIndex;}
pub type NodeSlotMap = slotmap::SlotMap<crate::trie::NodeIndex, node::Node>;

pub struct VerkleTrie {
    pub root: InternalNode,
    slot_map: SlotMap<NodeIndex, Node>,
}

impl VerkleTrie {
    pub fn new() -> VerkleTrie {
        let mut slot_map = SlotMap::with_key();
        let root = InternalNode::new(0, &mut slot_map);
        VerkleTrie { root, slot_map }
    }

    pub fn insert(&mut self, key: Key, value: Value) {
        self.root.insert(key, value, &mut self.slot_map).unwrap();
    }
    // Creates a verkle path for the given key
    pub fn create_path(
        &mut self,
        key: &Key,
        commit_key: &CommitKey<Bls12_381>,
    ) -> Result<VerklePath, NodeError> {
        self.root
            .find_commitment_path(&mut self.slot_map, &key, commit_key)
    }

    #[cfg(test)]
    fn root_children(&self, index: usize) -> Node {
        self.get_child(&self.root, index)
    }
    #[cfg(test)]
    fn get_child(&self, internal_node: &InternalNode, index: usize) -> Node {
        let first_child_node_idx = internal_node.children[index];
        self.slot_map[first_child_node_idx].clone()
    }
    #[cfg(test)]
    fn root_children_types(&self) -> Vec<u8> {
        self.children_types(&self.root)
    }
    #[cfg(test)]
    fn children_types(&self, internal: &InternalNode) -> Vec<u8> {
        internal.children_types(&self.slot_map)
    }
}

#[cfg(test)]
mod test {
    use crate::trie::node::internal::NUM_CHILDREN;
    use crate::trie::node::{EMPTY_NODE_TYPE, INTERNAL_NODE_TYPE, LEAF_NODE_TYPE};

    use super::VerkleTrie;
    use crate::kzg10::{CommitKey, OpeningKey, PublicParameters};
    use crate::trie::node::Node;
    use crate::{Key, Value};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_poly::EvaluationDomain;
    use rand_core::OsRng;

    #[test]
    fn insert_first_last() {
        let mut tree = VerkleTrie::new();

        let first_value = Value::from_arr([1u8; 32]);
        let last_value = Value::from_arr([2u8; 32]);

        tree.insert(Key::zero(), first_value);
        tree.insert(Key::max(), last_value);

        let first_child_node = tree.root_children(0);
        if let Node::Leaf(leaf_node) = first_child_node {
            assert_eq!(leaf_node.value, first_value);
        } else {
            panic!(
                "there should be a leaf node in the first position, found {:?}",
                first_child_node
            )
        }

        let num_children = tree.root.children.len();
        let last_child_node = tree.root_children(num_children - 1);
        if let Node::Leaf(leaf_node) = last_child_node {
            assert_eq!(leaf_node.value, last_value);
        } else {
            panic!(
                "there should be a leaf node in the last position, found {:?}",
                last_child_node
            )
        }
    }

    #[test]
    fn insert_one() {
        let mut tree = VerkleTrie::new();

        let value = Value::from_arr([1u8; 32]);
        tree.insert(Key::zero(), value);

        let child_node = tree.root_children(0);
        if let Node::Leaf(leaf_node) = child_node {
            assert_eq!(leaf_node.value, value);
        } else {
            panic!("this should be a leaf node, found {:?}", child_node)
        }
    }

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test() -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let degree = NUM_CHILDREN;
        let srs = PublicParameters::setup(degree, &mut OsRng).unwrap();
        srs.trim(degree).unwrap()
    }

    #[test]
    fn insert_long_path() {
        let mut tree = VerkleTrie::new();
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

        let mut vec = vec![EMPTY_NODE_TYPE; NUM_CHILDREN];
        vec[0] = INTERNAL_NODE_TYPE;
        let mut depth = 0;
        assert_eq!(tree.root_children_types(), vec);
        assert_eq!(tree.root.depth, depth);

        // Now extract the internal node at position 0
        // First child
        let mut internal = if let Node::Internal(internal) = tree.root_children(0) {
            internal
        } else {
            panic!("first node should be internal")
        };

        // All of the other nodes are exactly the same, except for the last child
        // Repeat the same check we did for first node 24 times.
        for i in 1..=24 {
            depth = depth + 10;
            assert_eq!(internal.depth, depth, "i is {}", i);
            assert_eq!(internal.children_types(&tree.slot_map), vec);

            // extract the first child as the new internal
            internal = if let Node::Internal(internal) = tree.get_child(&internal, 0) {
                internal
            } else {
                panic!("first node should be internal")
            };
        }

        // The last child should have two leaves
        let mut vec = vec![EMPTY_NODE_TYPE; NUM_CHILDREN];
        vec[0] = LEAF_NODE_TYPE;
        vec[1] = LEAF_NODE_TYPE;

        let first_child = tree.get_child(&internal, 0);
        let second_child = tree.get_child(&internal, 1);

        if let Node::Leaf(leaf_node) = first_child {
            assert_eq!(leaf_node.key, Key::zero());
            assert_eq!(leaf_node.value, first_value);
        } else {
            panic!("expected a leaf node at the first position")
        }

        if let Node::Leaf(leaf_node) = second_child {
            assert_eq!(leaf_node.key, Key::one());
            assert_eq!(leaf_node.value, second_value);
        } else {
            panic!("expected a leaf node at the first position")
        }

        assert_eq!(tree.children_types(&internal), vec);
    }

    #[test]
    fn dankrads_example_with_32_bits_manual() {
        // This example is similar to dankrads example
        // In dankrads example, the width was 4 bits, while in this example, the width is 10
        //
        // To simulate similar conditions, we need to have a path with two branch nodes,
        // which means that the chosen leaf node needs to share 20 bits with another node

        let (ck, vk) = setup_test();

        let mut tree = VerkleTrie::new();

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

        let (shared_path, _, _) = Key::path_difference(&first_key, &second_key);
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

        // So the world view is that two keys have been inserted.
        // The prover and verifier both know the root commitment
        let root_poly = tree.root.compute_polynomial(&tree.slot_map, &ck);

        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(NUM_CHILDREN).unwrap();

        // All of the keys start with 80,0
        // in binary this is 0101 0000 0000 which is 320 2^6 + 2^8
        //
        //
        let mut branch_node_level_1 = if let Node::Internal(internal) = tree.root_children(320) {
            internal
        } else {
            panic!(
                "expected inner node A, to be at the index 320, got {:?}",
                tree.root.children[320]
            )
        };
        let root_inner_node_a = branch_node_level_1
            .commitment(&tree.slot_map, &ck)
            .to_hash()
            .to_fr();

        // Lets manually traverse the trie from the top and check each commitment is correct
        //
        // This is level 0, where the root is.
        //
        // The first check is that root_poly(0101_0000_00) = H(N_1)
        // N_1 here means the branch node that is on the first level.
        // In Dankrad's diagram, this is inner node a
        //
        let proof_a = ck
            .open_single(&root_poly, None, &root_inner_node_a, &domain.element(320))
            .unwrap();
        let ok = vk.check(domain.element(320), proof_a);
        assert!(ok);

        // Lets move to level 1.
        //
        // We are now looking for the next 10 bits that are shared
        //
        // Remember Key1 = 80,0,0 = 0101_0000 , 0000_0000, 0000_0000 = [0101000000], [0000000000] , [0000,...]
        // Remember Key2 = 80,0,8 = 0101_0000 , 0000_0000, 0000_1000 = [0101000000], [0000000000], [1000,...]
        //
        // As you can see, the keys differ after the second group of 10 bits.
        // The second group of 10 bits, also tells us where the child branch node is located in N_1
        // at 0
        //
        // The next check is to check that N_1_poly(0000_0000_00) = H(N_2)

        let branch_node_level_2 =
            if let Node::Internal(internal) = tree.get_child(&branch_node_level_1, 0) {
                internal
            } else {
                panic!(
                    "expected inner node B, to be at the index 0, got {:?}",
                    branch_node_level_1.children[0],
                )
            };

        let n_1_poly = branch_node_level_2.compute_polynomial(&tree.slot_map, &ck);
        let branch_node_level_3 = if let Node::Leaf(leaf) = tree.get_child(&branch_node_level_2, 0)
        {
            leaf
        } else {
            panic!(
                "expected leaf node, to be at the index 0, got {:?}",
                branch_node_level_2.children[0]
            )
        };
        let c_fr = branch_node_level_3.hash().to_fr();
        let proof_a = ck
            .open_single(&n_1_poly, None, &c_fr, &domain.element(0))
            .unwrap();
        let ok = vk.check(domain.element(0), proof_a);
        assert!(ok);
    }
    #[test]
    fn dankrads_example_with_32_bits_automatic() {
        // This is the same example as above, however we use an algorithm to collect the verkle path
        // for the first key instead of manually checking and testing
        let (ck, vk) = setup_test();

        let mut tree = VerkleTrie::new();

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

        let (shared_path, _, _) = Key::path_difference(&first_key, &second_key);
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

        let verkle_path = tree
            .root
            .find_commitment_path(&mut tree.slot_map, &first_key, &ck)
            .unwrap();

        // Check consistency with manual checks
        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(NUM_CHILDREN).unwrap();

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
}

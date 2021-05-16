use self::node::errors::NodeError;
use crate::{verkle::VerklePath, Key, Value, VerkleCommitment};

// Can we trivially add node type information to DataIndex?
// We could fetch it, but that is a get method
// Can we also ensure that adding into childmap has type information? only internal node

pub mod node;
pub mod verkle;
pub use verkle::VerkleTrie;

/// Trait to describe the VerkleTrie implementation.
/// This does not include proof creation, but does expose functions to get all of the information needed
/// to create a proof.
///
/// XXXX: This trait relies on the KZG trait for commitments. We need to create it, so that we can parametrize
/// VerkleTrieTrait. Alternatively, we can just parametrize the VerkleTrie struct
pub trait VerkleTrait {
    /// Inserts multiple values into the trie, recomputes the root
    /// using the pippenger.
    ///
    /// Note: it is not possible to insert a value without recomputing the root
    /// This avoids any complications where one may insert without updating the root, and
    /// then one updates a different key.
    ///
    /// Update assumes that all commitments in the trie are updated
    fn insert(&mut self, kv: impl Iterator<Item = (Key, Value)>) -> VerkleCommitment;
    /// Inserts a single value and computes it's root using pippenger.
    // XXX: Can we remove this and just use update? or use update under the hood
    // update should be cheaper since it is a single value
    fn insert_single(&mut self, key: Key, value: Value) -> VerkleCommitment;
    /// Gets the value at the `Key` if it exists
    /// Returns an error if it does not exist
    // XXX: This should return a reference to &Value, as the data might be large
    fn get(&self, key: &Key) -> Result<Value, NodeError>;

    // // updates a key's value and recomputes the delta
    // fn update(&mut self, key : Key, value : Value);

    /// Computes the root of the trie
    fn compute_root(&mut self) -> VerkleCommitment;

    /// Creates a verkle path which can be used to create a verkle proof
    fn create_verkle_path(&mut self, key: &Key) -> Result<VerklePath, NodeError>;
}

#[cfg(test)]
mod test {
    use crate::trie::node::{EMPTY_NODE_TYPE, INTERNAL_NODE_TYPE, LEAF_NODE_TYPE};

    use super::verkle::VerkleTrie;
    use super::VerkleTrait;
    use crate::kzg10::{commit_key_coeff::CommitKey, OpeningKey, PublicParameters};
    use crate::trie::node::internal::InternalNode;
    use crate::{Key, Value};
    use ark_bls12_381::{Bls12_381, Fr};

    // use crate::kzg10::{CommitKey, OpeningKey, PublicParameters};
    // Creates a proving key and verifier key based on a specified degree
    fn test_kzg(width: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
        let degree = (1 << width) - 1;
        let srs = PublicParameters::<Bls12_381>::setup_from_secret(
            degree,
            Fr::from(8927347823478352432985u128),
        )
        .unwrap();
        (srs.commit_key, srs.opening_key)
    }

    #[test]
    fn basic_same_insert() {
        let width = 10;
        let (ck, _) = test_kzg(width);
        let mut tree = VerkleTrie::new(width, &ck);

        for _ in 0..100 {
            tree.insert_single(Key::one(), Value::zero());
        }
    }

    #[test]
    fn basic_insert_key() {
        let width = 8;
        let (ck, _) = test_kzg(width);
        let mut tree = VerkleTrie::new(width, &ck);

        let value = Value::from_arr([1u8; 32]);
        tree.insert_single(Key::zero(), value);

        let child_data_index = tree.child_map.child(tree.root_index, 0).unwrap();
        let child_node = tree.data_indexer.get(child_data_index);

        let leaf_node = child_node.as_leaf();

        assert_eq!(leaf_node.key, Key::zero());
        assert_eq!(leaf_node.value, value);
    }

    #[test]
    fn basic_get() {
        let width = 10;
        let (ck, _) = test_kzg(width);
        let mut tree = VerkleTrie::new(width, &ck);

        tree.insert_single(Key::zero(), Value::one());
        let val = tree.get(&Key::zero()).unwrap();
        assert_eq!(val, Value::one());

        assert!(tree.get(&Key::one()).is_err());

        tree.insert_single(Key::one(), Value::one());
        let val = tree.get(&Key::one()).unwrap();
        assert_eq!(val, Value::one());
    }

    #[test]
    fn longest_path_insert() {
        // This solely tests whether we get an OOM error, this will not happen with
        // this implementation, but may happen if children are eagerly allocated.
        let width = 10;
        let (ck, _) = test_kzg(width);
        let mut tree = VerkleTrie::new(width, &ck);

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

        tree.insert_single(zero, first_value);
        tree.insert_single(one, second_value);
    }

    #[test]
    fn check_longest_path_insert() {
        let width = 10;
        let (ck, _) = test_kzg(width);
        let mut tree = VerkleTrie::new(width, &ck);

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

        tree.insert_single(zero, first_value);
        tree.insert_single(one, second_value);

        // All children should be empty except for the first one which should be
        // an internal node. This repeats until the last children
        // Since we are offsetting by 10 bits, and the key is 256 bits.
        // We should have 26 children altogether.

        let mut vec = vec![EMPTY_NODE_TYPE; 1 << width];
        vec[0] = INTERNAL_NODE_TYPE;

        let mut child_data_index = tree.root_index;

        // All of the nodes are exactly the same, except for the last child
        // Recursively Check 25 times that we have a branch node and the first child is also a branch node
        for _ in 0..25 {
            let child_types = InternalNode::children_types(
                child_data_index,
                1 << width,
                &tree.data_indexer,
                &tree.child_map,
            );

            assert_eq!(child_types, vec);

            // extract the first child as the new internal
            child_data_index = tree.child_map.child(child_data_index, 0).unwrap();
            let child_node = tree.data_indexer.get(child_data_index);
            assert_eq!(child_node.node_type(), INTERNAL_NODE_TYPE);
        }

        // The last inner node should have two leaves
        let mut vec = vec![EMPTY_NODE_TYPE; 1 << width];
        vec[0] = LEAF_NODE_TYPE;
        vec[16] = LEAF_NODE_TYPE;

        let child_types = InternalNode::children_types(
            child_data_index,
            1 << width,
            &tree.data_indexer,
            &tree.child_map,
        );
        assert_eq!(child_types, vec);

        let first_child = tree.child_map.child(child_data_index, 0).unwrap();
        let second_child = tree.child_map.child(child_data_index, 16).unwrap();

        let first_node = tree.data_indexer.get(first_child);
        let second_node = tree.data_indexer.get(second_child);

        let first_leaf_node = first_node.as_leaf();
        let second_leaf_node = second_node.as_leaf();

        assert_eq!(first_leaf_node.key, Key::zero());
        assert_eq!(first_leaf_node.value, first_value);

        assert_eq!(second_leaf_node.key, Key::one());
        assert_eq!(second_leaf_node.value, second_value);
    }
}

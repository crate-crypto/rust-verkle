#[deny(unreachable_patterns)]
pub mod committer;
pub mod config;
pub mod constants;
pub mod database;
pub mod proof;
pub mod to_bytes;
pub mod trie;

pub use config::*;
pub use trie::Trie;

pub use bandersnatch::{EdwardsProjective, Fr};

pub type Key = [u8; 32];
pub type Value = [u8; 32];
pub trait TrieTrait {
    /// Inserts multiple values into the trie
    /// If the number of items is below FLUSH_BATCH, they will be persisted
    /// atomically
    /// This method will implicitly compute the new root
    fn insert(&mut self, kv: impl Iterator<Item = (Key, Value)>);

    /// Inserts a single value
    /// This method will implicitly compute the new root
    fn insert_single(&mut self, key: Key, value: Value) {
        self.insert(vec![(key, value)].into_iter())
    }
    /// Gets the value at the `Key` if it exists
    /// Returns an error if it does not exist
    /// TODO: Find out if this method is ever needed
    fn get(&self, key: Key) -> Option<Value>;

    /// Returns the root of the trie
    fn root_hash(&self) -> Fr;

    /// Creates a verkle proof over many keys
    /// TODO: This will return a Result in the future
    fn create_verkle_proof(&self, key: impl Iterator<Item = Key>) -> proof::VerkleProof;
}

pub(crate) fn group_to_field(point: &EdwardsProjective) -> Fr {
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalSerialize;

    if point.is_zero() {
        return Fr::zero();
    }
    let mut bytes = [0u8; 32];
    point
        .serialize(&mut bytes[..])
        .expect("could not serialise point into a 32 byte array");
    Fr::from_le_bytes_mod_order(&bytes)
}

// TODO: Possible optimisation. This means we never allocate for paths
use smallvec::SmallVec;
pub type SmallVec32 = SmallVec<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;

    use ark_serialize::CanonicalSerialize;
    #[test]
    fn consistent_group_to_field() {
        // In python this is called commitment_to_field
        // print(commitment_to_field(Point(generator=True)).to_bytes(32, "little").hex())
        let expected = "37c6db79b111ea6cf47f80392239ea2bf2cc5579759b686773d5a361f7c8c50c";
        use ark_ec::ProjectiveCurve;

        let generator = EdwardsProjective::prime_subgroup_generator();
        let mut bytes = [0u8; 32];
        group_to_field(&generator)
            .serialize(&mut bytes[..])
            .unwrap();
        assert_eq!(hex::encode(&bytes), expected);
    }
}

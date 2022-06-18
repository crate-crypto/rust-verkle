#[deny(unreachable_patterns)]
pub mod committer;
pub mod config;
pub mod constants;
pub mod database;
pub mod from_to_bytes;
pub mod proof;
pub mod trie;
mod trie_fuzzer;

pub use config::*;
pub use trie::Trie;

pub use banderwagon::{Element, Fr};

pub type Key = [u8; 32];
pub type Value = [u8; 32];
pub type Stem = [u8; 31];

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

    /// Returns the root commitment of the trie
    fn root_commitment(&self) -> Element;

    /// Creates a verkle proof over many keys
    /// TODO: This will return a Result in the future
    fn create_verkle_proof(&self, key: impl Iterator<Item = Key>) -> proof::VerkleProof;
}

// Note: This is a 2 to 1 map, but the two preimages are identified to be the same
// TODO: Create a document showing that this poses no problems
pub(crate) fn group_to_field(point: &Element) -> Fr {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;

    let base_field = point.map_to_field();

    let mut bytes = [0u8; 32];
    base_field
        .serialize(&mut bytes[..])
        .expect("could not serialise point into a 32 byte array");
    println!("hex bytes {}", hex::encode(bytes));

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
        let expected = "d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14";

        let generator = Element::prime_subgroup_generator();
        let mut bytes = [0u8; 32];
        group_to_field(&generator)
            .serialize(&mut bytes[..])
            .unwrap();
        assert_eq!(hex::encode(&bytes), expected);
    }
}

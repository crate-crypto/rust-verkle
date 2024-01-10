#[deny(unreachable_patterns)]
// pub mod committer;
pub mod config;
pub mod constants;
pub mod database;
pub mod errors;
pub mod from_to_bytes;
pub mod proof;
pub mod trie;

pub use config::*;
use errors::ProofCreationError;
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
    fn create_verkle_proof(
        &self,
        key: impl Iterator<Item = Key>,
    ) -> Result<proof::VerkleProof, ProofCreationError>;
}

// TODO: remove this, its here for backwards compatibility
pub(crate) fn group_to_field(point: &Element) -> Fr {
    point.map_to_scalar_field()
}

// TODO: Possible optimization. This means we never allocate for paths
use smallvec::SmallVec;
pub type SmallVec32 = SmallVec<[u8; 32]>;

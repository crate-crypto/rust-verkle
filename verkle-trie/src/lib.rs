#[deny(unreachable_patterns)]
mod byte_arr;
pub mod database;
pub mod precompute;
pub mod proof;
pub mod trie;

pub type Key = [u8; 32];
pub type Value = [u8; 32];

use std::convert::TryInto;

use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use bandersnatch::EdwardsAffine;
pub use bandersnatch::{EdwardsProjective, Fr};
pub use trie::Trie;

pub const FLUSH_BATCH: u32 = 20_000;

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for EdwardsProjective {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..]).unwrap();
        bytes.to_vec()
    }
}

pub trait TrieTrait {
    /// Inserts multiple values into the trie, returning the recomputed root.
    /// If the number of items is below FLUSH_BATCH, they will be persisted
    /// atomically
    fn insert(&mut self, kv: impl Iterator<Item = (Key, Value)>) -> Fr;

    /// Inserts a single value and returns the root.
    fn insert_single(&mut self, key: Key, value: Value) -> Fr {
        self.insert(vec![(key, value)].into_iter())
    }
    /// Gets the value at the `Key` if it exists
    /// Returns an error if it does not exist
    fn get(&self, key: &Key) -> Result<Value, ()>;

    // It's possible to have an update API, where we update the
    // values already in the database and return those which are not
    // It's more efficient to make batch updates since no new
    // nodes are being added, and we can skip intermediate updates for a node
    // We can also alternatively, just return an error if the key's stem is missing
    // // updates a key's value and recomputes the delta
    // fn update(&mut self, kv: impl Iterator<Item = (Key, Value)>);

    /// Returns the root of the trie
    fn compute_root(&mut self) -> Fr;

    /// Creates a verkle proof over many keys
    fn create_verkle_proof(
        &mut self,
        key: impl Iterator<Item = Key>,
    ) -> Result<proof::VerkleProof, ()>;
}

// This is the function that commits to the branch nodes and computes the delta optimisation
// XXX: For consistency with the PCS, ensure that this component uses the same SRS as the PCS
// Or we could initialise the PCS with this committer
pub trait Committer {
    // Commit to a lagrange polynomial, evaluations.len() must equal the size of the SRS at the moment
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective;
    // compute value * G for a specific generator in the SRS
    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective;

    fn commit_sparse(&self, val_indices: Vec<(Fr, usize)>) -> EdwardsProjective {
        let mut result = EdwardsProjective::default();

        for (value, lagrange_index) in val_indices {
            result += self.scalar_mul(value, lagrange_index)
        }

        return result;
    }
}
// A Basic Commit struct to be used in tests.
// In production, we will use the Precomputed points
pub struct BasicCommitter;
impl Committer for BasicCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        let mut res = EdwardsProjective::zero();
        for (val, point) in evaluations.iter().zip(SRS.iter()) {
            res += point.mul(val.into_repr())
        }
        res
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        SRS[lagrange_index].mul(value.into_repr())
    }
}

pub(crate) fn group_to_field(point: &EdwardsProjective) -> Fr {
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

use once_cell::sync::Lazy;

// TODO: change this into a constant
pub(crate) fn two_pow_128() -> Fr {
    let mut arr = [0u8; 17];
    arr[0] = 1;
    Fr::from_be_bytes_mod_order(&arr)
}

pub static SRS: Lazy<[EdwardsProjective; 256]> = Lazy::new(|| {
    use ipa_multipoint::multiproof::CRS;
    const SEED: &'static [u8] = b"eth_verkle_oct_2021";
    let crs = CRS::new(256, SEED);
    crs.G.try_into().unwrap()
});

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

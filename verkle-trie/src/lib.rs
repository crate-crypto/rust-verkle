#[deny(unreachable_patterns)]
mod byte_arr;
pub mod database;
pub mod precompute;
pub mod proof;
pub mod to_bytes;
pub mod trie;

use ark_ec::ProjectiveCurve;
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use bandersnatch::EdwardsAffine;
pub use bandersnatch::{EdwardsProjective, Fr};
use ipa_multipoint::multiproof::CRS;
use precompute::PrecomputeLagrange;
use std::convert::TryInto;
pub use trie::Trie;

pub const FLUSH_BATCH: u32 = 20_000;
// This library only works for a width of 256. It can be modified to work for other widths, but this is
// out of scope for this project.
pub const VERKLE_NODE_WIDTH: usize = 256;
// Seed used to compute the 256 pedersen generators
// using try-and-increment
const PEDERSEN_SEED: &'static [u8] = b"eth_verkle_oct_2021";
pub(crate) const TWO_POW_128: Fr = Fr::new(BigInteger256([
    3195623856215021945,
    6342950750355062753,
    18424290587888592554,
    1249884543737537366,
]));
pub type Key = [u8; 32];
pub type Value = [u8; 32];
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
    /// TODO: Find out if this method is ever needed
    fn get(&self, key: &Key) -> Result<Value, ()>;

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

/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}
pub(crate) type TestConfig<Storage> = Config<Storage, TestCommitter>;
pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;

impl<Storage> TestConfig<Storage> {
    pub(crate) fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        Config { db, committer }
    }
}

// A Basic Commit struct to be used in tests.
// In production, we will use the Precomputed points
pub struct TestCommitter;
impl Committer for TestCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        let mut res = EdwardsProjective::zero();
        for (val, point) in evaluations.iter().zip(CRS.G.iter()) {
            res += point.mul(val.into_repr())
        }
        res
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        CRS[lagrange_index].mul(value.into_repr())
    }
}

impl Default for TestCommitter {
    fn default() -> Self {
        TestCommitter
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
pub static CRS: Lazy<CRS> = Lazy::new(|| CRS::new(VERKLE_NODE_WIDTH, PEDERSEN_SEED));

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
#[test]
fn test_two_pow128_constant() {
    let mut arr = [0u8; 17];
    arr[0] = 1;
    let expected = Fr::from_be_bytes_mod_order(&arr);
    assert_eq!(TWO_POW_128, expected)
}

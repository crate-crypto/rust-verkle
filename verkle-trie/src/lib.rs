mod byte_arr;
pub mod database;
pub mod precompute;
#[deny(unreachable_patterns)]
mod proof;
pub mod trie;
pub struct Key([u8; 32]);
pub struct Value([u8; 32]);

pub struct VerklePath;
use ark_serialize::CanonicalSerialize;
use bandersnatch::{EdwardsProjective, Fr};

pub trait TrieTrait {
    /// Inserts multiple values into the trie, recomputes the root
    /// using the pippenger.
    ///
    /// Note: it is not possible to insert a value without recomputing the root
    /// This avoids any complications where one may insert without updating the root, and
    /// then one updates a different key.
    ///
    /// Update assumes that all commitments in the trie are updated

    fn insert(&mut self, kv: impl Iterator<Item = (Key, Value)>) -> Fr;
    /// Inserts a single value and computes it's root using pippenger.

    fn insert_single(&mut self, key: Key, value: Value) -> Fr {
        self.insert(vec![(key, value)].into_iter())
    }
    /// Gets the value at the `Key` if it exists
    /// Returns an error if it does not exist
    // XXX: This should return a reference to &Value, as the data might be large
    fn get(&self, key: &Key) -> Result<Value, std::io::Error>;

    // // updates a key's value and recomputes the delta
    // fn update(&mut self, key : Key, value : Value);

    /// Computes the root of the trie
    // For computing the root, we can make a call to the leaf table.
    // If there is only one or zero leaves, we return the leave value or 0 respectively
    fn compute_root(&mut self) -> Fr;

    /// Creates a verkle path which can be used to create a verkle proof
    fn create_verkle_proof(&mut self, key: &Key) -> Result<VerklePath, std::io::Error>;
}

// This is the function that commits to the branch nodes and computes the delta optimisation
// XXX: For consistency with the PCS, ensure that this component uses the same SRS as the PCS
// Or we could initialise the PCS with this committer
pub trait Committer {
    // Commit to a lagrange polynomial, evaluations.len() must equal the size of the SRS at the moment
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective;
    // compute value * G for a specific generator in the SRS
    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective;
}

pub(crate) fn group_to_field(point: &EdwardsProjective) -> Fr {
    use ark_ff::PrimeField;
    use ark_ff::Zero;
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
    use ark_ff::PrimeField;
    let mut arr = [0u8; 17];
    arr[0] = 1;
    Fr::from_be_bytes_mod_order(&arr)
}

// TODO: This is insecure, it is used to test interopability with the python code
// TODO: change SRS to CRS. There is no structure
pub static SRS: Lazy<[EdwardsProjective; 256]> = Lazy::new(|| {
    let mut points = [EdwardsProjective::default(); 256];
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;
    let gen = EdwardsProjective::prime_subgroup_generator();

    for i in 0..256 {
        points[i] = gen.mul(Fr::from((i + 1) as u64).into_repr());
    }

    points
});
// TODO: This is secure, but we cannot use it yet, since the python code does not
// TODO have this method
// pub static SRS: Lazy<[EdwardsProjective; 256]> = Lazy::new(|| {
//     let mut points = [EdwardsProjective::default(); 256];
//     use ark_std::rand::SeedableRng;
//     use ark_std::UniformRand;
//     use rand_chacha::ChaCha20Rng;

//     let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

//     for i in 0..256 {
//         points[i] = EdwardsProjective::rand(&mut rng);
//     }

//     points
// });

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

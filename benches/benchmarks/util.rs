use ark_bls12_381::Bls12_381;
use sha2::Digest;

use once_cell::sync::Lazy;
use std::convert::TryInto;
use verkle_trie::kzg10::CommitKeyLagrange;
use verkle_trie::{dummy_setup, kzg10::precomp_lagrange::PrecomputeLagrange, HashFunction, Key};
pub const WIDTH_10: usize = 10;

pub static COMMITTED_KEY_1024: Lazy<CommitKeyLagrange<Bls12_381>> =
    Lazy::new(|| dummy_setup(WIDTH_10).0);

pub static PRECOMPUTED_TABLE_1024: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
    PrecomputeLagrange::<Bls12_381>::precompute(&COMMITTED_KEY_1024.lagrange_powers_of_g)
});

pub static KEYS_10K: Lazy<Vec<Key>> = Lazy::new(|| generate_diff_set_of_keys(10_000).collect());
pub static SAME_KEYS_10K: Lazy<Vec<Key>> = Lazy::new(|| generate_set_of_keys(10_000).collect());

pub fn generate_set_of_keys(n: u32) -> impl Iterator<Item = Key> {
    (0u32..n).map(|i| {
        let mut arr = [0u8; 32];
        let i_bytes = i.to_be_bytes();
        arr[0] = i_bytes[0];
        arr[1] = i_bytes[1];
        arr[2] = i_bytes[2];
        arr[3] = i_bytes[3];

        let mut hasher = HashFunction::new();
        hasher.update(&arr[..]);
        hasher.update(b"seed");

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Key::from_arr(res)
    })
}

pub fn generate_diff_set_of_keys(n: u32) -> impl Iterator<Item = Key> {
    (0u32..n).map(|i| {
        let mut hasher = HashFunction::new();
        hasher.update(i.to_be_bytes());

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Key::from_arr(res)
    })
}

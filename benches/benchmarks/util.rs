use ark_bls12_381::Bls12_381;
use sha2::Digest;

use verkle_trie::{dummy_setup, kzg10::precomp_lagrange::PrecomputeLagrange, HashFunction, Key};

use once_cell::sync::Lazy;
pub const WIDTH_10: usize = 10;
pub static PRECOMPUTED_TABLE_1024: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
    let ck = dummy_setup(WIDTH_10).0;
    PrecomputeLagrange::<Bls12_381>::precompute(&ck.lagrange_powers_of_g)
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
        Key::from_arr(arr)
    })
}

pub fn generate_diff_set_of_keys(n: u32) -> impl Iterator<Item = Key> {
    use std::convert::TryInto;
    (0u32..n).map(|i| {
        let mut hasher = HashFunction::new();
        hasher.update(i.to_be_bytes());

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Key::from_arr(res)
    })
}

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

// pub static PRECOMPUTED_TABLE: Lazy<PrecomputeLagrange> =
//    Lazy::new(|| PrecomputeLagrange::precompute(&SRS.map(|point| point.into_affine())));

pub static KEYS_10K: Lazy<Vec<[u8; 32]>> =
    Lazy::new(|| generate_diff_set_of_keys(10_000).collect());
#[allow(dead_code)]
pub static SAME_KEYS_10K: Lazy<Vec<[u8; 32]>> =
    Lazy::new(|| generate_set_of_keys(10_000).collect());

pub fn generate_set_of_keys(n: u32) -> impl Iterator<Item = [u8; 32]> {
    (0u32..n).map(|i| {
        let mut arr = [0u8; 32];
        let i_bytes = i.to_be_bytes();
        arr[0] = i_bytes[0];
        arr[1] = i_bytes[1];
        arr[2] = i_bytes[2];
        arr[3] = i_bytes[3];

        let mut hasher = Sha256::new();
        hasher.update(&arr[..]);
        hasher.update(b"seed");

        let res: [u8; 32] = hasher.finalize().into();
        res
    })
}

pub fn generate_diff_set_of_keys(n: u32) -> impl Iterator<Item = [u8; 32]> {
    (0u32..n).map(|i| {
        let mut hasher = Sha256::new();
        hasher.update(i.to_be_bytes());

        let res: [u8; 32] = hasher.finalize().into();
        res
    })
}

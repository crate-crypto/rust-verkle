use sha2::{Digest, Sha256};

use ark_ec::ProjectiveCurve;
use once_cell::sync::Lazy;
use std::convert::TryInto;
use verkle_db::{BareMetalDiskDb, RocksDb, SledDb};
use verkle_trie::{
    database::{memory_db::MemoryDb, VerkleDb},
    precompute::PrecomputeLagrange,
    trie::Trie,
    SRS,
};

pub static PRECOMPUTED_TABLE: Lazy<PrecomputeLagrange> =
    Lazy::new(|| PrecomputeLagrange::precompute(&SRS.map(|point| point.into_affine())));

pub static KEYS_10K: Lazy<Vec<[u8; 32]>> =
    Lazy::new(|| generate_diff_set_of_keys(10_000).collect());
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

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        res
    })
}

pub fn generate_diff_set_of_keys(n: u32) -> impl Iterator<Item = [u8; 32]> {
    (0u32..n).map(|i| {
        let mut hasher = Sha256::new();
        hasher.update(i.to_be_bytes());

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        res
    })
}

fn main() {
    use tempfile::tempdir;
    let temp_dir = tempdir().unwrap();

    let db = MemoryDb::new();
    let db = VerkleDb::<RocksDb>::from_path(&temp_dir);

    let mut trie = Trie::new(db, &*PRECOMPUTED_TABLE);
    // Initial set of keys
    let keys = generate_set_of_keys(500_000);
    for key in keys {
        trie.insert(key, key);
    }
    trie.flush_database();

    use std::time::Instant;

    let now = Instant::now();
    for key in KEYS_10K.iter() {
        trie.insert(*key, *key);
    }
    println!("insert keys time : {}", now.elapsed().as_millis());
    let now = Instant::now();
    trie.flush_database();
    println!(
        "total flush time (inc write to batch) : {}",
        now.elapsed().as_millis()
    );
}

use ark_bls12_381::Bls12_381;

use sha2::Digest;
use verkle_trie::{
    dummy_setup, kzg10::precomp_lagrange::PrecomputeLagrange, HashFunction, Key, Value,
    VerkleTrait, VerkleTrie,
};

use once_cell::sync::Lazy;
const WIDTH: usize = 10;
static PRECOMPUTED_TABLE_1024: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
    let ck = dummy_setup(WIDTH).0;
    PrecomputeLagrange::<Bls12_381>::precompute(&ck.lagrange_powers_of_g)
});
static KEYS_10K: Lazy<Vec<Key>> = Lazy::new(|| generate_diff_set_of_keys(10_000).collect());

fn generate_set_of_keys(n: u32) -> impl Iterator<Item = Key> {
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

fn generate_diff_set_of_keys(n: u32) -> impl Iterator<Item = Key> {
    use std::convert::TryInto;
    (0u32..n).map(|i| {
        let mut hasher = HashFunction::new();
        hasher.update(i.to_be_bytes());

        let res: [u8; 32] = hasher.finalize().try_into().unwrap();
        Key::from_arr(res)
    })
}

fn main() {
    let mut trie = VerkleTrie::new(WIDTH, &*PRECOMPUTED_TABLE_1024);
    let initial_keys = generate_set_of_keys(1_000_000);
    let keys_values = initial_keys.map(|key| (key, Value::zero()));

    println!("inserting 1M keys");
    let root_mil = trie.insert(keys_values);

    println!(
        "root after inserting 1M keys is {}",
        hex::encode(root_mil.compress())
    );

    println!("inserting 10K keys");
    let keys_values = KEYS_10K.iter().map(|key| (*key, Value::zero()));
    let root = trie.insert(keys_values);

    println!(
        "root after inserting 10K keys is {}",
        hex::encode(root.compress())
    );
}

use rayon::prelude::*;
use sha2::Digest;
use verkle_trie::{dummy_setup, HashFunction, Key, Value, VerkleTrait, VerkleTrie};
// fn main() {
//     println!("creating trusted setup");
//     let (commit_key, opening_key) = dummy_setup(10);

//     let mut trie = VerkleTrie::new(10, &commit_key);

//     println!("creating inserting values");
//     trie.insert_single(Key::one(), Value::one());
//     trie.insert_single(Key::from_arr([1; 32]), Value::one());

//     println!("creating verkle path");
//     let verkle_path = trie.create_verkle_path(&Key::one()).unwrap();

//     println!("creating verkle proof");
//     let verkle_proof = verkle_path.create_proof(&commit_key);

//     println!("verifying");
//     let ok = verkle_proof.verify(
//         &opening_key,
//         &verkle_path.commitments,
//         &verkle_path.omega_path_indices,
//         &verkle_path.node_roots,
//     );

//     println!("proof validity: {}", ok);
// }

fn main() {
    let (commit_key, _) = dummy_setup(10);

    let mut trie = VerkleTrie::new(10, &commit_key);

    const INITIAL_KEYS: u32 = 1_000_000_000; // 1B
    const TO_INSERT: u32 = 10_000; // 10K

    let keys = generate_set_of_keys(INITIAL_KEYS);
    println!("generated set of keys");
    let key_vals = keys
        .enumerate()
        .inspect(|(i, _)| {
            if i > &10_000 {
                if i % 100_000 == 0 {
                    println!("{}", i)
                }
            }
        })
        .map(|(_, key)| (key, Value::zero()));
    trie.insert(key_vals);

    println!("finished initial insertion of 1B Keys");

    use std::time::Instant;

    let keys = generate_diff_set_of_keys(TO_INSERT);
    let key_vals = keys.map(|key| (key, Value::zero()));

    let now = Instant::now();

    let root = trie.insert(key_vals);

    let elapsed = now.elapsed().as_nanos();

    println!("time :{}", elapsed);
    println!("root :{:?}", root.compress());
}

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

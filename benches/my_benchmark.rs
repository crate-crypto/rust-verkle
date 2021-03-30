use ark_bls12_381::Bls12_381;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use verkle_trie::{dummy_setup, kzg10::CommitKey, Key, Value, VerkleTrie};

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn insert_to_trie(trie: &mut VerkleTrie, to_insert: &[Key], ck: &CommitKey<Bls12_381>) {
    for key in to_insert {
        trie.insert(*key, Value::zero())
    }
    let _thing = black_box(trie.compute_root_commitment(&ck));
}

fn criterion_benchmark(c: &mut Criterion) {
    let (commit_key, _) = dummy_setup(1023);

    // setup a trie with 1 million leaves
    let mut trie = setup_trie(1_000_000, &commit_key);

    let to_insert = generate_set_of_keys(10_000);

    c.bench_function("insert trie", |b| {
        b.iter(|| insert_to_trie(&mut trie, &to_insert, &commit_key))
    });
}

// setups a trie by inserting `n` random keys into the trie
// and computing it's commitment
fn setup_trie(n: usize, ck: &CommitKey<Bls12_381>) -> VerkleTrie {
    let mut trie = VerkleTrie::new();
    let keys = generate_set_of_keys(n);

    for key in keys {
        trie.insert(key, Value::zero());
    }
    trie.compute_root_commitment(ck);

    trie
}

fn generate_set_of_keys(n: usize) -> Vec<Key> {
    (0..n).map(|_| rand_key()).collect()
}

fn rand_key() -> Key {
    let mut array = [0_u8; 32];
    use rand_core::RngCore;
    let rng = &mut rand_core::OsRng;
    rng.fill_bytes(&mut array);
    Key::from_arr(array)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// fn main() {
//     let mut trie = VerkleTrie::new();

//     println!("creating trusted setup");
//     let (commit_key, opening_key) = dummy_setup(1023);

//     println!("creating inserting values");
//     trie.insert(Key::one(), Value::one());
//     trie.insert(
//         Key::from_arr([
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//             0, 0, 1,
//         ]),
//         Value::one(),
//     );
// }

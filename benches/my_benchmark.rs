use ark_bls12_381::Bls12_381;
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::prelude::*;
use sha2::Digest;
use verkle_trie::HashFunction;
use verkle_trie::{
    dummy_setup, kzg10::CommitKey, kzg10::OpeningKey, Key, Value, VerkleTrait, VerkleTrie,
};

use once_cell::sync::Lazy;

static SRS: Lazy<(CommitKey<Bls12_381>, OpeningKey<Bls12_381>)> = Lazy::new(|| dummy_setup(10));
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

fn bench_create_proof_10K_keys_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("initial keys");

    for initial_keys in (0..=500_000_000).step_by(100_000) {
        let mut trie = VerkleTrie::new(10, &SRS.0);

        // Initial set of keys
        let keys = generate_set_of_keys(initial_keys);
        let kvs = keys.map(|key| (key, Value::zero()));
        trie.insert(kvs);

        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, &initial_keys| {
                b.iter_batched(
                    || trie.clone(),
                    |mut trie| {
                        let keys_values = KEYS_10K.iter().map(|key| (*key, Value::zero()));
                        black_box(trie.insert(keys_values))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches; 
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = bench_create_proof_10K_keys_group);
criterion_main!(benches);

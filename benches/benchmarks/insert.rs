use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K, PRECOMPUTED_TABLE_1024, WIDTH_10};
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_trie::{Value, VerkleTrait, VerkleTrie};

fn insert_10k_from_1mil(c: &mut Criterion) {
    let mut trie = VerkleTrie::new(WIDTH_10, &*PRECOMPUTED_TABLE_1024);
    let initial_keys = generate_set_of_keys(1_000_000);
    let keys_values = initial_keys.map(|key| (key, Value::zero()));
    trie.insert(keys_values);

    c.bench_function("insert trie", |b| {
        b.iter_batched(
            || trie.clone(),
            |mut trie| {
                let keys_values = KEYS_10K.iter().map(|key| (*key, Value::zero()));
                black_box(trie.insert(keys_values))
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = insert_10k_from_1mil
);

use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K, PRECOMPUTED_TABLE_1024, WIDTH_10};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_trie::{Value, VerkleTrait, VerkleTrie};

fn insert_10k_from_10mil_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert 10k");

    for initial_keys in (0..=10_000_000).step_by(100_000) {
        let mut trie = VerkleTrie::new(WIDTH_10, &*PRECOMPUTED_TABLE_1024);

        // Initial set of keys
        let keys = generate_set_of_keys(initial_keys);
        let kvs = keys.map(|key| (key, Value::zero()));
        trie.insert(kvs);

        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, _| {
                b.iter_batched(
                    || trie.clone(),
                    |mut trie| {
                        // Insert different keys
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
    targets = insert_10k_from_10mil_step);

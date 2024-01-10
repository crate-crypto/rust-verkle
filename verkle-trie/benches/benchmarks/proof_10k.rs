use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::trie::Trie;
use verkle_trie::DefaultConfig;
use verkle_trie::TrieTrait;

fn proof_10k_from_10mil_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof 10k");

    let db = MemoryDb::new();
    let config = DefaultConfig::new(db);
    let mut trie = Trie::new(config);
    // Initial set of keys
    let _keys = generate_set_of_keys(1_000_000);

    let key_vals = KEYS_10K.iter().map(|key_bytes| (*key_bytes, *key_bytes));
    trie.insert(key_vals);

    for initial_keys in (0..=100_000).step_by(100_000) {
        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, _| {
                b.iter_batched(
                    || trie.clone(),
                    |trie| {
                        // Insert different keys
                        let key_vals = KEYS_10K.iter().copied();
                        black_box(trie.create_verkle_proof(key_vals))
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
    targets = proof_10k_from_10mil_step
);

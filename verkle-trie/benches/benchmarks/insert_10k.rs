use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::trie::Trie;
use verkle_trie::DefaultConfig;
use verkle_trie::TrieTrait;

fn insert_10k_from_10mil_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert 10k");

    for initial_keys in (0..=100_000).step_by(100_000) {
        // let db = verkle_db::DefaultSledDb::from_path(&temp_dir);
        let db = MemoryDb::new();
        let config = DefaultConfig::new(db);
        let mut trie = Trie::new(config);
        // Initial set of keys
        let keys = generate_set_of_keys(initial_keys);
        let key_vals = keys.into_iter().map(|key_bytes| (key_bytes, key_bytes));
        trie.insert(key_vals);

        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, _| {
                b.iter_batched(
                    || trie.clone(),
                    |mut trie| {
                        // Insert different keys
                        let key_vals = KEYS_10K.iter().map(|key_bytes| (*key_bytes, *key_bytes));
                        #[allow(clippy::unit_arg)]
                        black_box(trie.insert(key_vals))
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

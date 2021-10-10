use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K, PRECOMPUTED_TABLE};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_db::BareMetalDiskDb;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::trie::Trie;
fn insert_10k_from_10mil_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert 10k");

    for initial_keys in (0..=10_000_000).step_by(100_000) {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();

        // let db = verkle_db::DefaultSledDb::from_path(&temp_dir);
        let db = MemoryDb::from_path(&temp_dir);
        let mut trie = Trie::new(db, &*PRECOMPUTED_TABLE);
        // Initial set of keys
        let keys = generate_set_of_keys(initial_keys);
        for key in keys {
            trie.insert(key, key);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, _| {
                b.iter_batched(
                    || trie.clone(),
                    |mut trie| {
                        // Insert different keys
                        for key in KEYS_10K.iter() {
                            black_box(trie.insert(*key, *key))
                        }
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

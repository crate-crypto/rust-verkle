use crate::benchmarks::util::{
    generate_set_of_keys, COMMITTED_KEY_1024, PRECOMPUTED_TABLE_1024, SAME_KEYS_10K, WIDTH_10,
};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_trie::{Value, VerkleTrait, VerkleTrie};

fn proof_10k_from_10mil_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof 10k");

    for initial_keys in (100_000..=10_000_000).step_by(100_000) {
        let mut trie = VerkleTrie::new(WIDTH_10, &*PRECOMPUTED_TABLE_1024);

        // Initial set of keys
        let keys = generate_set_of_keys(initial_keys);
        let kvs = keys.map(|key| (key, Value::zero()));
        trie.insert(kvs);

        let mut verkle_paths = Vec::with_capacity(10_000);

        for key in SAME_KEYS_10K.iter() {
            let verkle_path = trie.create_verkle_path(key).unwrap();
            verkle_paths.push(verkle_path);
        }

        let mut merged_path = verkle_paths.pop().unwrap();
        for path in verkle_paths {
            merged_path = merged_path.merge(path);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(initial_keys),
            &initial_keys,
            |b, _| {
                b.iter_batched(
                    || merged_path.clone(),
                    |merged_path| black_box(merged_path.create_proof(&*COMMITTED_KEY_1024)),
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
    targets = proof_10k_from_10mil_step);

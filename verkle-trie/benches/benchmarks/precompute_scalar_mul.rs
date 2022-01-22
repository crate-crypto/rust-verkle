use crate::benchmarks::util::{generate_set_of_keys, KEYS_10K, PRECOMPUTED_TABLE};
use ark_ff::{Field, PrimeField};
use banderwagon::Fr;
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, BatchSize, Criterion};
use verkle_db::BareMetalDiskDb;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::trie::Trie;
use verkle_trie::Committer;
fn scalar_mul_bench(c: &mut Criterion) {
    use ark_ff::One;
    let minus_one = -Fr::one();

    c.bench_function("precomputed scalar mul", |b| {
        // b.iter(|| black_box((&*PRECOMPUTED_TABLE).scalar_mul(minus_one, 2)))
        b.iter(|| black_box(minus_one.inverse().unwrap()))
    });
}

criterion_group!(benches, scalar_mul_bench);

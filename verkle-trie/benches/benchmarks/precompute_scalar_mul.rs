use ark_ff::Field;
use banderwagon::Fr;
use criterion::{black_box, criterion_group, Criterion};

fn scalar_mul_bench(c: &mut Criterion) {
    use ark_ff::One;
    let minus_one = -Fr::one();

    c.bench_function("precomputed scalar mul", |b| {
        // b.iter(|| black_box((&*PRECOMPUTED_TABLE).scalar_mul(minus_one, 2)))
        b.iter(|| black_box(minus_one.inverse().unwrap()))
    });
}

criterion_group!(benches, scalar_mul_bench);

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let fr_a = rand_fr(10);
    let fr_b = rand_fr(20);
    c.bench_function("fr mul", |b| b.iter(|| black_box(fr_a * fr_b)));
}

fn rand_fr(seed: u64) -> Fr {
    let mut array = [0_u8; 64];
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    let mut rng = StdRng::seed_from_u64(seed);

    rng.fill(&mut array);
    Fr::from_be_bytes_mod_order(&array)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

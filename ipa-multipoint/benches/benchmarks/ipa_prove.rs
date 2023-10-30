use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use banderwagon::Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ipa_multipoint::crs::CRS;
use ipa_multipoint::ipa::create;
use ipa_multipoint::lagrange_basis::LagrangeBasis;
use ipa_multipoint::math_utils::powers_of;
use ipa_multipoint::transcript::Transcript;
use rand_chacha::ChaCha20Rng;

pub fn criterion_benchmark(c: &mut Criterion) {
    let n = 256;
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let input_point = Fr::rand(&mut rng);
    let b_vec = powers_of(input_point, n);

    let crs = CRS::new(n, "lol".as_bytes());

    let mut prover_transcript = Transcript::new(b"ip_no_zk");

    let a_lagrange = LagrangeBasis::new(a.clone());
    let a_comm = crs.commit_lagrange_poly(&a_lagrange);

    c.bench_function("ipa - prove (256)", |b| {
        b.iter(|| {
            black_box(create(
                &mut prover_transcript,
                crs.clone(),
                a.clone(),
                a_comm,
                b_vec.clone(),
                input_point,
            ))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

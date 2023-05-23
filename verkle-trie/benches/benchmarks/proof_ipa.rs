use ark_ff::{BigInteger256, UniformRand};
use banderwagon::Fr;
use criterion::{black_box, criterion_group, BenchmarkId, Criterion};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::{MultiPoint, ProverQuery},
    transcript::Transcript,
};
use rand::Rng;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::*;

const VECTOR_WIDTH: usize = 256;

fn multiproof(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiproof");

    let crs = CRS::new(VECTOR_WIDTH, b"bench");
    let precomp = PrecomputedWeights::new(VECTOR_WIDTH);

    let prover_queries = (0..16_000)
        .into_par_iter()
        .map(|_| {
            LagrangeBasis::new(
                (0..VECTOR_WIDTH)
                    .map(|_| Fr::rand(&mut rand::thread_rng()))
                    .collect::<Vec<_>>(),
            )
        })
        .map(|poly| {
            let point = rand::thread_rng().gen_range(0..VECTOR_WIDTH);
            let result = poly.evaluate_in_domain(point);
            ProverQuery {
                commitment: crs.commit_lagrange_poly(&poly),
                poly,
                point,
                result,
            }
        })
        .collect::<Vec<_>>();

    for num_keys in [1, 1_000, 2_000, 4_000, 8_000, 16_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_keys),
            &num_keys,
            |b, num_polys| {
                let prover_queries: Vec<ProverQuery> =
                    prover_queries.iter().take(*num_polys).cloned().collect();
                b.iter(|| {
                    let crs = crs.clone();
                    let mut transcript = Transcript::new(b"bench");
                    let prover_queries = prover_queries.clone();
                    black_box(MultiPoint::open(
                        crs,
                        &precomp,
                        &mut transcript,
                        prover_queries,
                    ));
                });
            },
        );
    }
    group.finish();
}

fn ipa(c: &mut Criterion) {
    let crs = CRS::new(VECTOR_WIDTH, b"bench");
    let precomp = PrecomputedWeights::new(VECTOR_WIDTH);

    let poly = LagrangeBasis::new(
        (0..VECTOR_WIDTH)
            .map(|_| Fr::rand(&mut rand::thread_rng()))
            .collect::<Vec<_>>(),
    );
    let a_comm = crs.commit_lagrange_poly(&poly);

    let a_vec = poly.values().to_vec();
    let z_i = Fr::new(BigInteger256::from(10));
    let b_vec = LagrangeBasis::evaluate_lagrange_coefficients(&precomp, crs.n, z_i);
    c.bench_function("ipa", |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"bench");
            black_box(ipa_multipoint::ipa::create(
                &mut transcript,
                crs.clone(),
                a_vec.clone(),
                a_comm,
                b_vec.clone(),
                z_i,
            ));
        });
    });
}

criterion_group!(benches, multiproof, ipa);

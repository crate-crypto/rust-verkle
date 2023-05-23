use ark_ff::{UniformRand};
use criterion::{Criterion, BenchmarkId, criterion_group};
use ipa_multipoint::{multiproof::{MultiPoint, ProverQuery}, crs::CRS, lagrange_basis::{PrecomputedWeights, LagrangeBasis}, transcript::Transcript};
use banderwagon::Fr;
use rand::Rng;
use rayon::prelude::IntoParallelIterator;
use rayon::prelude::*;


fn multiproof(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiproof");

    let vector_width = 256;
    let crs = CRS::new(vector_width, b"bench");
    let precomp = PrecomputedWeights::new(vector_width);

    let prover_queries = (0..16_000)
        .into_par_iter()
        .map(|_| LagrangeBasis::new((0..vector_width).map(|_| Fr::rand(&mut rand::thread_rng())).collect::<Vec<_>>()))
        .map(|poly| {
                let mut rng = rand::thread_rng();
                let point  =  rng.gen_range(0..vector_width);
                let result = poly.evaluate_in_domain(point);
                ProverQuery {
                    commitment:  crs.commit_lagrange_poly(&poly),
                    poly,
                    point,
                    result,
                }
           }).collect::<Vec<_>>();


    for num_keys in [1, 1_000, 2_000, 4_000, 8_000, 16_000] {
    group.bench_with_input(BenchmarkId::from_parameter(num_keys),&num_keys,
            |b, num_polys| {
                let prover_queries :Vec<ProverQuery> = prover_queries.iter().take(*num_polys).cloned().collect();
                b.iter(|| {
                    let crs = crs.clone();
                    let mut transcript = Transcript::new(b"bench");
                    let prover_queries = prover_queries.clone();
                    MultiPoint::open(crs, &precomp, &mut transcript, prover_queries); 
                });
            });
    }
    group.finish();
}

criterion_group!(benches, multiproof);
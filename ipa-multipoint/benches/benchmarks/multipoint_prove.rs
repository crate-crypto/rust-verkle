use ark_std::UniformRand;
use banderwagon::Fr;
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ipa_multipoint::lagrange_basis::*;
use ipa_multipoint::multiproof::*;
use ipa_multipoint::transcript::Transcript;
use ipa_multipoint::crs::CRS;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiproof - prove (256)");

    use ark_std::test_rng;

    // Setup parameters, n is the degree + 1
    // CRs is the G_Vec, H_Vec, Q group elements
    let n = 256;
    let crs = CRS::new(n, b"random seed");

    let mut rng = test_rng();
    let poly = LagrangeBasis::new((0..n).map(|_| Fr::rand(&mut rng)).collect());
    let poly_comm = crs.commit_lagrange_poly(&poly);

    for num_polynomials in [1, 1_000, 2_000, 4_000, 8_000, 16_000, 128_000] {
        let mut polys: Vec<LagrangeBasis> = Vec::with_capacity(num_polynomials);
        for _ in 0..num_polynomials {
            polys.push(poly.clone())
        }

        let mut prover_queries = Vec::with_capacity(num_polynomials);
        for (i, poly) in polys.into_iter().enumerate() {
            let point = i % n;

            let y_i = poly.evaluate_in_domain(point);

            let prover_query = ProverQuery {
                commitment: poly_comm,
                poly,
                point,
                result: y_i,
            };

            prover_queries.push(prover_query);
        }

        let precomp = PrecomputedWeights::new(n);

        group.bench_with_input(
            BenchmarkId::from_parameter(num_polynomials),
            &num_polynomials,
            |b, _| {
                b.iter_batched(
                    || (Transcript::new(b"foo"), prover_queries.clone()),
                    |(mut transcript, prover_queries)| {
                        black_box(MultiPoint::open(
                            crs.clone(),
                            &precomp,
                            &mut transcript,
                            prover_queries,
                        ))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

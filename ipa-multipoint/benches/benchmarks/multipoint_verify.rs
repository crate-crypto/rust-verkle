use ark_std::UniformRand;
use banderwagon::Fr;
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ipa_multipoint::crs::CRS;
use ipa_multipoint::lagrange_basis::*;
use ipa_multipoint::multiproof::*;
use ipa_multipoint::transcript::Transcript;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("multipoint - verify (256)");

    use ark_std::test_rng;

    // Setup parameters, n is the degree + 1
    // CRs is the G_Vec, H_Vec, Q group elements
    let n = 256;
    let crs = CRS::new(n, b"random seed");

    let mut rng = test_rng();
    let poly = LagrangeBasis::new((0..n).map(|_| Fr::rand(&mut rng)).collect());
    let poly_comm = crs.commit_lagrange_poly(&poly);

    for num_polynomials in [1, 1_000, 2_000, 4_000, 8_000, 16_000, 128_000] {
        // For verification, we simply generate one polynomial and then clone it `num_polynomial`
        // time.  whether it is the same polynomial or different polynomial does not affect verification.
        let mut polys: Vec<LagrangeBasis> = Vec::with_capacity(num_polynomials);
        for _ in 0..num_polynomials {
            polys.push(poly.clone())
        }

        let mut prover_queries = Vec::with_capacity(num_polynomials);
        for poly in polys.into_iter() {
            let point = 1;
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

        let mut transcript = Transcript::new(b"foo");
        let multiproof = MultiPoint::open(
            crs.clone(),
            &precomp,
            &mut transcript,
            prover_queries.clone(),
        );

        let mut verifier_queries: Vec<VerifierQuery> = Vec::with_capacity(num_polynomials);
        for prover_query in prover_queries {
            verifier_queries.push(prover_query.into())
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(num_polynomials),
            &num_polynomials,
            |b, _| {
                b.iter_batched(
                    || Transcript::new(b"foo"),
                    |mut transcript| {
                        black_box(multiproof.check(
                            &crs,
                            &precomp,
                            &verifier_queries,
                            &mut transcript,
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

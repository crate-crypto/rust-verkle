use crate::benchmarks::util::{
    generate_set_of_keys, COMMITTED_KEY_1024, PRECOMPUTED_TABLE_1024, SAME_KEYS_10K, WIDTH_10,
};
use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_bls12_381::G1Affine;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations, GeneralEvaluationDomain};
use criterion::BenchmarkId;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use merlin::Transcript;
use rand_core::OsRng;
use verkle_trie::kzg10::Commitment;
use verkle_trie::kzg10::MultiPointProver;

pub fn criterion_benchmark(c: &mut Criterion) {
    let degree = 1023;
    let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();

    let mut group = c.benchmark_group("kzg prove");
    for num_polys in (10_000..=40_000).step_by(10_000) {
        let mut polys = Vec::with_capacity(num_polys);
        for _ in 0..num_polys {
            let poly_a = Polynomial::rand(degree, &mut rand_core::OsRng);
            let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly_a), domain);
            polys.push(evaluations);
        }

        let mut points = Vec::with_capacity(num_polys);
        for i in 0..num_polys {
            points.push(domain.element(i));
        }

        let mut evaluations = Vec::with_capacity(num_polys);
        for _ in 0..num_polys {
            evaluations.push(Fr::rand(&mut OsRng));
        }

        let mut commitments = Vec::with_capacity(num_polys);
        for _ in 0..num_polys {
            commitments.push(Commitment::<Bls12_381>::mul_generator(Fr::rand(&mut OsRng)));
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(num_polys),
            &num_polys,
            |b, num_polys| {
                b.iter_batched(
                    || {
                        //
                        //
                        //
                        let transcript = Transcript::new(b"foo");
                        (&polys, &points, &evaluations, &commitments, transcript)
                    },
                    |(polys, points, evaluations, commitments, mut transcript)| {
                        black_box(COMMITTED_KEY_1024.open_multipoint_lagrange(
                            polys,
                            Some(commitments),
                            evaluations,
                            points,
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

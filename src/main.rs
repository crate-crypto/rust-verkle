use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use ark_poly::UVPolynomial;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations, GeneralEvaluationDomain};
use ark_std::{end_timer, start_timer};
use rand_core::OsRng;
use verkle_trie::kzg10::Commitment;
use verkle_trie::kzg10::MultiPointProver;
use verkle_trie::transcript::BasicTranscript;
use verkle_trie::{dummy_setup, Key, Value, VerkleTrait, VerkleTrie};
fn main() {
    let (commit_key, _) = dummy_setup(10);

    let num_polys = 20_000;
    let degree = 1023;
    let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(degree).unwrap();

    let mut polys = Vec::with_capacity(num_polys);
    let poly_a = Polynomial::rand(degree, &mut rand_core::OsRng);
    let evaluations = Evaluations::from_vec_and_domain(domain.fft(&poly_a), domain);
    for _ in 0..num_polys {
        polys.push(evaluations.clone());
    }

    let mut points = Vec::with_capacity(num_polys);
    for i in 0..num_polys {
        points.push(domain.element(i));
    }

    let mut evaluations = Vec::with_capacity(num_polys);
    let eval = Fr::rand(&mut OsRng);
    for _ in 0..num_polys {
        evaluations.push(eval.clone());
    }

    let mut commitments = Vec::with_capacity(num_polys);
    let com = Commitment::<Bls12_381>::mul_generator(Fr::rand(&mut OsRng));
    for _ in 0..num_polys {
        commitments.push(com.clone());
    }
    let mut transcript = BasicTranscript::new(b"foo");
    let s = start_timer!(|| "start prove");
    commit_key
        .open_multipoint_lagrange(
            &polys,
            Some(&commitments),
            &evaluations,
            &points,
            &mut transcript,
        )
        .unwrap();
    end_timer!(s)
}

use banderwagon::{
    msm::MSMPrecompWnaf,
    msm_strauss::{MSMPrecomp, MSMPrecomp16Bit},
    Element, Fr,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngCore;

pub fn msm_wnaf(c: &mut Criterion) {
    const NUM_ELEMENTS: usize = 5;

    let bases = random_point(120, NUM_ELEMENTS);
    let scalars = random_scalars(NUM_ELEMENTS, 16);

    let precomp = MSMPrecompWnaf::new(&bases, 12);

    c.bench_function(&format!("msm wnaf: {}", NUM_ELEMENTS), |b| {
        b.iter(|| precomp.mul(&scalars))
    });

    let precomp = MSMPrecomp::new(&bases, 16);
    c.bench_function(&format!("msm strauss: {}", NUM_ELEMENTS), |b| {
        b.iter(|| precomp.mul(&scalars))
    });

    let precomp = MSMPrecomp16Bit::new(&bases, 16);
    c.bench_function(&format!("msm precomp 16: {}", NUM_ELEMENTS), |b| {
        b.iter(|| precomp.mul(&scalars))
    });
}

pub fn keccak_32bytes(c: &mut Criterion) {
    use rand::Rng;
    use sha3::{Digest, Keccak256};

    c.bench_function("keccak 64 bytes", |b| {
        b.iter_with_setup(
            // Setup function: generates new random data for each iteration
            || {
                let keccak = Keccak256::default();
                let mut rand_buffer = [0u8; 64];
                rand::thread_rng().fill(&mut rand_buffer);
                (keccak, rand_buffer)
            },
            |(mut keccak, rand_buffer)| {
                keccak.update(&rand_buffer);
                keccak.finalize()
            },
        )
    });
}

fn random_point(seed: u64, num_points: usize) -> Vec<Element> {
    (0..num_points)
        .map(|i| Element::prime_subgroup_generator() * Fr::from((seed + i as u64 + 1) as u64))
        .collect()
}
fn random_scalars(num_points: usize, num_bytes: usize) -> Vec<Fr> {
    use ark_ff::PrimeField;

    (0..num_points)
        .map(|_| {
            let mut bytes = vec![0u8; num_bytes];
            rand::thread_rng().fill_bytes(&mut bytes[..]);
            Fr::from_le_bytes_mod_order(&bytes)
        })
        .collect()
}

criterion_group!(benches, msm_wnaf, keccak_32bytes);
criterion_main!(benches);

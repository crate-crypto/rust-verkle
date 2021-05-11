use ark_bls12_381::Bls12_381;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use verkle_trie::{
    dummy_setup, kzg10::CommitKey, kzg10::OpeningKey, Key, Value, VerkleTrait, VerkleTrie,
};

use once_cell::sync::Lazy;

static SRS: Lazy<(CommitKey<Bls12_381>, OpeningKey<Bls12_381>)> = Lazy::new(|| dummy_setup(10));
static KEYS_11K: Lazy<Vec<Key>> = Lazy::new(|| generate_set_of_keys(11_000, 200).collect());

fn generate_set_of_keys(n: usize, seed: u64) -> impl Iterator<Item = Key> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(move |i| rand_key(&mut rng))
}

fn rand_key(rng: &mut StdRng) -> Key {
    let mut array = [0_u8; 32];

    rng.fill(&mut array);
    Key::from_arr(array)
}

fn bench_create_proof_10K_keys(c: &mut Criterion) {
    let mut trie = VerkleTrie::new(10, &SRS.0);

    c.bench_function("insert trie", |b| {
        b.iter(|| {
            let keys_values = KEYS_11K.iter().map(|key| (*key, Value::zero()));
            black_box(trie.insert(keys_values))
        })
    });
}

criterion_group!(benches, bench_create_proof_10K_keys);
criterion_main!(benches);

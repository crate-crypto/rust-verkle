use crate::{dummy_setup, kzg10::CommitKey, kzg10::OpeningKey, Key, Value, VerkleTrie};
use ark_bls12_381::Bls12_381;
use rand_core::OsRng;
use std::time::Duration;

fn insert_to_trie(trie: &mut VerkleTrie, to_insert: &[Key], ck: &CommitKey<Bls12_381>) {
    for key in to_insert {
        trie.insert(*key, Value::zero())
    }
    let _comm = trie.compute_root_commitment(&ck);
}

// setups a trie by inserting `n` random keys into the trie
// and computing it's commitment
fn setup_trie(n: usize, ck: &CommitKey<Bls12_381>) -> VerkleTrie {
    let mut trie = VerkleTrie::new(10);
    let keys = generate_set_of_keys(n);
    for key in keys {
        trie.insert(key, Value::zero());
    }
    trie.compute_root_commitment(ck);

    trie
}

fn generate_set_of_keys(n: usize) -> Vec<Key> {
    (0..n).map(|_| rand_key()).collect()
}

fn rand_key() -> Key {
    let mut array = [0_u8; 32];
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    let mut rng = StdRng::seed_from_u64(20);

    rng.fill(&mut array);
    Key::from_arr(array)
}

use once_cell::sync::Lazy;

static SRS: Lazy<(CommitKey<Bls12_381>, OpeningKey<Bls12_381>)> = Lazy::new(|| dummy_setup(1023));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::Bencher;

    #[bench]
    fn bench_insert_10k_from_1_million(b: &mut Bencher) {
        let mut trie = setup_trie(1_000_000, &SRS.0);

        let to_insert = generate_set_of_keys(10_000);

        b.iter(|| insert_to_trie(&mut trie, &to_insert, &SRS.0))
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let mut trie = VerkleTrie::new(10);
        // insert 0 and 1, so that the proof is the longest it can be
        let zero = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let x = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        trie.insert(x, Value::max());
        trie.insert(zero, Value::max());

        let verkle_path = trie.create_path(&x, &SRS.0).unwrap();

        let verkle_proof = verkle_path.create_proof(&SRS.0);

        b.iter(|| {
            let ok = verkle_proof.verify(
                &SRS.1,
                &verkle_path.commitments,
                &verkle_path.omega_path_indices,
                &verkle_path.node_roots,
            );
            assert!(ok);
        })
    }
    #[bench]
    fn bench_create_proof(b: &mut Bencher) {
        let mut trie = VerkleTrie::new(10);
        // insert 0 and 1, so that the proof is the longest it can be
        let zero = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let x = Key::from_arr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        trie.insert(x, Value::max());
        trie.insert(zero, Value::max());

        let verkle_path = trie.create_path(&x, &SRS.0).unwrap();
        dbg!(verkle_path.omega_path_indices.len());
        b.iter(|| verkle_path.create_proof(&SRS.0))
    }
}

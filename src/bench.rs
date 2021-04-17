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
    fn bench_create_proof_224(b: &mut Bencher) {
        // benchmark the time it takes to create a proof where we have inserted 2^24 leaves
        let mut trie = VerkleTrie::new(10);
        let n = 2usize.pow(24);
        let keys = generate_set_of_keys(n);
        for key in keys.iter() {
            trie.insert(key.clone(), Value::zero());
        }
        trie.compute_root_commitment(&SRS.0);

        // Create the verkle paths
        let mut verkle_paths = Vec::new();
        for key in keys.into_iter().take(1000) {
            let verkle_path = trie.create_path(&key, &SRS.0).unwrap();
            verkle_paths.push(verkle_path);
        }

        let mut merged_path = verkle_paths.pop().unwrap();
        for path in verkle_paths {
            merged_path = merged_path.merge(path);
        }

        // benchmark creation of 1K verkle proofs
        b.iter(|| {
            merged_path.create_proof(&SRS.0);
        })
    }
}

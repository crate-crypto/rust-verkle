use std::sync::Mutex;

use ipa_multipoint::committer::Committer;
use once_cell::sync::Lazy;
use verkle_trie::{database::memory_db::MemoryDb, Trie, TrieTrait, VerkleConfig};

pub static CONFIG: Lazy<Mutex<VerkleConfig<MemoryDb>>> =
    Lazy::new(|| Mutex::new(VerkleConfig::new(MemoryDb::new())));

#[test]
fn test_vector_insert_100_step() {
    let mut prng = BasicPRNG::default();
    let mut trie = Trie::new(CONFIG.lock().unwrap().clone());
    let batch_size = 100;
    // N = 100
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "afb01df826bd42ddea9001551980f7cfa74f0ca7e0ba36a9079dea4062848600",
    );

    // N = 200
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "4cd6573f3602df0a1438c894e2f0f465e16537c4474e3ab35ee74d5b3afe180f",
    );
    // N = 300
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "1da1675938ba4ad2545fd163dc2053212cd75b54fc44e70f11fd20b05363650b",
    );
    // N = 400
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "bdad99347763dc06765e329da53ae85333a9d89fa9e06ef3fccf30c8c89cb804",
    );
    // N = 500
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "cf0b7ea967a755f6c09762aa4a650899bb79d21ef56f1fe6672621149e639905",
    );
}

#[test]
fn test_vector_insert_1000_step() {
    let mut prng = BasicPRNG::default();
    let mut trie = Trie::new(CONFIG.lock().unwrap().clone());
    let batch_size = 1_000;

    // N = 1_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "c94ef4103861b4788602e503f70ad1f47779d6b8b367532d7b4748c401f7391c",
    );

    // N = 2_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "4284fb75185662925ae4b45143184147db4fd297db1912a6ca17ee3040d21104",
    );
    // N = 3_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "447fa30818141f6034b99a2ece305de601e4af3b635ad216e2a0248a7039240c",
    );
    // N = 4_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "9647ad8f43a64a08fd1d56af5765d9d9e265eb9be703eeb80c2117242c358305",
    );
    // N = 5_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "26ed4b641a6a974f09b1b012784580d96cfbbd99f0eed9db541a89f9f2883201",
    );
}

fn step_test_helper<C: Committer>(
    trie: &mut Trie<MemoryDb, C>,
    prng: &mut BasicPRNG,
    num_keys: usize,
    expected: &str,
) {
    let keys = prng.rand_vec_bytes(num_keys);
    let key_vals = keys.into_iter().map(|key_bytes| (key_bytes, key_bytes));

    trie.insert(key_vals);

    let root = trie.root_hash();

    use banderwagon::trait_defs::*;
    let mut root_bytes = [0u8; 32];
    root.serialize_compressed(&mut root_bytes[..]).unwrap();
    assert_eq!(hex::encode(root_bytes), expected);
}

// A test structure that allows us to have a seedable prng
// that is easy to implement in both python, go and Rust
// This is only used for tests
struct BasicPRNG {
    seed: [u8; 32],
    counter: u64,
}

impl Default for BasicPRNG {
    fn default() -> Self {
        BasicPRNG::new([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
    }
}

impl BasicPRNG {
    pub fn new(seed: [u8; 32]) -> BasicPRNG {
        let counter = 0u64;
        BasicPRNG { counter, seed }
    }

    pub fn rand_bytes(&mut self) -> [u8; 32] {
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.counter.to_le_bytes()[..]);
        hasher.update(&self.seed[..]);
        let res: [u8; 32] = hasher.finalize().into();

        self.counter += 1;

        res
    }

    pub fn rand_vec_bytes(&mut self, num_keys: usize) -> Vec<[u8; 32]> {
        (0..num_keys).map(|_| self.rand_bytes()).collect()
    }
}

#[test]
fn prng_consistent() {
    let mut prng = BasicPRNG::default();

    let expected = [
        "2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb",
        "b68f593141969cfeddf2011667ccdca92d2d22b414194bdf4ccbaa2833c85be2",
        "74d8b89f49a16dd0a338f1dc90fe470f3137d7df12cf0b76c82b0b5f2fa9028b",
    ];
    for expected_output in expected {
        assert_eq!(hex::encode(prng.rand_bytes()), expected_output)
    }
}

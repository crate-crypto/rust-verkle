use crate::{
    committer::precompute::PrecomputeLagrange, constants::CRS, database::memory_db::MemoryDb, Trie,
    TrieTrait, VerkleConfig,
};
use once_cell::sync::Lazy;
pub static CONFIG: Lazy<VerkleConfig<MemoryDb>> = Lazy::new(|| VerkleConfig::new(MemoryDb::new()));

#[test]
fn test_vector_insert_100_step() {
    let mut prng = BasicPRNG::default();
    let mut trie = Trie::new(CONFIG.clone());
    let batch_size = 100;
    // N = 100
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "5fa5fe5785649312156be73aff1dabc8b93b715a761d9d789f429df375db1d19",
    );

    // N = 200
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "5eebe397c95f264a559a5b87a14da941541cc429d2c2db1413d37f5f1f82a615",
    );
    // N = 300
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "6ccf7881aa5d1a58157a933bd069856823df8240dca6e8a2ff7068252e62ca19",
    );
    // N = 400
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "88f3e42093394fdb8e624822990232efd6693172f83de8a25adbff18754d3410",
    );
    // N = 500
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "ec2c3cb0e7ed20b016d179480521f574e659f8e31b44f573f6a8505032536903",
    );
}

#[test]
fn test_vector_insert_1000_step() {
    let mut prng = BasicPRNG::default();
    let mut trie = Trie::new(CONFIG.clone());
    let batch_size = 1_000;

    // N = 1_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "5f33e7659c1a3fad443052c2ebda4b4c0760821d61d400cbdcfaee892cd95f0b",
    );

    // N = 2_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "85697f7ccf45f0356761d9f9f97a875363d764c8c0060427c619aa4fe23b800f",
    );
    // N = 3_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "7fd3c1fe659f2e2b55416d14b1cf9c2667d8c014f09c2bcd04e9234f31231f0b",
    );
    // N = 4_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "da76cb6a533f50e75fd7854e2b686a2ccd20b0a7f80456d5145208be6710b912",
    );
    // N = 5_000
    step_test_helper(
        &mut trie,
        &mut prng,
        batch_size,
        "fb6c34c1a0add04a54dba8eaf810df29dffe466d0d67a832707e7fa2dbf15417",
    );
}

fn step_test_helper(
    trie: &mut Trie<MemoryDb, PrecomputeLagrange>,
    prng: &mut BasicPRNG,
    num_keys: usize,
    expected: &str,
) {
    let keys = prng.rand_vec_bytes(num_keys);
    let key_vals = keys.into_iter().map(|key_bytes| (key_bytes, key_bytes));

    trie.insert(key_vals);

    let root = trie.root_hash();

    use ark_serialize::CanonicalSerialize;
    let mut root_bytes = [0u8; 32];
    root.serialize(&mut root_bytes[..]).unwrap();
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
        let res: [u8; 32] = hasher.finalize().try_into().unwrap();

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

#[cfg(test)]
mod test {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Zero;
    use once_cell::sync::Lazy;

    use crate::{
        dummy_setup,
        kzg10::{precomp_lagrange::PrecomputeLagrange, CommitKeyLagrange, LagrangeCommitter},
        Key, Value, VerkleTrait, VerkleTrie,
    };

    const WIDTH_BITS: usize = 8;
    // Setup secret scalar is 8927347823478352432985

    static COMMITTED_KEY_256: Lazy<CommitKeyLagrange<Bls12_381>> =
        Lazy::new(|| dummy_setup(WIDTH_BITS).0);

    static PRECOMPUTED_TABLE_256: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
        PrecomputeLagrange::<Bls12_381>::precompute(&COMMITTED_KEY_256.lagrange_powers_of_g)
    });

    fn hex_fr(fr: &Fr) -> String {
        hex::encode(ark_ff::to_bytes!(fr).unwrap())
    }

    // Compute root for empty trie
    #[test]
    fn test_vector_0() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_256);

        let root = trie.compute_root();
        let got = hex_fr(&root);

        let expected = hex_fr(&Fr::zero());
        assert_eq!(got, expected)
    }
    // Tests insert:
    // Key=0, value = 0
    // Both in little endian format
    // The endian does not matter in this case, since the key and value is zero
    // If this passes and other tests fail, there is most likely an endian mismatch
    #[test]
    fn test_vector_1() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_256);

        let root = trie.insert_single(Key::zero(), Value::zero());
        let got = hex_fr(&root);

        let expected = "c754161429960718cd6eca5ac4bf74af76b5435e838b928d90632f52be470034";
        assert_eq!(got, expected)
    }
    // Tests insert:
    // [
    //(Key  =  0000000000000000000000000000000000000000000000000000000000000001
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //]
    #[test]
    fn test_vector_2() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_256);

        let root = trie.insert_single(Key::one(), Value::zero());
        let got = hex_fr(&root);

        let expected = "31fc83f98ee6032fb08633785d47985a7fd0a45e2cb1039f906e29a90890f006";
        assert_eq!(got, expected)
    }
    // Tests insert:
    // [
    // (Key  =  0100000000000000000000000000000000000000000000000000000000000000
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //]
    #[test]
    fn test_vector_3() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_256);
        let root = trie.insert_single(
            Key::from_arr([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            Value::zero(),
        );
        assert_eq!(
            "daddd7c85f1917a7b8480dc7ab11a07bf31bb3bd1bc3562f273cac2b008a7502",
            hex_fr(&root)
        )
    }

    // Tests insert:
    // [
    // (Key  =  0000000000000000000000000000000000000000000000000000000000000001
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //
    // (Key  =  0100000000000000000000000000000000000000000000000000000000000000
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //]
    #[test]
    fn test_vector_4() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_256);

        trie.insert_single(Key::one(), Value::zero());

        let root = trie.insert_single(
            Key::from_arr([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            Value::zero(),
        );

        assert_eq!(
            "2c6e2daa3a5f30dce5f81c66913afa42dcfaa26f1508d10be78722e7d3ee0230",
            hex_fr(&root)
        )
    }

    #[test]
    fn test_vector_insert_100_step() {
        // N = 100
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            100,
            "4db90ee0ac51895cff2b8bdc057e17432b1cc08008a7adc4a3cec472a9213a3e",
        );
        // N = 200
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            200,
            "2a9c42a5b37d8ec22776d735de103cb8b8d8f6043caadba82524bfaac1b8602b",
        );
        // N = 300
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            300,
            "4726d89e444226036b95885cfe98b4be8e1ffb387465b6950c95204298e67527",
        );
        // N = 400
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            400,
            "f47a45d6e7cc28885e92dfd090f1353594b5b22690e5f4b7a5285aa4898b5720",
        );
        // N = 500
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            500,
            "ad14157990211d9130384ec00ed39d487266c2cd9694be3216dcf9a6b0350b35",
        );
    }

    #[test]
    fn test_vector_step_1k() {
        // N = 1_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            1_000,
            "dfd7869995c23e4b50831508cdb1ea7a34de1601b16adf0e47440522915ca539",
        );
        // N = 2_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            2_000,
            "13cd84340546e89170f67dabf5e036de57bd0475c3be9f0d17d8570214b8c430",
        );
        // N = 3_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            3_000,
            "c596f8d02859fdd94d6c14d37424c4f0b3cc93887482d90ab1daec82fb78b805",
        );
        // N = 4_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            4_000,
            "b50445cbbf1171e0e6fcf7ffb622fde28cfb8b22f117d7fcd7a3984224db2a39",
        );
        // N = 5_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            5_000,
            "62014822508bfa1897fd775881ed7fa974c0b48ad4bf36b30497222b59bbcc26",
        );
    }

    #[test]
    fn test_vector_step_10k() {
        // N = 10_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            10_000,
            "6f5cfd2ebc2c917634900bb19a909dcb36529c2c3ea5f7ff6de7936c53202133",
        );
        // N = 20_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            20_000,
            "8456d4442cb9a47f245ef2f527798d0152752cfa1f9e56a51fa0ca391b4b1111",
        );
        // N = 30_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            30_000,
            "a4ed172ca05e404f885c3898e6ad30aa787027c239ca6c92c3f56a420d27082d",
        );
        // N = 40_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            40_000,
            "bef8320df8afedbe624d74d0c9a48f1d8ba06ab09df7e22e4e4def93bd4a241e",
        );
        // N = 50_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            50_000,
            "faae2eb7c089eb872a17a69fb2f2be68d1dadb6a9d35ade32ab0a4c3eb7b0616",
        );
    }

    #[test]
    #[ignore] // it is expensive
    fn test_vector_step_100k() {
        // N = 100_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            100_000,
            "99867f780c6da684b21e5fd0823375b51d57722d5979189c2662c6992adba804",
        );
        // N = 200_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            200_000,
            "e2f617c8abab9c705a0268052cf43309596e8128d58cf1ed83348cd6facd7215",
        );
        // N = 300_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            300_000,
            "9f22ebbb36bdeea231e46d095527618bfeb6cdfd210c24aa6138e3c603ae6925",
        );
        // N = 400_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            400_000,
            "47e6ab9af1f972c243eec4552f360ca810408b51c13ec99533c72355ee51f13b",
        );
        // N = 500_000
        step_test_helper(
            &*PRECOMPUTED_TABLE_256,
            WIDTH_BITS,
            500_000,
            "f0afc929351c93a05b3deed74e1914eacda984999d2ce5d13379af5f0ee73a36",
        );
    }

    fn step_test_helper(
        ck: &dyn LagrangeCommitter<Bls12_381>,
        width: usize,
        num_keys: usize,
        expected: &str,
    ) {
        let mut rng = BasicPRNG::default();
        let keys = rng.rand_vec_bytes(num_keys);
        let key_vals = keys
            .into_iter()
            .map(|key_bytes| (Key::from_arr(key_bytes), Value::zero()));

        let mut trie = VerkleTrie::new(width, ck);
        let root = trie.insert(key_vals);

        assert_eq!(hex_fr(&root), expected);
    }

    // A test structure that allows us to have a seedable prng
    // that is easy to implement in both python, go and Rust
    // This is only used for tests
    struct BasicPRNG {
        state: [u8; 64],
        counter: u128,
    }

    impl Default for BasicPRNG {
        fn default() -> Self {
            BasicPRNG::new([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
        }
    }

    impl BasicPRNG {
        pub fn new(seed: [u8; 32]) -> BasicPRNG {
            let mut state = [0u8; 64];

            let counter = 0u128;
            let counter_arr32 = BasicPRNG::arr32(counter);
            state[..32].clone_from_slice(&counter_arr32);
            state[32..].clone_from_slice(&seed);

            BasicPRNG { state, counter }
        }

        pub fn rand_bytes(&mut self) -> [u8; 32] {
            use crate::HashFunction;
            use sha2::Digest;
            use std::convert::TryInto;

            let mut hasher = HashFunction::new();
            hasher.update(self.state);

            let res: [u8; 32] = hasher.finalize().try_into().unwrap();

            self.update_state();

            res
        }

        pub fn rand_vec_bytes(&mut self, num_keys: usize) -> Vec<[u8; 32]> {
            (0..num_keys).map(|_| self.rand_bytes()).collect()
        }

        fn update_state(&mut self) {
            // update counter and replace the first 16 bytes with the
            // new counter value. The seed does not change.
            self.counter += 1;
            let counter_arr32 = BasicPRNG::arr32(self.counter);
            self.state[..32].clone_from_slice(&counter_arr32);
        }

        fn arr32(num: u128) -> [u8; 32] {
            let mut result = [0u8; 32];
            result[..16].clone_from_slice(&num.to_le_bytes()[..]);
            result
        }
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381;
    use once_cell::sync::Lazy;

    use crate::{
        dummy_setup,
        kzg10::{precomp_lagrange::PrecomputeLagrange, CommitKeyLagrange, LagrangeCommitter},
        Key, Value, VerkleTrait, VerkleTrie,
    };

    const WIDTH_BITS: usize = 10;
    // Setup secret scalar is 8927347823478352432985

    static COMMITTED_KEY_1024: Lazy<CommitKeyLagrange<Bls12_381>> = Lazy::new(|| dummy_setup(10).0);

    static PRECOMPUTED_TABLE_1024: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
        PrecomputeLagrange::<Bls12_381>::precompute(&COMMITTED_KEY_1024.lagrange_powers_of_g)
    });
    // Compute root for empty trie
    #[test]
    fn test_vector_0() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);

        let root = trie.compute_root();
        let got = hex::encode(root.compress());

        let expected = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(got, expected)
    }
    // Tests insert:
    // Key=0, value = 0
    // Both in little endian format
    // The endian does not matter in this case, since the key and value is zero
    // If this passes and other tests fail, there is most likely an endian mismatch
    #[test]
    fn test_vector_1() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);

        let root = trie.insert_single(Key::zero(), Value::zero());
        let got = hex::encode(root.compress());

        let expected = "a8211de8d5ba22f6dd6b199b0df87bdb7de85e3056042ae316efc5453b0b49e6964e247942d66375c4f1230033a462aa";
        assert_eq!(got, expected)
    }
    // Tests insert:
    // [
    //(Key  =  0000000000000000000000000000000000000000000000000000000000000001
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //]
    #[test]
    fn test_vector_2() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);

        let root = trie.insert_single(Key::one(), Value::zero());
        let got = hex::encode(root.compress());

        let expected = "aa025aaa8dcf44407f27949d15a6c6dbfd6fa74307ba97aa7e9e74fbe520509fa0f9155fa314bbaba8384fd71e638033";
        assert_eq!(got, expected)
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
    fn test_vector_3() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);

        trie.insert_single(Key::one(), Value::zero());

        let root = trie.insert_single(
            Key::from_arr([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            Value::zero(),
        );

        assert_eq!("934659bc76722aa157e2adf5f5ce9f5aa7a9fcf3b4675651acd9382c8dfeaa19bdc852addea16eee84c38eb10ec07af2", hex::encode(root.compress()))
    }
    // Tests insert:
    // [
    // (Key  =  0100000000000000000000000000000000000000000000000000000000000000
    // Value = 0000000000000000000000000000000000000000000000000000000000000000)
    //]
    #[test]
    fn test_vector_4() {
        let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);
        let root = trie.insert_single(
            Key::from_arr([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            Value::zero(),
        );
        assert_eq!("adb36cefe99f0931b017eaffbf3fc58e785bd92181fba6d15b015f203c0cf73a8b5a14baf68d4ecd0151012bec70367c",hex::encode(root.compress()))
    }

    #[test]
    fn test_vector_insert_100_step() {
        // N = 100
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 100, "8d8fe2e7769b498ec9bfda5da692901315db60e973ff40f75069a18b8508fa56b263b365b48980b2f874706ed2f34c73");
        // N = 200
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 200, "b018e472c8a12aec18d5d5d820225340229ebcbae6d70b22be636cb84e8a9bc1769fc6e790ad00fe76e8cb96bb56b34a");
        // N = 300
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 300, "94f5f41a1c9c82fcd1602913dfb8fd8f70c688cf77de389e4a9d94842cd1c67f3a972720245b1277ef5ee601ada90f8d");
        // N = 400
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 400, "89565323cffcfaf4e3d841301e39a556dacabe74499337dd463011b220f470c2a69a8b73a69cb48af9402d3ca10b2b8e");
        // N = 500
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 500, "95341e9c6a0467dca0967e7d4d5edc7594ff4b5bfa320d13cdcf38b48916668dbb71ecc9a5165f5d47241613dfbdda33");
    }

    #[test]
    fn test_vector_step_1k() {
        // N = 1_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 1_000, "b5c18f72b43e6cb078f9dcee5d81f2d2cb99fc1af36bbe22b9860fb18b66f95419ae240736d3aaa4cecdaa412d360b58");
        // N = 2_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 2_000, "94a027952de98f3741ce485e6fed34942a7ac37997e3bb56c4ca743c53ad2efbd7e0fb6dbab97a24cfa38fd272036fae");
        // N = 3_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 3_000, "8d2d9fd6952eb4e60af58b0e06ec4669309f3a4b78a011ad8318425c6edca3f81e34228666ca57d76af8744f27c2fdc7");
        // N = 4_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 4_000, "a32ca8e260da356e9240dc419ea0a514163e0f6114e021d919dfe7c36f62ecd984b3dcb2de757527aaf9bca45eaac541");
        // N = 5_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 5_000, "801d45490730c801e4a5d0b5b301126967b2811cf293de7ac79eeb39d0671af7a4df72a87c6202cfa0f0888521719e9c");
    }

    #[test]
    fn test_vector_step_10k() {
        // N = 10_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 10_000, "b9aac5cf1fade329028d40aca951a0e2b614ad3193c41058451ddfcd57d1cc8438b3796dd62bf7478af2e5adc1a70fe4");
        // N = 20_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 20_000, "b95db153f389b05f9c939273ba004b13fd32816d0f81255261e1ace6ba0b31b04a597cbc4be175616bf194dcd4a05860");
        // N = 30_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 30_000, "b025a4efdf79e87990165ac0006b2f5b2965e7262d197ab5d4cf6a8d67647926368e836b28dae637be507c931b1ac681");
        // N = 40_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 40_000, "8378e5a7a7592be9b7bf009dec095314a9d01343087c3109bdb20a4b838812a1ab47bdbc4b8d6043aa1ef09e4e686465");
        // N = 50_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 50_000, "abfabaa890dd3a85e793d8c018525abbdab1e25c84ade3c9934708a7a290fddc2c715e87a9ce0d190571fcfeda4bff72");
    }

    #[test]
    fn test_vector_step_100k() {
        // N = 100_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 100_000, "8602e138ef96fa3bfc559e6333dc7737e9f0a10ddc760a92397d5d002570ccd4636fd484f91bf63ce253de5f1eabdd62");
        // N = 200_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 200_000, "abd86ec6e91cb5a0b1085a093b574239f96540b7c9f0ad5a9c7922c808656dc67d09d208e2eaac3579d31b3ac25f2e98");
        // N = 300_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 300_000, "877a2ccce7adafea43c30c4382c5cca2e50e4ac6ff24ede9a928082ed5278b612e61c93172f1bcb6ebb6addec52c0f03");
        // N = 400_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 400_000, "b129344704fa3b529a0324c128ce3cd9e34bf984bdf9f3389158acff8b8e28ec538190a12ae8763cede58ae05aaf0cf0");
        // N = 500_000
        step_test_helper(&*PRECOMPUTED_TABLE_1024, WIDTH_BITS, 500_000, "ab1d17b8eb8edd8dd90c415c55b4c7232fdae2b960e01aa886695b47c40ac767061cbdd3c12c72f27d73c4c6c0f1dc80");
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

        let root_bytes = root.compress();
        assert_eq!(hex::encode(root_bytes), expected);
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

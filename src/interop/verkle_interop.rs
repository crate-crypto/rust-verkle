#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381;
    use once_cell::sync::Lazy;

    use crate::{
        dummy_setup,
        kzg10::{
            commit_key_coeff::CommitKey, precomp_lagrange::PrecomputeLagrange, CommitKeyLagrange,
            LagrangeCommitter,
        },
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

    // The following step test cases were generated from the following python code:
    //
    // root = {"node_type": "inner", "commitment": blst.G1().mult(0)}
    // add_node_hash(root)
    //    state = int(0).to_bytes(32, "little")
    //     for i in range(N):
    //         new_state = hash(state)
    //         state = new_state
    //         key = state
    //         value = int(0).to_bytes(32, "big")
    //         insert_verkle_node(root, key, value)
    //     add_node_hash(root)
    //     print(bytes(root["commitment"].compress()).hex())
    //
    // Insert N keys from a prng, then compute the root.
    // start at N and we increment by N

    fn test_vector_insert_100_step(ck: &dyn LagrangeCommitter<Bls12_381>) {
        // N = 100
        step_test_helper(ck, WIDTH_BITS, 100, "b7bbeaa9457095d69ac9bb669bc63175784dcac6dc775f92d45e2180eddcb682baae640fa92a8e96c8aa1e2707908ff1");
        // N = 200
        step_test_helper(ck, WIDTH_BITS, 200, "a91f655e75b85f2d60eaede73068af1061d32997c0651748d162a3a08ff6f6cdef9b0c6d8c843c50404e38c97351d7d3");
        // N = 300
        step_test_helper(ck, WIDTH_BITS, 300, "b4b8b2b8e811f72e8b2a3522729356e2e7fa68decf1f75de4bbae19272be9f1b15d85cff1510a1f4a4c202f80aab8c73");
        // N = 400
        step_test_helper(ck, WIDTH_BITS, 400, "b7801d52d642af27fb019547ea629fae0b87230e12067d2e13004a2d8c8205eea6a99345e2037ed960747fbaab596cf5");
        // N = 500
        step_test_helper(ck, WIDTH_BITS, 500, "929cc832762aca99520552d170b6c5a0c2532778a1347d37d2c82ee0fe3e26f7503cad3f041667feb0128129d190000c");
    }
    #[test]
    fn insert_100_step() {
        test_vector_insert_100_step(&*COMMITTED_KEY_1024);
        test_vector_insert_100_step(&*PRECOMPUTED_TABLE_1024);
    }

    fn test_vector_step_1k(ck: &dyn LagrangeCommitter<Bls12_381>) {
        // N = 1_000
        step_test_helper(ck, WIDTH_BITS, 1_000, "809743aa087f81c8ec5c9c59640c9104c6399f48470da9438ae2707f9b9adf243b1be5c09ad98fbfb1683535ff02c1dd");
        // N = 2_000
        step_test_helper(ck, WIDTH_BITS, 2_000, "abfbd9adfda7ee6a160cb9a1b1ab4066c0a6babad9589c2bc6c29c8e04e1abfb8505611686a1ea49f1ea89674a83d3d2");
        // N = 3_000
        step_test_helper(ck, WIDTH_BITS, 3_000, "83d37aeb005a799f7a11794ed2416e371bc7bd538d98c7ed4913ef4d40c38c8f77d111442ede5a7a776639043aad64f8");
        // N = 4_000
        step_test_helper(ck, WIDTH_BITS, 4_000, "b798afc162c04f0265af03fdec632a50a44c59a3209898cd5fdf63c1d1151e507a2c567aee9f402af2afb0d7a4d5871e");
        // N = 5_000
        step_test_helper(ck, WIDTH_BITS, 5_000, "82cfe5eadbe2eee91abca654a35f8cbdb9cee97904cc063a8af28fe3a6de4bbbbeb9b759881633f9d0c03e21e81769dd");
    }
    #[test]
    fn insert_1k_step() {
        test_vector_step_1k(&*COMMITTED_KEY_1024);
        test_vector_step_1k(&*PRECOMPUTED_TABLE_1024);
    }

    fn test_vector_step_10k(ck: &dyn LagrangeCommitter<Bls12_381>) {
        // N = 10_000
        step_test_helper(ck, WIDTH_BITS, 10_000, "ac6f80ecf262097837348a4170c4a6600d855ba02663859aceb1d3753f1228eef73d0a68be7df8b73d0509230c254c5c");
        // N = 20_000
        step_test_helper(ck, WIDTH_BITS, 20_000, "8c218ca0347c459db9f66b3b795c52b94e0f93adb96e8f6e8e9201b07f870377d4c1286ac38f4cbc610f696cdb3cab05");
        // N = 30_000
        step_test_helper(ck, WIDTH_BITS, 30_000, "92761241a3c6d1093a007c250ced3d57e5332be5d77b9060b8c68be70612677e8e43f21528a68730697e7d70ae3a5c01");
        // N = 40_000
        step_test_helper(ck, WIDTH_BITS, 40_000, "a56b3c6a6c4f038e06f978fc2d5e278fba982a73cec0ee44b3210b11134a77f1ecf0fdf0625d1989b0d72ba78eb41148");
        // N = 50_000
        step_test_helper(ck, WIDTH_BITS, 50_000, "a3518f182895d97a51ddaea8351e1f11a33439ff3bebeeb24241d1a8acc91030264c960d49232f40e031c8b5671c286e");
    }
    #[test]
    fn insert_10k_step() {
        test_vector_step_10k(&*COMMITTED_KEY_1024);
        test_vector_step_10k(&*PRECOMPUTED_TABLE_1024);
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
        state: [u8; 32],
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
            BasicPRNG { state: seed }
        }

        pub fn rand_bytes(&mut self) -> [u8; 32] {
            use crate::HashFunction;
            use sha2::Digest;
            use std::convert::TryInto;

            let mut hasher = HashFunction::new();
            hasher.update(self.state);

            let res: [u8; 32] = hasher.finalize().try_into().unwrap();

            self.state = res;

            res
        }

        pub fn rand_vec_bytes(&mut self, num_keys: usize) -> Vec<[u8; 32]> {
            (0..num_keys).map(|_| self.rand_bytes()).collect()
        }
    }
}

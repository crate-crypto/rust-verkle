use ark_bls12_381::Bls12_381;

use crate::{dummy_setup, kzg10::CommitKey, Key, Value, VerkleTrait, VerkleTrie};

// Setup secret scalar is 8927347823478352432985

// Compute root for empty trie
#[test]
fn test_vector_0() {
    let width = 10;
    let (ck, _) = dummy_setup(width);
    let mut trie = VerkleTrie::new(width, &ck);

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
    let width = 10;
    let (ck, _) = dummy_setup(width);
    let mut trie = VerkleTrie::new(width, &ck);

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
    let width = 10;
    let (ck, _) = dummy_setup(width);
    let mut trie = VerkleTrie::new(width, &ck);

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
    let width = 10;
    let (ck, _) = dummy_setup(width);
    let mut combined_trie = VerkleTrie::new(width, &ck);

    combined_trie.insert_single(Key::one(), Value::zero());

    let root = combined_trie.insert_single(
        Key::from_arr([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
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
    let width = 10;
    let (ck, _) = dummy_setup(width);

    let mut trie = VerkleTrie::new(width, &ck);
    let root = trie.insert_single(
        Key::from_arr([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]),
        Value::zero(),
    );
    assert_eq!("adb36cefe99f0931b017eaffbf3fc58e785bd92181fba6d15b015f203c0cf73a8b5a14baf68d4ecd0151012bec70367c",hex::encode(root.compress()))
}

// root2 = {"node_type": "inner", "commitment": blst.G1().mult(0)}
// add_node_hash(root2)
//    state = int(0).to_bytes(32, "little")
//     for i in range(100):
//         new_state = hash(state)
//         state = new_state
//         key = state
//         value = int(0).to_bytes(32, "big")
//         insert_verkle_node(root2, key, value)
//     # average_depth = get_average_depth(root)
//     add_node_hash(root2)
//     print("start", bytes(root2["commitment"].compress()).hex(), "end")
// Insert N keys from a prng, then compute the root.
// N starts at 100 and we increment it by 100 each time
#[test]
fn test_vector_insert_100_step() {
    let width = 10;
    let (ck, _) = dummy_setup(width);

    // N = 100
    step_test_helper(&ck, width, 100, "b7bbeaa9457095d69ac9bb669bc63175784dcac6dc775f92d45e2180eddcb682baae640fa92a8e96c8aa1e2707908ff1");
    // N = 200
    step_test_helper(&ck, width, 200, "a91f655e75b85f2d60eaede73068af1061d32997c0651748d162a3a08ff6f6cdef9b0c6d8c843c50404e38c97351d7d3");
    // N = 300
    step_test_helper(&ck, width, 300, "b4b8b2b8e811f72e8b2a3522729356e2e7fa68decf1f75de4bbae19272be9f1b15d85cff1510a1f4a4c202f80aab8c73");
}

fn step_test_helper(ck: &CommitKey<Bls12_381>, width: usize, num_keys: usize, expected: &str) {
    let mut rng = BasicPRNG::default();
    let keys = rng.rand_vec_bytes(num_keys);
    let key_vals = keys
        .into_iter()
        .map(|key_bytes| (Key::from_arr(key_bytes), Value::zero()));

    let mut trie = VerkleTrie::new(width, &ck);
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
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

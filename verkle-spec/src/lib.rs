pub mod code;
pub mod header;
pub mod storage;

pub(crate) mod parameters;
mod util;

// TODO: specify the parts in the code where we assume VERKLE_WIDTH = 256;
// TODO: expose type markers in verkle-trie, so we can ensure that none of them overlap
// TODO: with the type markers in this crate. In particular, this crate uses 2, while verkle-trie uses 1 and 0

pub use ethereum_types::{H160, H256, U256};

pub use code::Code;
pub use header::Header;
use ipa_multipoint::committer::{Committer, DefaultCommitter};
pub use storage::Storage;
use verkle_trie::constants::new_crs;

// Used to hash the input in get_tree_key
pub trait Hasher {
    fn hash64(bytes64: [u8; 64]) -> H256 {
        // TODO: We should make this a part of the Hasher signature instead of
        // TODO being inefficient here
        let committer = DefaultCommitter::new(&new_crs().G);
        hash64(&committer, bytes64)
    }

    fn chunk64(bytes64: [u8; 64]) -> [u128; 5] {
        crate::util::chunk64(bytes64)
    }
    fn chunk_bytes(bytes: &[u8]) -> Vec<u128> {
        crate::util::chunk_bytes(bytes)
    }
}

// This is the default implementation for `pedersen_hash`
// in the EIP. Since the EIP hashes 64 bytes (address32 + tree_index),
// we just special case the method here to hash 64 bytes.
pub fn hash64(committer: &DefaultCommitter, bytes64: [u8; 64]) -> H256 {
    let inputs = crate::util::chunk64(bytes64).map(verkle_trie::Fr::from);
    let result = committer.commit_lagrange(&inputs);

    let hashed_point = result.map_to_scalar_field();
    use banderwagon::trait_defs::*;

    let mut output = [0u8; 32];
    hashed_point
        .serialize_compressed(&mut output[..])
        .expect("Failed to serialize scalar to bytes");

    H256::from(output)
}

// Old address styles
pub type Address20 = H160;
// New address styles
pub type Address32 = H256;

pub fn addr20_to_addr32(addr20: Address20) -> Address32 {
    let bytes20: [u8; 20] = addr20.to_fixed_bytes();

    let mut bytes32: [u8; 32] = [0u8; 32];
    bytes32[12..].copy_from_slice(&bytes20);

    Address32::from(bytes32)
}

#[test]
fn smoke_test_hash64() {
    let committer = DefaultCommitter::new(&new_crs().G);

    // Hash of all zeroes
    let all_zeroes = [0u8; 64];
    let hash = hash64(&committer, all_zeroes);
    let expected =
        hex::decode("1a100684fd68185060405f3f160e4bb6e034194336b547bdae323f888d533207").unwrap();
    assert_eq!(hash, H256::from_slice(&expected));

    // Hash of all ones
    let all_ones = [1u8; 64];
    let hash = hash64(&committer, all_ones);
    let expected =
        hex::decode("3afb8486ed3053ac55f62864da803c074844509d253260d870337c20fd73eb11").unwrap();
    assert_eq!(hash, H256::from_slice(&expected));
}

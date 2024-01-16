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
pub use storage::Storage;
use verkle_trie::constants::new_crs;

// Used to hash the input in get_tree_key
pub trait Hasher {
    fn hash64(bytes64: [u8; 64]) -> H256 {
        hash64(bytes64)
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
pub fn hash64(bytes64: [u8; 64]) -> H256 {
    use ipa_multipoint::committer::{Committer, DefaultCommitter};
    use verkle_trie::Element;

    // TODO: We should either make this a global or have it be passed in
    // TODO: so that we don't create a new crs each time
    let committer = DefaultCommitter::new(new_crs());
    let mut result = Element::zero();

    let inputs = crate::util::chunk64(bytes64);

    for (index, input) in inputs.into_iter().enumerate() {
        result += committer.scalar_mul(input.into(), index);
    }

    // Reverse the endian of the byte array
    let mut output = result.to_bytes();
    output.reverse();

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
    // Hash of all zeroes
    let all_zeroes = [0u8; 64];
    let hash = hash64(all_zeroes);
    let expected =
        hex::decode("bf101a6e1c8e83c11bd203a582c7981b91097ec55cbd344ce09005c1f26d1922").unwrap();
    assert_eq!(hash, H256::from_slice(&expected));

    // Hash of all ones
    let all_ones = [1u8; 64];
    let hash = hash64(all_ones);
    let expected =
        hex::decode("54427497ffbee0d2511e14ddaf3497e9b5e8438ff17974d06918e0e8ebe8b61a").unwrap();
    assert_eq!(hash, H256::from_slice(&expected));
}

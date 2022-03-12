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

// Used to hash the input in get_tree_key
pub trait Hasher {
    fn hash64(bytes64: [u8; 64]) -> H256;

    fn chunk64(bytes64: [u8; 64]) -> [u128; 5] {
        crate::util::chunk64(bytes64)
    }
    fn chunk_bytes(bytes: &[u8]) -> Vec<u128> {
        crate::util::chunk_bytes(bytes)
    }
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
